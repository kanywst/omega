// aws_pca.go implements Authority for AWS Private CA (ACM PCA). Like
// the Vault PKI and step-ca backends it is a hybrid: X.509-SVID
// signing is delegated to the private CA (the CA key stays in AWS's
// HSMs and never sits on omega's disk), JWT-SVID signing stays local.
// ADR 0005 documents why JWT signing is not delegated.
//
// AWS Private CA issues asynchronously: IssueCertificate returns a
// certificate ARN, and GetCertificate answers RequestInProgressException
// until the certificate is ready. IssueSVID polls GetCertificate with a
// short backoff inside one deadline.
//
// The SPIFFE ID is passed to AWS through the ApiPassthrough structure
// of an *_APIPassthrough template rather than relying on the CSR: the
// CSRs omega's agents send carry no SANs, and an API-supplied SAN
// takes precedence over anything a CSR carries, so the issued leaf
// holds exactly the URI SAN omega asked for.

package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	defaultAWSPCABundleTTL = 5 * time.Minute
	defaultAWSPCATimeout   = 30 * time.Second
	// awsPCATemplate is the template the backend uses unless the
	// operator overrides it. It fixes CA:FALSE, digital signature +
	// key encipherment, and server + client auth EKUs, and lets the
	// API supply the SAN and subject.
	awsPCATemplate = "template/EndEntityCertificate_APIPassthrough/V1"
	// awsPCAMaxCommonName is AWS Private CA's limit on the subject
	// CommonName; longer SPIFFE IDs are issued with no subject, which
	// X.509-SVIDs allow (the URI SAN carries the identity).
	awsPCAMaxCommonName = 64
	awsPCAPollMin       = 100 * time.Millisecond
	awsPCAPollMax       = 2 * time.Second
	// awsPCAValiditySlack absorbs clock skew between omega and AWS
	// when checking that a leaf does not outlive the requested TTL.
	awsPCAValiditySlack = 5 * time.Minute
)

// awsPCAAuthority signs X.509-SVIDs with an AWS Private CA. The
// embedded *localAuthority handles the JWT-SVID side, trust domain
// accessor, and OIDC issuer URL.
type awsPCAAuthority struct {
	*localAuthority

	caARN       string
	templateARN string
	signingAlg  acmpcatypes.SigningAlgorithm
	client      *acmpca.Client
	timeout     time.Duration

	bundleMu  sync.RWMutex
	bundle    []byte
	issuingCA *x509.Certificate // the CA's own certificate, used to check issued leaves
	bundleExp time.Time
	bundleTTL time.Duration
	overlap   *caOverlap
	// refreshMu serialises concurrent refreshBundle callers so a TTL
	// expiry under load triggers one round-trip to AWS, not N.
	refreshMu sync.Mutex
}

func newAWSPCAAuthority(local *localAuthority, cfg Config) (*awsPCAAuthority, error) {
	caARN := strings.TrimSpace(cfg.AWSPCACAARN)
	parsed, err := arn.Parse(caARN)
	if err != nil {
		return nil, fmt.Errorf("identity: aws-pca: AWSPCACAARN: %w", err)
	}
	if parsed.Service != "acm-pca" || !strings.HasPrefix(parsed.Resource, "certificate-authority/") {
		return nil, fmt.Errorf("identity: aws-pca: AWSPCACAARN %q is not an acm-pca certificate-authority ARN", caARN)
	}
	region := strings.TrimSpace(cfg.AWSPCARegion)
	if region == "" {
		region = parsed.Region
	}
	if region == "" {
		return nil, errors.New("identity: aws-pca: region is empty in the CA ARN and AWSPCARegion is unset")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.AWSPCAEndpoint), "/")
	if endpoint != "" {
		if err := checkAWSPCAEndpoint(endpoint); err != nil {
			return nil, fmt.Errorf("identity: aws-pca: AWSPCAEndpoint: %w", err)
		}
	}
	templateARN := strings.TrimSpace(cfg.AWSPCATemplateARN)
	if templateARN == "" {
		templateARN = fmt.Sprintf("arn:%s:acm-pca:::%s", parsed.Partition, awsPCATemplate)
	}
	bundleTTL := cfg.AWSPCABundleTTL
	if bundleTTL <= 0 {
		bundleTTL = defaultAWSPCABundleTTL
	}
	timeout := cfg.AWSPCATimeout
	if timeout <= 0 {
		timeout = defaultAWSPCATimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Credentials come from the standard AWS chain (env, shared
	// config, web identity / IRSA, ECS, IMDS). Nothing here reads or
	// logs the secret material itself.
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("identity: aws-pca: load aws config: %w", err)
	}
	client := acmpca.NewFromConfig(awsCfg, func(o *acmpca.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	// The SDK also takes an endpoint from AWS_ENDPOINT_URL,
	// AWS_ENDPOINT_URL_ACM_PCA or endpoint_url in the shared config;
	// hold whichever one won to the same https rule as the flag.
	if resolved := aws.ToString(client.Options().BaseEndpoint); resolved != "" {
		if err := checkAWSPCAEndpoint(resolved); err != nil {
			return nil, fmt.Errorf("identity: aws-pca: resolved endpoint: %w", err)
		}
	}

	a := &awsPCAAuthority{
		localAuthority: local,
		caARN:          caARN,
		templateARN:    templateARN,
		signingAlg:     acmpcatypes.SigningAlgorithm(strings.TrimSpace(cfg.AWSPCASigningAlgorithm)),
		client:         client,
		timeout:        timeout,
		bundleTTL:      bundleTTL,
		overlap:        newCAOverlap(upstreamGrace(cfg.UpstreamCAGrace)),
	}
	// Boot-time probe so a wrong ARN, region, endpoint or missing IAM
	// permission fails at startup instead of at the first IssueSVID.
	if _, err := a.refreshBundle(ctx); err != nil {
		return nil, fmt.Errorf("identity: aws-pca: initial CA certificate probe: %w", err)
	}
	if a.signingAlg == "" {
		a.bundleMu.RLock()
		alg, err := awsPCASigningAlgorithmFor(a.issuingCA)
		a.bundleMu.RUnlock()
		if err != nil {
			return nil, fmt.Errorf("identity: aws-pca: %w", err)
		}
		a.signingAlg = alg
	}
	return a, nil
}

// checkAWSPCAEndpoint requires https, except for a loopback host. Over
// plain http a network attacker could replace both the CA certificate
// and the issued leaf, so the leaf checks would prove nothing; loopback
// http is kept for local fakes and test servers.
func checkAWSPCAEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", endpoint)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("%q uses http to a non-loopback host; use https", endpoint)
	default:
		return fmt.Errorf("%q must be an https URL", endpoint)
	}
}

// awsPCASigningAlgorithmFor picks the IssueCertificate SigningAlgorithm
// that matches the CA's key, so operators only set it explicitly for
// unusual choices (RSA-PSS, SHA-512 on a P-256 key).
func awsPCASigningAlgorithmFor(ca *x509.Certificate) (acmpcatypes.SigningAlgorithm, error) {
	switch pub := ca.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return acmpcatypes.SigningAlgorithmSha256withecdsa, nil
		case elliptic.P384():
			return acmpcatypes.SigningAlgorithmSha384withecdsa, nil
		case elliptic.P521():
			return acmpcatypes.SigningAlgorithmSha512withecdsa, nil
		}
	case *rsa.PublicKey:
		return acmpcatypes.SigningAlgorithmSha256withrsa, nil
	}
	return "", fmt.Errorf("cannot infer a signing algorithm from the CA key (%T); set AWSPCASigningAlgorithm", ca.PublicKey)
}

// BundlePEM returns the CA certificate and its chain, cached for
// bundleTTL. On a failed refresh the stale bundle is served: it is
// still the trust anchor consumers were chaining to, and returning nil
// would break every workload's mTLS handshake on an AWS API blip.
func (a *awsPCAAuthority) BundlePEM() []byte {
	a.bundleMu.RLock()
	if len(a.bundle) > 0 && time.Now().Before(a.bundleExp) {
		out := append([]byte(nil), a.bundle...)
		a.bundleMu.RUnlock()
		return out
	}
	stale := append([]byte(nil), a.bundle...)
	a.bundleMu.RUnlock()

	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.bundleMu.RLock()
	if len(a.bundle) > 0 && time.Now().Before(a.bundleExp) {
		out := append([]byte(nil), a.bundle...)
		a.bundleMu.RUnlock()
		return out
	}
	a.bundleMu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	if _, err := a.refreshBundle(ctx); err != nil {
		// Re-serve from the last fetch rather than the cached bytes, so
		// a rotated-out CA whose grace has ended is dropped even while
		// AWS cannot be reached.
		served := a.overlap.serve(time.Now())
		if served == nil {
			served = stale
		}
		// Push the next attempt out so a sustained outage costs one
		// AWS call (and one log line) per retry interval, not one per
		// BundlePEM caller.
		a.bundleMu.Lock()
		if len(served) > 0 {
			a.bundle = served
		}
		a.bundleExp = time.Now().Add(min(a.bundleTTL, upstreamRefreshBackoff))
		a.bundleMu.Unlock()
		slog.Warn("aws-pca: CA bundle refresh failed, serving the cached bundle", "ca", a.caARN, "err", err)
		return served
	}
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return append([]byte(nil), a.bundle...)
}

// refreshBundle calls GetCertificateAuthorityCertificate and replaces
// the cached bundle with the CA certificate followed by its chain (the
// chain is empty for a root CA). The call is made outside bundleMu so
// cache hits are not blocked by a slow AWS endpoint.
func (a *awsPCAAuthority) refreshBundle(ctx context.Context) ([]byte, error) {
	out, err := a.client.GetCertificateAuthorityCertificate(ctx, &acmpca.GetCertificateAuthorityCertificateInput{
		CertificateAuthorityArn: aws.String(a.caARN),
	})
	if err != nil {
		return nil, fmt.Errorf("aws-pca: GetCertificateAuthorityCertificate: %w", err)
	}
	cas, err := parseAWSPCACerts(aws.ToString(out.Certificate))
	if err != nil {
		return nil, fmt.Errorf("aws-pca: CA certificate: %w", err)
	}
	if len(cas) != 1 {
		return nil, fmt.Errorf("aws-pca: CA certificate field holds %d certificates, want 1", len(cas))
	}
	chain, err := parseAWSPCACerts(aws.ToString(out.CertificateChain))
	if err != nil {
		return nil, fmt.Errorf("aws-pca: CA certificate chain: %w", err)
	}
	// The bundle is the trust anchor set served to workloads and
	// federation peers, so every certificate in it must be a CA and
	// the chain must link from the issuing CA up to its root.
	certs := append(cas, chain...)
	for _, c := range certs {
		if !c.IsCA {
			return nil, fmt.Errorf("aws-pca: bundle certificate %q is not marked CA:TRUE", c.Subject)
		}
	}
	// Re-encode rather than echo AWS's strings, so nothing but the
	// parsed certificates reaches the bundle.
	var buf bytes.Buffer
	for i, c := range certs {
		if i+1 < len(certs) {
			if err := c.CheckSignatureFrom(certs[i+1]); err != nil {
				return nil, fmt.Errorf("aws-pca: chain does not link %q to %q: %w", c.Subject, certs[i+1].Subject, err)
			}
		}
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	caCert := cas[0]
	served, err := a.overlap.update(buf.Bytes(), time.Now())
	if err != nil {
		return nil, fmt.Errorf("aws-pca: %w", err)
	}

	a.bundleMu.Lock()
	a.bundle = served
	a.issuingCA = caCert
	a.bundleExp = time.Now().Add(a.bundleTTL)
	a.bundleMu.Unlock()
	return served, nil
}

// BundleSequence advances when the CA's bundle from AWS or the local JWT
// signing CAs change.
func (a *awsPCAAuthority) BundleSequence() int64 {
	// Refresh first, so the sequence a caller reads matches the bundle
	// it reads next (the SPIFFE bundle endpoint reads the sequence first).
	_ = a.BundlePEM()
	return a.overlap.sequence() + a.localAuthority.BundleSequence() - 1
}

// SetKeptCAHook implements UpstreamCAKeeper.
func (a *awsPCAAuthority) SetKeptCAHook(h func(KeptCAEvent)) { a.overlap.setHook(h) }

// DistrustCAs implements UpstreamCAKeeper. The cached bundle is replaced
// at once, under refreshMu so a refresh in flight cannot cache the
// bundle from before the drop after it.
func (a *awsPCAAuthority) DistrustCAs(fps [][32]byte) int {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	n := a.overlap.distrust(fps, time.Now())
	if n > 0 {
		if served := a.overlap.serve(time.Now()); served != nil {
			a.bundleMu.Lock()
			a.bundle = served
			a.bundleMu.Unlock()
		}
	}
	return n
}

// parseAWSPCACerts parses a concatenation of PEM CERTIFICATE blocks,
// rejecting anything else (stray text, other block types, bad DER).
func parseAWSPCACerts(s string) ([]*x509.Certificate, error) {
	rest := []byte(strings.TrimSpace(s))
	var out []*x509.Certificate
	for len(rest) > 0 {
		block, r := pem.Decode(rest)
		if block == nil {
			return nil, errors.New("not PEM")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		rest = bytes.TrimSpace(r)
	}
	return out, nil
}

// IssueSVID submits the CSR to IssueCertificate, polls GetCertificate
// until the leaf is ready, checks that the leaf carries the requested
// SPIFFE ID and the CSR's key and was signed by the configured CA, and
// returns the assembled SVID.
func (a *awsPCAAuthority) IssueSVID(id spiffeid.ID, csr *x509.CertificateRequest) (*SVID, error) {
	if id.IsZero() {
		return nil, errors.New("spiffe id is empty")
	}
	if !id.MemberOf(a.trustDomain) {
		return nil, fmt.Errorf("spiffe id %q is not in trust domain %q", id, a.trustDomain)
	}
	if csr == nil {
		return nil, errors.New("csr is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	// An idempotency token makes the SDK's own retries of
	// IssueCertificate return the same certificate instead of
	// minting a second one.
	token, err := awsPCAIdempotencyToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(svidValidity)
	passthrough := &acmpcatypes.ApiPassthrough{
		Extensions: &acmpcatypes.Extensions{
			SubjectAlternativeNames: []acmpcatypes.GeneralName{
				{UniformResourceIdentifier: aws.String(id.String())},
			},
		},
	}
	if len(id.String()) <= awsPCAMaxCommonName {
		passthrough.Subject = &acmpcatypes.ASN1Subject{CommonName: aws.String(id.String())}
	}
	issued, err := a.client.IssueCertificate(ctx, &acmpca.IssueCertificateInput{
		CertificateAuthorityArn: aws.String(a.caARN),
		Csr:                     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw}),
		SigningAlgorithm:        a.signingAlg,
		TemplateArn:             aws.String(a.templateARN),
		ApiPassthrough:          passthrough,
		Validity: &acmpcatypes.Validity{
			Type:  acmpcatypes.ValidityPeriodTypeAbsolute,
			Value: aws.Int64(notAfter.Unix()),
		},
		ValidityNotBefore: &acmpcatypes.Validity{
			Type:  acmpcatypes.ValidityPeriodTypeAbsolute,
			Value: aws.Int64(now.Add(-1 * time.Minute).Unix()),
		},
		IdempotencyToken: aws.String(token),
	})
	if err != nil {
		return nil, fmt.Errorf("aws-pca: IssueCertificate: %w", err)
	}
	certARN := aws.ToString(issued.CertificateArn)
	if certARN == "" {
		return nil, errors.New("aws-pca: IssueCertificate returned no certificate ARN")
	}
	leafPEM, err := a.waitForCertificate(ctx, certARN)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(leafPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("aws-pca: issued certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("aws-pca: parse certificate: %w", err)
	}
	if err := a.checkIssued(ctx, cert, id, csr, notAfter); err != nil {
		return nil, err
	}
	return &SVID{
		SPIFFEID:  id,
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		BundlePEM: a.BundlePEM(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

// waitForCertificate polls GetCertificate until AWS stops answering
// RequestInProgressException or ctx expires.
func (a *awsPCAAuthority) waitForCertificate(ctx context.Context, certARN string) (string, error) {
	delay := awsPCAPollMin
	for {
		out, err := a.client.GetCertificate(ctx, &acmpca.GetCertificateInput{
			CertificateAuthorityArn: aws.String(a.caARN),
			CertificateArn:          aws.String(certARN),
		})
		if err == nil {
			leaf := aws.ToString(out.Certificate)
			if leaf == "" {
				return "", errors.New("aws-pca: GetCertificate returned no certificate")
			}
			return leaf, nil
		}
		var inProgress *acmpcatypes.RequestInProgressException
		if !errors.As(err, &inProgress) {
			return "", fmt.Errorf("aws-pca: GetCertificate: %w", err)
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return "", fmt.Errorf("aws-pca: certificate %s not ready before deadline: %w", certARN, ctx.Err())
		case <-t.C:
		}
		delay = min(delay*2, awsPCAPollMax)
	}
}

// checkIssued is defence in depth against a misconfigured template or
// CA: the leaf must be an end-entity certificate for exactly the
// requested SPIFFE ID, carry the CSR's key, be usable for mTLS in both
// directions, be valid now and not outlive the requested notAfter, and
// be signed by the CA the bundle publishes.
func (a *awsPCAAuthority) checkIssued(ctx context.Context, cert *x509.Certificate, id spiffeid.ID, csr *x509.CertificateRequest, notAfter time.Time) error {
	if cert.IsCA {
		return errors.New("aws-pca: issued certificate is a CA certificate; check the template ARN")
	}
	// X.509-SVID: a leaf must assert digitalSignature and must not
	// assert keyCertSign or cRLSign.
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return fmt.Errorf("aws-pca: issued certificate key usage %#x is not an X.509-SVID leaf's; check the template ARN", cert.KeyUsage)
	}
	// No EKU at all leaves the key unrestricted, which X.509-SVID
	// allows; an EKU list that names only one direction does not.
	if len(cert.ExtKeyUsage) > 0 && (!slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)) {
		return errors.New("aws-pca: issued certificate lacks the serverAuth or clientAuth extended key usage; check the template ARN")
	}
	now := time.Now()
	if now.Before(cert.NotBefore.Add(-awsPCAValiditySlack)) || !now.Before(cert.NotAfter) {
		return fmt.Errorf("aws-pca: issued certificate is not valid now (%s to %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	if cert.NotAfter.After(notAfter.Add(awsPCAValiditySlack)) {
		return fmt.Errorf("aws-pca: issued certificate expires at %s, after the requested %s", cert.NotAfter.Format(time.RFC3339), notAfter.Format(time.RFC3339))
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return errors.New("aws-pca: issued certificate public key does not match CSR")
	}
	wantURI := id.URL().String()
	if len(cert.URIs) != 1 || cert.URIs[0].String() != wantURI {
		return fmt.Errorf("aws-pca: issued certificate URI SANs %v are not exactly the requested SPIFFE ID %q", cert.URIs, wantURI)
	}
	// Any other name would be one omega never authorized; a template
	// that copies SANs from the CSR could otherwise let a workload add
	// DNS names a hostname-matching verifier would accept.
	if len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses) > 0 {
		return errors.New("aws-pca: issued certificate carries DNS, email or IP SANs besides the SPIFFE ID; check the template ARN")
	}
	err := cert.CheckSignatureFrom(a.currentIssuingCA())
	if err != nil {
		// The CA certificate may have changed in AWS since the bundle
		// was cached; refresh once before refusing the leaf.
		a.refreshMu.Lock()
		_, rerr := a.refreshBundle(ctx)
		a.refreshMu.Unlock()
		if rerr == nil {
			err = cert.CheckSignatureFrom(a.currentIssuingCA())
		}
	}
	if err != nil {
		return fmt.Errorf("aws-pca: issued certificate is not signed by the configured CA: %w", err)
	}
	return nil
}

func (a *awsPCAAuthority) currentIssuingCA() *x509.Certificate {
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return a.issuingCA
}

func awsPCAIdempotencyToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("aws-pca: idempotency token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
