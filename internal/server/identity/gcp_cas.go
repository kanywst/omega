// gcp_cas.go implements Authority for Google Cloud Certificate
// Authority Service (CAS). Like the Vault PKI and step-ca backends it
// is a hybrid: X.509-SVID signing is delegated to a CAS CA pool (the
// CA keys live in Google-managed HSMs and never sit on omega's disk),
// JWT-SVID signing stays local. ADR 0005 documents the rationale.
//
// The backend calls the CAS v1 REST API directly with an OAuth 2.0
// bearer token from Application Default Credentials, rather than
// pulling in the generated cloud.google.com/go/security/privateca
// client: omega needs two calls (certificates.create and
// caPools.fetchCaCerts), and the REST surface keeps the dependency
// footprint to golang.org/x/oauth2 and lets tests run against an
// httptest fake.

package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	defaultGCPCASEndpoint  = "https://privateca.googleapis.com"
	defaultGCPCASBundleTTL = 5 * time.Minute
	defaultGCPCASTimeout   = 10 * time.Second
	// gcpCASRetryInterval is how long a stale bundle is served after a
	// failed refresh before the next attempt, so an outage costs one
	// fetchCaCerts timeout per interval instead of one per caller.
	gcpCASRetryInterval = 30 * time.Second
	// gcpCASClockSkew bounds how far CAS's clock may lead omega's when
	// checking the issued certificate's validity window.
	gcpCASClockSkew = 5 * time.Minute
	gcpCASScope     = "https://www.googleapis.com/auth/cloud-platform"
	maxGCPCASResp   = 1 << 20
)

var (
	gcpCASPoolRe     = regexp.MustCompile(`^projects/[a-z0-9.:-]+/locations/[a-z0-9-]+/caPools/[a-zA-Z0-9_-]{1,63}$`)
	gcpCASTemplateRe = regexp.MustCompile(`^projects/[a-z0-9.:-]+/locations/[a-z0-9-]+/certificateTemplates/[a-zA-Z0-9_-]{1,63}$`)
	gcpCASCAIDRe     = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)
)

// gcpCASAuthority signs X.509-SVIDs through a CAS CA pool. The
// embedded *localAuthority handles the JWT-SVID side, the trust domain
// accessor, and the OIDC issuer URL.
type gcpCASAuthority struct {
	*localAuthority

	endpoint   string
	pool       string
	issuingCA  string
	template   string
	httpClient *http.Client
	bundleTTL  time.Duration
	bundleMu   sync.RWMutex
	bundle     []byte
	bundleExp  time.Time
	// refreshMu serialises concurrent refreshBundle callers so a TTL
	// expiry under load triggers one fetchCaCerts call, not N.
	refreshMu sync.Mutex
}

func newGCPCASAuthority(local *localAuthority, cfg Config) (*gcpCASAuthority, error) {
	if !gcpCASPoolRe.MatchString(cfg.GCPCASPool) {
		return nil, fmt.Errorf("identity: gcp-cas: GCPCASPool must be projects/<project>/locations/<location>/caPools/<pool>; got %q", cfg.GCPCASPool)
	}
	if cfg.GCPCASIssuingCA != "" && !gcpCASCAIDRe.MatchString(cfg.GCPCASIssuingCA) {
		return nil, fmt.Errorf("identity: gcp-cas: GCPCASIssuingCA must be a CA id matching [a-zA-Z0-9_-]{1,63}; got %q", cfg.GCPCASIssuingCA)
	}
	if cfg.GCPCASCertificateTemplate != "" && !gcpCASTemplateRe.MatchString(cfg.GCPCASCertificateTemplate) {
		return nil, fmt.Errorf("identity: gcp-cas: GCPCASCertificateTemplate must be projects/<project>/locations/<location>/certificateTemplates/<template>; got %q", cfg.GCPCASCertificateTemplate)
	}
	endpoint, err := gcpCASEndpoint(cfg.GCPCASEndpoint)
	if err != nil {
		return nil, err
	}
	bundleTTL := cfg.GCPCASBundleTTL
	if bundleTTL <= 0 {
		bundleTTL = defaultGCPCASBundleTTL
	}
	ts := cfg.GCPCASTokenSource
	if ts == nil {
		// The context outlives this call: the returned token source keeps
		// it for every later refresh, so it must not be cancelled.
		creds, err := google.FindDefaultCredentials(context.Background(), gcpCASScope)
		if err != nil {
			return nil, fmt.Errorf("identity: gcp-cas: application default credentials: %w", err)
		}
		ts = creds.TokenSource
	}
	// oauth2.Transport attaches "Authorization: Bearer <token>" to every
	// request. The token is never logged: error messages below carry
	// only the response status and a bounded body preview from CAS.
	transport := &oauth2.Transport{
		Source: oauth2.ReuseTokenSource(nil, ts),
		Base:   http.DefaultTransport.(*http.Transport).Clone(),
	}
	a := &gcpCASAuthority{
		localAuthority: local,
		endpoint:       endpoint,
		pool:           cfg.GCPCASPool,
		issuingCA:      cfg.GCPCASIssuingCA,
		template:       cfg.GCPCASCertificateTemplate,
		httpClient:     &http.Client{Timeout: defaultGCPCASTimeout, Transport: transport},
		bundleTTL:      bundleTTL,
	}
	// Boot-time probe so a bad pool name, missing IAM grant, or
	// unreachable endpoint fails at startup instead of at first IssueSVID.
	if _, err := a.refreshBundle(context.Background()); err != nil {
		return nil, fmt.Errorf("identity: gcp-cas: initial fetchCaCerts probe: %w", err)
	}
	return a, nil
}

// gcpCASEndpoint normalises the API base URL. The bearer token rides
// on every request, so plain http is refused except for a loopback
// host (a local fake or emulator).
func gcpCASEndpoint(raw string) (string, error) {
	if raw == "" {
		return defaultGCPCASEndpoint, nil
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return "", fmt.Errorf("identity: gcp-cas: endpoint: %w", err)
	}
	if u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("identity: gcp-cas: endpoint must be a base URL like %s; got %q", defaultGCPCASEndpoint, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", fmt.Errorf("identity: gcp-cas: endpoint %q must use https (http is allowed only for a loopback host)", raw)
		}
	default:
		return "", fmt.Errorf("identity: gcp-cas: endpoint must be http(s); got %q", raw)
	}
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// BundlePEM returns the cached trust anchors of the CA pool, refreshing
// them once the TTL lapses. A failed refresh serves the stale bundle:
// returning nil would break every workload's mTLS handshake the moment
// CAS is unreachable.
func (a *gcpCASAuthority) BundlePEM() []byte {
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

	if _, err := a.refreshBundle(context.Background()); err != nil {
		slog.Warn("gcp-cas: trust bundle refresh failed; serving the cached bundle", "pool", a.pool, "retry_in", gcpCASRetryInterval, "err", err)
		a.bundleMu.Lock()
		a.bundleExp = time.Now().Add(gcpCASRetryInterval)
		a.bundleMu.Unlock()
		return stale
	}
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return append([]byte(nil), a.bundle...)
}

// refreshBundle calls `POST /v1/<pool>:fetchCaCerts` and caches every
// certificate of every CA chain in the pool, deduplicated, in the
// order returned. Intermediates are kept alongside the roots: omega
// hands workloads the leaf alone, so a pool whose CAs are subordinate
// needs the issuing CA in the bundle for the leaf to verify.
func (a *gcpCASAuthority) refreshBundle(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultGCPCASTimeout)
	defer cancel()
	var out struct {
		CACerts []struct {
			Certificates []string `json:"certificates"`
		} `json:"caCerts"`
	}
	if err := a.call(ctx, "/v1/"+a.pool+":fetchCaCerts", nil, []byte("{}"), &out); err != nil {
		return nil, fmt.Errorf("gcp-cas: fetchCaCerts: %w", err)
	}
	var buf bytes.Buffer
	seen := map[string]bool{}
	for _, chain := range out.CACerts {
		for _, c := range chain.Certificates {
			block, _ := pem.Decode([]byte(c))
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("gcp-cas: fetchCaCerts returned a certificate that is not PEM")
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("gcp-cas: fetchCaCerts: parse certificate: %w", err)
			}
			if seen[string(block.Bytes)] {
				continue
			}
			seen[string(block.Bytes)] = true
			_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		}
	}
	if buf.Len() == 0 {
		return nil, errors.New("gcp-cas: fetchCaCerts returned no CA certificates (is any CA in the pool enabled?)")
	}
	body := buf.Bytes()
	a.bundleMu.Lock()
	a.bundle = body
	a.bundleExp = time.Now().Add(a.bundleTTL)
	a.bundleMu.Unlock()
	return body, nil
}

// IssueSVID asks CAS to sign a certificate for the CSR's public key.
// The request uses CertificateConfig rather than pemCsr because omega's
// CSRs carry no SANs: the SPIFFE ID is set as the only URI SAN here,
// the same way the Vault backend passes uri_sans. The pool's issuance
// policy must therefore allow SAN passthrough.
func (a *gcpCASAuthority) IssueSVID(id spiffeid.ID, csr *x509.CertificateRequest) (*SVID, error) {
	if id.IsZero() {
		return nil, errors.New("spiffe id is empty")
	}
	if !id.MemberOf(a.trustDomain) {
		return nil, fmt.Errorf("spiffe id %q is not in trust domain %q", id, a.trustDomain)
	}
	if csr == nil {
		return nil, errors.New("csr is nil")
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: csr.RawSubjectPublicKeyInfo})
	certReq := map[string]any{
		// Protobuf Duration in JSON: seconds with an "s" suffix.
		"lifetime": strconv.FormatInt(int64(svidValidity/time.Second), 10) + "s",
		"config": map[string]any{
			"subjectConfig": map[string]any{
				"subject":        map[string]any{},
				"subjectAltName": map[string]any{"uris": []string{id.String()}},
			},
			"x509Config": map[string]any{
				"caOptions": map[string]any{"isCa": false},
				"keyUsage": map[string]any{
					"baseKeyUsage": map[string]any{
						"digitalSignature": true,
						"keyEncipherment":  true,
						"keyAgreement":     true,
					},
					"extendedKeyUsage": map[string]any{
						"serverAuth": true,
						"clientAuth": true,
					},
				},
			},
			// bytes fields are base64 in proto JSON; encoding/json
			// base64-encodes a []byte, which is what CAS expects.
			"publicKey": map[string]any{"key": pubPEM, "format": "PEM"},
		},
	}
	if a.template != "" {
		certReq["certificateTemplate"] = a.template
	}
	body, err := json.Marshal(certReq)
	if err != nil {
		return nil, fmt.Errorf("gcp-cas: marshal: %w", err)
	}
	certID, err := gcpCASCertificateID()
	if err != nil {
		return nil, err
	}
	// certificateId is required by Enterprise-tier pools and ignored by
	// DevOps-tier ones, so always send one.
	q := url.Values{"certificateId": {certID}}
	if a.issuingCA != "" {
		q.Set("issuingCertificateAuthorityId", a.issuingCA)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultGCPCASTimeout)
	defer cancel()
	var out struct {
		PEMCertificate string `json:"pemCertificate"`
	}
	if err := a.call(ctx, "/v1/"+a.pool+"/certificates", q, body, &out); err != nil {
		return nil, fmt.Errorf("gcp-cas: create certificate: %w", err)
	}
	if out.PEMCertificate == "" {
		return nil, errors.New("gcp-cas: response has no pemCertificate")
	}
	block, _ := pem.Decode([]byte(out.PEMCertificate))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("gcp-cas: pemCertificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcp-cas: parse certificate: %w", err)
	}
	if err := checkGCPCASLeaf(cert, id, csr); err != nil {
		return nil, err
	}
	bundle, err := a.verifyLeaf(cert)
	if err != nil {
		return nil, err
	}
	return &SVID{
		SPIFFEID:  id,
		CertPEM:   pem.EncodeToMemory(block),
		BundlePEM: bundle,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

// checkGCPCASLeaf is defence in depth against a pool's baseline values,
// a template, or a hostile upstream: the certificate must be a leaf for
// the CSR's key, name exactly the requested SPIFFE ID and nothing else
// (an X.509-SVID has one URI SAN), and live no longer than an SVID.
func checkGCPCASLeaf(cert *x509.Certificate, id spiffeid.ID, csr *x509.CertificateRequest) error {
	if cert.IsCA {
		return errors.New("gcp-cas: issued certificate is a CA certificate")
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return errors.New("gcp-cas: issued certificate public key does not match CSR")
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != id.URL().String() {
		return fmt.Errorf("gcp-cas: issued certificate URI SANs %v are not exactly the requested SPIFFE ID %q (does the pool's issuance policy allow SAN passthrough?)", cert.URIs, id)
	}
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 {
		return errors.New("gcp-cas: issued certificate carries DNS, IP or email SANs omega did not request")
	}
	if cert.NotAfter.After(time.Now().Add(svidValidity + gcpCASClockSkew)) {
		return fmt.Errorf("gcp-cas: issued certificate is valid until %s, longer than the %s SVID lifetime", cert.NotAfter.UTC().Format(time.RFC3339), svidValidity)
	}
	return nil
}

// verifyLeaf checks that cert chains to the pool's trust bundle and
// returns that bundle. A failure against the cached bundle triggers one
// refresh first, since a CA newly added to the pool can sign before the
// cache would have picked it up.
func (a *gcpCASAuthority) verifyLeaf(cert *x509.Certificate) ([]byte, error) {
	bundle := a.BundlePEM()
	if verifyAgainstBundle(cert, bundle) == nil {
		return bundle, nil
	}
	a.refreshMu.Lock()
	fresh, err := a.refreshBundle(context.Background())
	a.refreshMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("gcp-cas: issued certificate does not chain to the cached bundle and the refresh failed: %w", err)
	}
	if err := verifyAgainstBundle(cert, fresh); err != nil {
		return nil, fmt.Errorf("gcp-cas: issued certificate does not chain to the pool's CA certificates: %w", err)
	}
	return append([]byte(nil), fresh...), nil
}

func verifyAgainstBundle(cert *x509.Certificate, bundle []byte) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return errors.New("empty trust bundle")
	}
	// Verify at the leaf's own notBefore: this checks the chain, not the
	// clock, so a CAS clock slightly ahead of omega's cannot fail it.
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: cert.NotBefore,
	})
	return err
}

// call POSTs body to endpoint+path?query and decodes a 2xx JSON reply
// into out. A non-2xx reply becomes an error carrying the status and a
// bounded preview of the body (the Google error message, never the
// request's bearer token).
func (a *gcpCASAuthority) call(ctx context.Context, path string, query url.Values, body []byte, out any) error {
	u := a.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("returned %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxGCPCASResp)).Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// gcpCASCertificateID returns a random certificate id matching CAS's
// `[a-zA-Z0-9_-]{1,63}`.
func gcpCASCertificateID() (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return "", fmt.Errorf("gcp-cas: random certificate id: %w", err)
	}
	return "omega-" + hex.EncodeToString(buf[:]), nil
}
