package identity_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

const testPCAARN = "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/11111111-2222-3333-4444-555555555555"

// pcaFixture is a fake AWS Private CA speaking the awsJson1_1 protocol
// the SDK uses: POST / with X-Amz-Target naming the operation. It
// signs with its own subordinate CA (under a root it also returns as
// the chain), so issued leaves verify against the bundle omega serves.
type pcaFixture struct {
	server *httptest.Server

	rootPEM  []byte
	subCert  *x509.Certificate
	subKey   crypto.Signer
	subPEM   []byte
	leafMode atomic.Value // string: "" for a valid leaf, or one of the bad-leaf modes in sign

	inProgress    atomic.Int64 // GetCertificate calls left that answer RequestInProgressException
	failCA        atomic.Bool
	caOverride    atomic.Value // [2]string{Certificate, CertificateChain} replacing the real answer
	failIssue     atomic.Bool
	issueHits     atomic.Int64
	getHits       atomic.Int64
	caHits        atomic.Int64
	sawSigV4      atomic.Bool
	mu            sync.Mutex
	lastIssue     map[string]any
	issued        map[string][]byte // certificate ARN -> leaf PEM
	foreignCACert *x509.Certificate
	foreignCAKey  *ecdsa.PrivateKey
}

func mustCA(t *testing.T, cn string, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent, parentKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("create %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", cn, err)
	}
	return cert
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func newPCAFixture(t *testing.T, subKey crypto.Signer) *pcaFixture {
	t.Helper()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := mustCA(t, "PCA Mock Root", rootKey, nil, nil)
	if subKey == nil {
		subKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	sub := mustCA(t, "PCA Mock Issuing CA", subKey, root, rootKey)
	foreignKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreign := mustCA(t, "Foreign CA", foreignKey, nil, nil)

	f := &pcaFixture{
		rootPEM:       certPEM(root),
		subCert:       sub,
		subKey:        subKey,
		subPEM:        certPEM(sub),
		issued:        map[string][]byte{},
		foreignCACert: foreign,
		foreignCAKey:  foreignKey,
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func pcaError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-ErrorType", code)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": code})
}

func (f *pcaFixture) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
		f.sawSigV4.Store(true)
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body["CertificateAuthorityArn"] != testPCAARN {
		pcaError(w, "ResourceNotFoundException")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch r.Header.Get("X-Amz-Target") {
	case "ACMPrivateCA.GetCertificateAuthorityCertificate":
		f.caHits.Add(1)
		if f.failCA.Load() {
			pcaError(w, "AccessDeniedException")
			return
		}
		ca, chain := string(f.subPEM), string(f.rootPEM)
		if o, ok := f.caOverride.Load().([2]string); ok {
			ca, chain = o[0], o[1]
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Certificate":      ca,
			"CertificateChain": chain,
		})
	case "ACMPrivateCA.IssueCertificate":
		f.issueHits.Add(1)
		if f.failIssue.Load() {
			pcaError(w, "AccessDeniedException")
			return
		}
		f.mu.Lock()
		f.lastIssue = body
		f.mu.Unlock()
		leaf, err := f.sign(body)
		if err != nil {
			pcaError(w, "MalformedCSRException")
			return
		}
		arn := fmt.Sprintf("%s/certificate/%d", testPCAARN, f.issueHits.Load())
		f.mu.Lock()
		f.issued[arn] = leaf
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"CertificateArn": arn})
	case "ACMPrivateCA.GetCertificate":
		f.getHits.Add(1)
		if f.inProgress.Load() > 0 {
			f.inProgress.Add(-1)
			pcaError(w, "RequestInProgressException")
			return
		}
		arn, _ := body["CertificateArn"].(string)
		f.mu.Lock()
		leaf, ok := f.issued[arn]
		f.mu.Unlock()
		if !ok {
			pcaError(w, "ResourceNotFoundException")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Certificate":      string(leaf),
			"CertificateChain": string(f.subPEM) + string(f.rootPEM),
		})
	default:
		pcaError(w, "UnknownOperationException")
	}
}

// sign mimics EndEntityCertificate_APIPassthrough/V1: the SAN comes
// from ApiPassthrough, the key from the CSR (a base64 blob of PEM).
func (f *pcaFixture) sign(body map[string]any) ([]byte, error) {
	csrB64, _ := body["Csr"].(string)
	csrPEM, err := base64.StdEncoding.DecodeString(csrB64)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, fmt.Errorf("csr not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	var uris []*url.URL
	pt, _ := body["ApiPassthrough"].(map[string]any)
	ext, _ := pt["Extensions"].(map[string]any)
	sans, _ := ext["SubjectAlternativeNames"].([]any)
	for _, s := range sans {
		m, _ := s.(map[string]any)
		if u, ok := m["UniformResourceIdentifier"].(string); ok {
			parsed, _ := url.Parse(u)
			uris = append(uris, parsed)
		}
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(30 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  uris,
	}
	pub := csr.PublicKey
	parent, parentKey := f.subCert, f.subKey
	mode, _ := f.leafMode.Load().(string)
	switch mode {
	case "extra-uri":
		extra, _ := url.Parse("spiffe://omega.local/admin")
		tpl.URIs = append(tpl.URIs, extra)
	case "wrong-key":
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub = &other.PublicKey
	case "foreign-ca":
		parent, parentKey = f.foreignCACert, f.foreignCAKey
	case "ca-leaf":
		tpl.IsCA = true
	case "cert-sign-ku":
		tpl.KeyUsage |= x509.KeyUsageCertSign
	case "client-only-eku":
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "long-lived":
		tpl.NotAfter = time.Now().Add(24 * time.Hour)
	case "dns-san":
		tpl.DNSNames = []string{"admin.internal"}
	case "expired":
		tpl.NotBefore = time.Now().Add(-2 * time.Hour)
		tpl.NotAfter = time.Now().Add(-time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, parentKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// isolateAWSEnv pins the SDK's credential chain to static test keys so
// no developer profile, SSO cache or instance metadata is consulted.
func isolateAWSEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func pcaConfig(t *testing.T, f *pcaFixture) identity.Config {
	t.Helper()
	isolateAWSEnv(t)
	return identity.Config{
		Kind:           identity.KindAWSPCA,
		TrustDomain:    "omega.local",
		Dir:            filepath.Join(t.TempDir(), "ca"),
		AWSPCACAARN:    testPCAARN,
		AWSPCAEndpoint: f.server.URL,
	}
}

func newPCAAuthority(t *testing.T, f *pcaFixture) identity.Authority {
	t.Helper()
	a, err := identity.New(pcaConfig(t, f))
	if err != nil {
		t.Fatalf("new aws-pca authority: %v", err)
	}
	return a
}

func parseLeaf(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("leaf pem decode")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return c
}

func TestAWSPCAIssueSVID_RoundTrip(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f)
	if f.caHits.Load() < 1 {
		t.Fatalf("expected boot-time CA certificate probe, got %d", f.caHits.Load())
	}

	csr, _ := vaultIssueCSR(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")
	svid, err := a.IssueSVID(id, csr)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !f.sawSigV4.Load() {
		t.Error("requests were not SigV4-signed with the credentials from the default chain")
	}

	leaf := parseLeaf(t, svid.CertPEM)
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != id.String() {
		t.Errorf("leaf URIs = %v, want [%s]", leaf.URIs, id)
	}
	// The bundle carries the issuing CA and its chain to the root; the
	// leaf must verify against the root with the issuing CA as an
	// intermediate taken from the same bundle.
	if !strings.Contains(string(svid.BundlePEM), string(f.subPEM)) || !strings.Contains(string(svid.BundlePEM), string(f.rootPEM)) {
		t.Fatal("bundle does not hold the issuing CA and its chain")
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AppendCertsFromPEM(f.rootPEM)
	inter.AppendCertsFromPEM(f.subPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("leaf does not chain to the PCA root: %v", err)
	}

	f.mu.Lock()
	req := f.lastIssue
	f.mu.Unlock()
	if got := req["TemplateArn"]; got != "arn:aws:acm-pca:::template/EndEntityCertificate_APIPassthrough/V1" {
		t.Errorf("TemplateArn = %v", got)
	}
	if got := req["SigningAlgorithm"]; got != "SHA256WITHECDSA" {
		t.Errorf("SigningAlgorithm = %v, want SHA256WITHECDSA for a P-256 CA", got)
	}
	if tok, _ := req["IdempotencyToken"].(string); tok == "" || len(tok) > 36 {
		t.Errorf("IdempotencyToken = %q, want 1..36 chars", tok)
	}
	validity, _ := req["Validity"].(map[string]any)
	if validity["Type"] != "ABSOLUTE" {
		t.Errorf("Validity.Type = %v", validity["Type"])
	}
	if v, _ := validity["Value"].(float64); time.Until(time.Unix(int64(v), 0)) > 31*time.Minute || time.Until(time.Unix(int64(v), 0)) < 29*time.Minute {
		t.Errorf("Validity.Value %v is not ~30 minutes out", v)
	}
	pt, _ := req["ApiPassthrough"].(map[string]any)
	subj, _ := pt["Subject"].(map[string]any)
	if subj["CommonName"] != id.String() {
		t.Errorf("Subject.CommonName = %v, want %s", subj["CommonName"], id)
	}
}

func TestAWSPCAIssueSVID_PollsWhileInProgress(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f)
	f.inProgress.Store(2)
	csr, _ := vaultIssueCSR(t)
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/poll"), csr); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got := f.getHits.Load(); got != 3 {
		t.Errorf("GetCertificate calls = %d, want 3 (two in-progress, one ready)", got)
	}
}

func TestAWSPCAIssueSVID_PollDeadline(t *testing.T) {
	f := newPCAFixture(t, nil)
	cfg := pcaConfig(t, f)
	cfg.AWSPCATimeout = 400 * time.Millisecond
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	f.inProgress.Store(1 << 30)
	csr, _ := vaultIssueCSR(t)
	_, err = a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/slow"), csr)
	if err == nil || !strings.Contains(err.Error(), "not ready before deadline") {
		t.Fatalf("expected poll deadline error, got %v", err)
	}
}

func TestAWSPCAIssueSVID_IssueError(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f)
	f.failIssue.Store(true)
	csr, _ := vaultIssueCSR(t)
	_, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/x"), csr)
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("expected IssueCertificate error, got %v", err)
	}
	if strings.Contains(err.Error(), "test-secret") {
		t.Fatal("error leaks the secret access key")
	}
}

func TestAWSPCAIssueSVID_RejectsBadLeaf(t *testing.T) {
	for _, mode := range []string{"extra-uri", "wrong-key", "foreign-ca", "ca-leaf", "cert-sign-ku", "client-only-eku", "long-lived", "expired", "dns-san"} {
		t.Run(mode, func(t *testing.T) {
			f := newPCAFixture(t, nil)
			a := newPCAAuthority(t, f)
			f.leafMode.Store(mode)
			csr, _ := vaultIssueCSR(t)
			if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/x"), csr); err == nil {
				t.Fatalf("expected %s leaf to be rejected", mode)
			}
		})
	}
}

func TestAWSPCAIssueSVID_InputValidation(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f)
	csr, _ := vaultIssueCSR(t)
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://other.example/x"), csr); err == nil {
		t.Error("expected foreign trust domain to be rejected")
	}
	if _, err := a.IssueSVID(spiffeid.ID{}, csr); err == nil {
		t.Error("expected empty id to be rejected")
	}
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/x"), nil); err == nil {
		t.Error("expected nil csr to be rejected")
	}
	if f.issueHits.Load() != 0 {
		t.Errorf("invalid input reached IssueCertificate %d times", f.issueHits.Load())
	}
}

func TestAWSPCALongIDHasNoSubject(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f)
	csr, _ := vaultIssueCSR(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/" + strings.Repeat("a", 80))
	if _, err := a.IssueSVID(id, csr); err != nil {
		t.Fatalf("issue: %v", err)
	}
	f.mu.Lock()
	pt, _ := f.lastIssue["ApiPassthrough"].(map[string]any)
	f.mu.Unlock()
	if _, ok := pt["Subject"]; ok {
		t.Error("a SPIFFE ID over 64 bytes must not be sent as the subject CommonName")
	}
}

func TestAWSPCABundleServesStaleOnError(t *testing.T) {
	f := newPCAFixture(t, nil)
	cfg := pcaConfig(t, f)
	cfg.AWSPCABundleTTL = time.Nanosecond
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	first := a.BundlePEM()
	if len(first) == 0 {
		t.Fatal("empty bundle")
	}
	hits := f.caHits.Load()
	f.failCA.Store(true)
	stale := a.BundlePEM()
	if string(stale) != string(first) {
		t.Error("expected the stale bundle on refresh failure")
	}
	if f.caHits.Load() == hits {
		t.Error("expired bundle did not trigger a refresh")
	}
}

func TestAWSPCABundleRefreshFailureBacksOff(t *testing.T) {
	f := newPCAFixture(t, nil)
	cfg := pcaConfig(t, f)
	cfg.AWSPCABundleTTL = 50 * time.Millisecond
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	f.failCA.Store(true)
	time.Sleep(60 * time.Millisecond)
	_ = a.BundlePEM()
	hits := f.caHits.Load()
	for range 5 {
		if len(a.BundlePEM()) == 0 {
			t.Fatal("empty bundle during an outage")
		}
	}
	if f.caHits.Load() != hits {
		t.Errorf("failed refresh retried on every call: %d extra calls", f.caHits.Load()-hits)
	}
}

func TestAWSPCABundleCached(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f)
	hits := f.caHits.Load()
	for range 5 {
		_ = a.BundlePEM()
	}
	if f.caHits.Load() != hits {
		t.Errorf("cached bundle refetched: %d extra calls", f.caHits.Load()-hits)
	}
}

func TestAWSPCARejectsBadCAMaterial(t *testing.T) {
	nonCA := func(f *pcaFixture) string {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(7),
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, f.subCert, f.subKey.Public(), f.subKey)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	cases := []struct {
		name string
		resp func(f *pcaFixture) (ca, chain string)
		want string
	}{
		{"trailing garbage in chain", func(f *pcaFixture) (string, string) {
			return string(f.subPEM), string(f.rootPEM) + "junk\n"
		}, "not PEM"},
		{"other block in chain", func(f *pcaFixture) (string, string) {
			return string(f.subPEM), "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n"
		}, "unexpected PEM block"},
		{"non-CA in chain", func(f *pcaFixture) (string, string) {
			return string(f.subPEM), nonCA(f)
		}, "not marked CA:TRUE"},
		{"chain does not link", func(f *pcaFixture) (string, string) {
			return string(f.subPEM), string(certPEM(f.foreignCACert))
		}, "does not link"},
		{"two certificates as the CA", func(f *pcaFixture) (string, string) {
			return string(f.subPEM) + string(f.rootPEM), ""
		}, "want 1"},
		{"empty CA", func(f *pcaFixture) (string, string) {
			return "", string(f.rootPEM)
		}, "want 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPCAFixture(t, nil)
			ca, chain := tc.resp(f)
			f.caOverride.Store([2]string{ca, chain})
			_, err := identity.New(pcaConfig(t, f))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestAWSPCARejectsPlainHTTPEndpointFromEnv(t *testing.T) {
	f := newPCAFixture(t, nil)
	cfg := pcaConfig(t, f)
	cfg.AWSPCAEndpoint = ""
	t.Setenv("AWS_ENDPOINT_URL_ACM_PCA", "http://pca.example")
	_, err := identity.New(cfg)
	if err == nil || !strings.Contains(err.Error(), "resolved endpoint") {
		t.Fatalf("got %v, want the env endpoint rejected", err)
	}
}

func TestAWSPCABootProbeFails(t *testing.T) {
	f := newPCAFixture(t, nil)
	f.failCA.Store(true)
	_, err := identity.New(pcaConfig(t, f))
	if err == nil || !strings.Contains(err.Error(), "initial CA certificate probe") {
		t.Fatalf("expected boot probe failure, got %v", err)
	}
}

func TestAWSPCASigningAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := []struct {
		name     string
		key      crypto.Signer
		override string
		want     string
	}{
		{"rsa", rsaKey, "", "SHA256WITHRSA"},
		{"p384", p384, "", "SHA384WITHECDSA"},
		{"override", rsaKey, "SHA512WITHRSA", "SHA512WITHRSA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPCAFixture(t, tc.key)
			cfg := pcaConfig(t, f)
			cfg.AWSPCASigningAlgorithm = tc.override
			a, err := identity.New(cfg)
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			csr, _ := vaultIssueCSR(t)
			if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/x"), csr); err != nil {
				t.Fatalf("issue: %v", err)
			}
			f.mu.Lock()
			got := f.lastIssue["SigningAlgorithm"]
			f.mu.Unlock()
			if got != tc.want {
				t.Errorf("SigningAlgorithm = %v, want %s", got, tc.want)
			}
		})
	}
}

func TestAWSPCATemplateOverride(t *testing.T) {
	f := newPCAFixture(t, nil)
	cfg := pcaConfig(t, f)
	cfg.AWSPCATemplateARN = "arn:aws:acm-pca:::template/BlankEndEntityCertificate_APIPassthrough/V1"
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	csr, _ := vaultIssueCSR(t)
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/x"), csr); err != nil {
		t.Fatalf("issue: %v", err)
	}
	f.mu.Lock()
	got := f.lastIssue["TemplateArn"]
	f.mu.Unlock()
	if got != cfg.AWSPCATemplateARN {
		t.Errorf("TemplateArn = %v", got)
	}
}

func TestAWSPCAJWTSVIDStaysLocal(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f)
	id := spiffeid.RequireFromString("spiffe://omega.local/jwt")
	tok, err := a.IssueJWTSVID(id, []string{"aud"}, 5*time.Minute, nil)
	if err != nil {
		t.Fatalf("issue jwt: %v", err)
	}
	got, err := a.ValidateJWTSVID(tok.Token, "aud")
	if err != nil || got != id {
		t.Fatalf("validate jwt: %v (%s)", err, got)
	}
}

func TestAWSPCAConfigRejected(t *testing.T) {
	isolateAWSEnv(t)
	base := func() identity.Config {
		return identity.Config{Kind: identity.KindAWSPCA, TrustDomain: "omega.local", Dir: t.TempDir(), AWSPCACAARN: testPCAARN}
	}
	cases := []struct {
		name string
		mut  func(*identity.Config)
		want string
	}{
		{"no arn", func(c *identity.Config) { c.AWSPCACAARN = "" }, "requires AWSPCACAARN"},
		{"no dir", func(c *identity.Config) { c.Dir = "" }, "--data-dir"},
		{"not an arn", func(c *identity.Config) { c.AWSPCACAARN = "my-ca" }, "AWSPCACAARN"},
		{"wrong service", func(c *identity.Config) {
			c.AWSPCACAARN = "arn:aws:kms:us-east-1:111122223333:key/abc"
		}, "not an acm-pca certificate-authority ARN"},
		{"no region", func(c *identity.Config) {
			c.AWSPCACAARN = "arn:aws:acm-pca::111122223333:certificate-authority/abc"
		}, "region"},
		{"endpoint without scheme", func(c *identity.Config) { c.AWSPCAEndpoint = "pca.example" }, "AWSPCAEndpoint"},
		{"endpoint other scheme", func(c *identity.Config) { c.AWSPCAEndpoint = "ftp://pca.example" }, "must be an https URL"},
		{"plain http to a remote host", func(c *identity.Config) { c.AWSPCAEndpoint = "http://pca.example" }, "non-loopback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base()
			tc.mut(&cfg)
			_, err := identity.New(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestAWSPCAKeepsTheRotatedOutCATrusted(t *testing.T) {
	f := newPCAFixture(t, nil)
	cfg := pcaConfig(t, f)
	cfg.AWSPCABundleTTL = time.Millisecond
	cfg.UpstreamCAGrace = identity.UpstreamCAGrace
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	keeper, ok := a.(identity.UpstreamCAKeeper)
	if !ok {
		t.Fatal("aws-pca authority does not implement UpstreamCAKeeper")
	}
	var mu sync.Mutex
	var events []identity.KeptCAEvent
	keeper.SetKeptCAHook(func(e identity.KeptCAEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	})
	seq := func() int64 { return a.(identity.BundleSequencer).BundleSequence() }
	if n := strings.Count(string(a.BundlePEM()), "BEGIN CERTIFICATE"); n != 2 || seq() != 1 {
		t.Fatalf("before: %d certs, seq %d", n, seq())
	}

	// The CA in AWS is replaced by a new self-signed one.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	next := certPEM(mustCA(t, "PCA Mock CA 2", key, nil, nil))
	f.caOverride.Store([2]string{string(next), ""})
	deadline := time.Now().Add(5 * time.Second)
	for seq() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	bundle := string(a.BundlePEM())
	if n := strings.Count(bundle, "BEGIN CERTIFICATE"); n != 3 || !strings.HasPrefix(bundle, string(next)) {
		t.Fatalf("after rotation the new CA comes first and the old issuing CA and root stay trusted: %d certs", n)
	}
	if seq() != 2 {
		t.Fatalf("spiffe_sequence after rotation: %d", seq())
	}

	// The operator distrusts the old issuing CA: it leaves the bundle at once.
	if n := keeper.DistrustCAs([][32]byte{sha256.Sum256(f.subCert.Raw)}); n != 1 {
		t.Fatalf("DistrustCAs dropped %d, want 1", n)
	}
	if strings.Contains(string(a.BundlePEM()), string(f.subPEM)) {
		t.Fatal("distrusted CA is still served")
	}
	mu.Lock()
	defer mu.Unlock()
	var kept, dropped int
	for _, e := range events {
		switch e.Action {
		case "kept":
			kept++
		case "dropped":
			dropped++
		}
	}
	if kept != 2 || dropped != 1 {
		t.Fatalf("kept-CA events: %d kept, %d dropped; want 2 and 1", kept, dropped)
	}
}

func TestAWSPCAIssueSVID_FollowsACAChangeBeforeTheCacheExpires(t *testing.T) {
	f := newPCAFixture(t, nil)
	a := newPCAAuthority(t, f) // default 5m bundle cache
	// AWS now signs with, and returns, a different CA certificate.
	f.leafMode.Store("foreign-ca")
	f.caOverride.Store([2]string{string(certPEM(f.foreignCACert)), ""})
	csr, _ := vaultIssueCSR(t)
	svid, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/x"), csr)
	if err != nil {
		t.Fatalf("issue after a CA change: %v", err)
	}
	if !strings.HasPrefix(string(svid.BundlePEM), string(certPEM(f.foreignCACert))) {
		t.Error("bundle was not refreshed to the new CA")
	}
}
