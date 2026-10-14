package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

// kvFixture is a fake Azure Key Vault plus a fake Entra ID token
// endpoint on one httptest server. It holds EC P-256 key versions
// under one key name and answers get key and sign the way Key Vault
// does: base64url coordinates, a raw R || S signature.
type kvFixture struct {
	server *httptest.Server
	name   string
	token  string

	mu       sync.Mutex
	versions map[string]*ecdsa.PrivateKey
	current  string

	// Knobs for error cases.
	kty       string
	crv       string
	keyOps    []string
	enabled   bool
	signFail  int // status code returned by sign when non-zero
	signWrong bool

	signHits  atomic.Int64
	tokenHits atomic.Int64
	getHits   atomic.Int64
}

func newKVFixture(t *testing.T) *kvFixture {
	t.Helper()
	f := &kvFixture{
		name:     "omega-ca",
		token:    "test-access-token",
		versions: map[string]*ecdsa.PrivateKey{},
		kty:      "EC",
		crv:      "P-256",
		keyOps:   []string{"sign", "verify"},
		enabled:  true,
	}
	f.addVersion(t, "v1")
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenHits.Add(1)
		f.mu.Lock()
		token := f.token
		f.mu.Unlock()
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "client-1" ||
			r.PostForm.Get("scope") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"bad grant"}`))
			return
		}
		if r.PostForm.Get("client_secret") != "s3cret" && r.PostForm.Get("client_assertion") != "federated-jwt" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\nTrace ID: x"}`))
			return
		}
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"` + token + `"}`))
	})
	mux.HandleFunc("GET /keys/{name}", f.getKey)
	mux.HandleFunc("GET /keys/{name}/{version}", f.getKey)
	mux.HandleFunc("POST /keys/{name}/{version}/sign", f.sign)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *kvFixture) addVersion(t *testing.T, version string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.versions[version] = k
	f.current = version
	f.mu.Unlock()
}

func (f *kvFixture) set(fn func()) {
	f.mu.Lock()
	fn()
	f.mu.Unlock()
}

func (f *kvFixture) key(version string) *ecdsa.PrivateKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	if version == "" {
		version = f.current
	}
	return f.versions[version]
}

func kvError(w http.ResponseWriter, status int, code, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (f *kvFixture) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Query().Get("api-version") == "" {
		kvError(w, http.StatusBadRequest, "MissingApiVersionParameter", "api-version is required")
		return false
	}
	f.mu.Lock()
	token := f.token
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+token {
		kvError(w, http.StatusUnauthorized, "Unauthorized", "AKV10000: Request is missing a Bearer or PoP token.")
		return false
	}
	return true
}

func (f *kvFixture) getKey(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(w, r) {
		return
	}
	f.getHits.Add(1)
	version := r.PathValue("version")
	f.mu.Lock()
	name, kty, crv, keyOps, enabled := f.name, f.kty, f.crv, f.keyOps, f.enabled
	if version == "" {
		version = f.current
	}
	k := f.versions[version]
	f.mu.Unlock()
	if r.PathValue("name") != name {
		kvError(w, http.StatusNotFound, "KeyNotFound", "A key with (name/id) "+r.PathValue("name")+" was not found in this key vault.")
		return
	}
	if k == nil {
		kvError(w, http.StatusNotFound, "KeyNotFound", "version not found")
		return
	}
	pt, _ := k.PublicKey.Bytes()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"key": map[string]any{
			"kid":     f.server.URL + "/keys/" + name + "/" + version,
			"kty":     kty,
			"crv":     crv,
			"key_ops": keyOps,
			"x":       base64.RawURLEncoding.EncodeToString(pt[1:33]),
			"y":       base64.RawURLEncoding.EncodeToString(pt[33:65]),
		},
		"attributes": map[string]any{"enabled": enabled},
	})
}

func (f *kvFixture) sign(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(w, r) {
		return
	}
	f.signHits.Add(1)
	f.mu.Lock()
	signFail, signWrong := f.signFail, f.signWrong
	f.mu.Unlock()
	if signFail != 0 {
		kvError(w, signFail, "Forbidden", "The user does not have keys sign permission on key vault.")
		return
	}
	var req struct {
		Alg   string `json:"alg"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Alg != "ES256" {
		kvError(w, http.StatusBadRequest, "BadParameter", "bad sign request")
		return
	}
	digest, err := base64.RawURLEncoding.DecodeString(req.Value)
	if err != nil || len(digest) != 32 {
		kvError(w, http.StatusBadRequest, "BadParameter", "bad digest")
		return
	}
	k := f.key(r.PathValue("version"))
	if k == nil {
		kvError(w, http.StatusNotFound, "KeyNotFound", "version not found")
		return
	}
	if signWrong {
		k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	rr, ss, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		kvError(w, http.StatusInternalServerError, "InternalError", err.Error())
		return
	}
	sig := make([]byte, 64)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	_ = json.NewEncoder(w).Encode(map[string]string{
		"kid":   f.server.URL + "/keys/" + r.PathValue("name") + "/" + r.PathValue("version"),
		"value": base64.RawURLEncoding.EncodeToString(sig),
	})
}

func (f *kvFixture) env(extra map[string]string) func(string) string {
	m := map[string]string{
		"AZURE_TENANT_ID":      "tenant-1",
		"AZURE_CLIENT_ID":      "client-1",
		"AZURE_CLIENT_SECRET":  "s3cret",
		"AZURE_AUTHORITY_HOST": f.server.URL,
	}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func (f *kvFixture) config(dir string) identity.Config {
	return identity.Config{
		Kind:                 identity.KindAzureKeyVault,
		TrustDomain:          "example.org",
		Dir:                  dir,
		AzureKeyVaultURL:     f.server.URL,
		AzureKeyVaultKeyName: f.name,
		AzureKeyVaultGetenv:  f.env(nil),
	}
}

func newCSR(t *testing.T) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr, k
}

func firstCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAzureKeyVaultRoundTrip(t *testing.T) {
	f := newKVFixture(t)
	dir := t.TempDir()
	cfg := f.config(dir)
	cfg.Issuer = "https://omega.example.org"
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.TrustDomain().String() != "example.org" || a.IssuerURL() != "https://omega.example.org" {
		t.Fatalf("trust domain %q issuer %q", a.TrustDomain(), a.IssuerURL())
	}
	if _, ok := a.(identity.CAReloader); ok {
		t.Fatal("azure-keyvault authority must not offer a disk CA reload")
	}

	// The CA was self-signed through Key Vault for the current key
	// version and kept in the CA directory.
	ca := firstCert(t, a.BundlePEM())
	if !ca.IsCA || !ca.PublicKey.(*ecdsa.PublicKey).Equal(&f.key("").PublicKey) {
		t.Fatal("bundle CA is not a CA for the Key Vault key")
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CA is not self-signed by the Key Vault key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, identity.AzureKeyVaultCACertFile)); err != nil {
		t.Fatalf("self-signed CA not persisted: %v", err)
	}
	if got := f.signHits.Load(); got != 1 {
		t.Fatalf("sign calls after start = %d, want 1 (the CA)", got)
	}

	id := spiffeid.RequireFromString("spiffe://example.org/web")
	csr, _ := newCSR(t)
	svid, err := a.IssueSVID(id, csr)
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}
	leaf := firstCert(t, svid.CertPEM)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("leaf does not chain to the Key Vault CA: %v", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != id.String() {
		t.Fatalf("leaf URIs %v", leaf.URIs)
	}

	jwt, err := a.IssueJWTSVID(id, []string{"aud-1"}, time.Minute, map[string]any{"cnf": map[string]any{"x5t#S256": identity.CertThumbprintS256(leaf)}})
	if err != nil {
		t.Fatalf("IssueJWTSVID: %v", err)
	}
	kid, err := a.JWTKeyID()
	if err != nil || kid != jwt.KeyID {
		t.Fatalf("JWTKeyID %q (%v), token kid %q", kid, err, jwt.KeyID)
	}
	if got, err := a.ValidateJWTSVID(jwt.Token, "aud-1"); err != nil || got != id {
		t.Fatalf("ValidateJWTSVID: %v %v", got, err)
	}
	if _, err := a.ValidatePresentedCertBinding(jwt.Token, "aud-1", leaf); err != nil {
		t.Fatalf("ValidatePresentedCertBinding: %v", err)
	}
	if _, claims, err := a.ParseJWTSVIDClaims(jwt.Token); err != nil || claims["iss"] != "https://omega.example.org" {
		t.Fatalf("ParseJWTSVIDClaims: %v %v", claims, err)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	raw, err := a.JWTBundle()
	if err != nil || json.Unmarshal(raw, &jwks) != nil || len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != kid {
		t.Fatalf("JWTBundle %s (%v)", raw, err)
	}
	if got := f.signHits.Load(); got != 3 {
		t.Fatalf("sign calls = %d, want 3 (CA, SVID, JWT)", got)
	}
	if got := f.tokenHits.Load(); got != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", got)
	}

	// A restart reuses the kept CA instead of minting another.
	b, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if string(b.BundlePEM()) != string(a.BundlePEM()) {
		t.Fatal("restart minted a new CA")
	}
	if got := f.signHits.Load(); got != 3 {
		t.Fatalf("restart signed %d times", got-3)
	}
	if _, err := b.ValidateJWTSVID(jwt.Token, "aud-1"); err != nil {
		t.Fatalf("token from before the restart: %v", err)
	}
}

func TestAzureKeyVaultKeyRotatedFailsClosed(t *testing.T) {
	f := newKVFixture(t)
	dir := t.TempDir()
	if _, err := identity.New(f.config(dir)); err != nil {
		t.Fatal(err)
	}
	f.addVersion(t, "v2")
	_, err := identity.New(f.config(dir))
	if err == nil || !strings.Contains(err.Error(), "the key changed") {
		t.Fatalf("want a key-changed error, got %v", err)
	}
	// Pinning the old version keeps the old CA working.
	cfg := f.config(dir)
	cfg.AzureKeyVaultKeyVersion = "v1"
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("pinned v1: %v", err)
	}
	csr, _ := newCSR(t)
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://example.org/x"), csr); err != nil {
		t.Fatalf("IssueSVID with v1: %v", err)
	}
	cfg.AzureKeyVaultKeyVersion = "v9"
	if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), "KeyNotFound") {
		t.Fatalf("unknown version: %v", err)
	}
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey, isCA bool) []byte {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "supplied"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAzureKeyVaultSuppliedCert(t *testing.T) {
	f := newKVFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	prev := selfSigned(t, other, true)
	active := selfSigned(t, f.key(""), true)
	path := filepath.Join(t.TempDir(), "ca.pem")
	// The previous CA comes first: order does not decide which signs.
	if err := os.WriteFile(path, append(append([]byte{}, prev...), active...), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := f.config("")
	cfg.AzureKeyVaultCACertFile = path
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if f.signHits.Load() != 0 {
		t.Fatal("a supplied certificate must not be re-minted")
	}
	if got := firstCert(t, a.BundlePEM()); !got.PublicKey.(*ecdsa.PublicKey).Equal(&f.key("").PublicKey) {
		t.Fatal("the signing CA must come first in the bundle")
	}
	if strings.Count(string(a.BundlePEM()), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("the extra CA is not in the bundle")
	}
	raw, _ := a.JWTBundle()
	if strings.Count(string(raw), `"kid"`) != 2 {
		t.Fatalf("JWKS should carry both CAs: %s", raw)
	}

	// Every other certificate becomes a trust anchor, so it must be a
	// current P-256 CA too.
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	expiredTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{CommonName: "expired"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	expiredDER, err := x509.CreateCertificate(rand.Reader, expiredTpl, expiredTpl, &other.PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	// A CA issued by another CA, not a root.
	other2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuedTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "issued"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	issuedDER, err := x509.CreateCertificate(rand.Reader, issuedTpl, firstCert(t, prev), &other2.PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	issuedExtra := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuedDER})
	for name, tc := range map[string]struct {
		extra []byte
		want  string
	}{
		"non-CA extra":  {selfSigned(t, other, false), "is not a CA certificate"},
		"P-384 extra":   {selfSigned(t, p384, true), "P-256"},
		"expired extra": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER}), "expired"},
		"issued extra":  {issuedExtra, "not a self-signed root"},
	} {
		if err := os.WriteFile(path, append(append([]byte{}, active...), tc.extra...), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want %q, got %v", name, tc.want, err)
		}
	}

	// A file without a certificate for the Key Vault key is refused.
	if err := os.WriteFile(path, prev, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), "no certificate matches") {
		t.Fatalf("mismatch: %v", err)
	}
	// So is a non-CA certificate for the key.
	if err := os.WriteFile(path, selfSigned(t, f.key(""), false), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), "not a CA certificate") {
		t.Fatalf("non-CA: %v", err)
	}
	// And a CA certificate for the key issued by another CA.
	issued := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "intermediate"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	parent := firstCert(t, prev)
	der, err := x509.CreateCertificate(rand.Reader, issued, parent, &f.key("").PublicKey, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), "not a self-signed root") {
		t.Fatalf("intermediate: %v", err)
	}
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("not pem: %v", err)
	}
	cfg.AzureKeyVaultCACertFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := identity.New(cfg); err == nil {
		t.Fatal("missing file accepted")
	}
	// No file and no directory leaves nowhere to keep a CA.
	cfg.AzureKeyVaultCACertFile = ""
	if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), "no CA directory") {
		t.Fatalf("no dir: %v", err)
	}
}

func TestAzureKeyVaultKeyChecks(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*kvFixture)
		want string
	}{
		{"rsa", func(f *kvFixture) { f.kty = "RSA" }, "only EC P-256"},
		{"curve", func(f *kvFixture) { f.crv = "P-384" }, "only P-256"},
		{"disabled", func(f *kvFixture) { f.enabled = false }, "disabled"},
		{"no sign op", func(f *kvFixture) { f.keyOps = []string{"verify"} }, "does not permit the sign operation"},
		{"wrong name", func(f *kvFixture) { f.name = "other" }, "KeyNotFound"},
		{"sign forbidden", func(f *kvFixture) { f.signFail = http.StatusForbidden }, "Forbidden"},
		{"foreign signature", func(f *kvFixture) { f.signWrong = true }, "does not verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newKVFixture(t)
			cfg := f.config(t.TempDir())
			f.mu.Lock()
			tc.mod(f)
			f.mu.Unlock()
			_, err := identity.New(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "test-access-token") {
				t.Fatal("error leaks the access token")
			}
		})
	}
}

func TestAzureKeyVaultSignErrorAtIssuance(t *testing.T) {
	f := newKVFixture(t)
	a, err := identity.New(f.config(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	id := spiffeid.RequireFromString("spiffe://example.org/web")
	f.set(func() { f.signFail = http.StatusTooManyRequests })
	csr, _ := newCSR(t)
	if _, err := a.IssueSVID(id, csr); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("IssueSVID under throttling: %v", err)
	}
	if _, err := a.IssueJWTSVID(id, []string{"a"}, 0, nil); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("IssueJWTSVID under throttling: %v", err)
	}

	// A 401 drops the cached token, so the next call fetches a new one.
	f.set(func() { f.signFail, f.token = 0, "rotated-token" })
	if _, err := a.IssueJWTSVID(id, []string{"a"}, 0, nil); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("stale token: %v", err)
	}
	before := f.tokenHits.Load()
	if _, err := a.IssueJWTSVID(id, []string{"a"}, 0, nil); err != nil {
		t.Fatalf("after token refresh: %v", err)
	}
	if f.tokenHits.Load() != before+1 {
		t.Fatal("the token was not refetched after a 401")
	}
}

func TestAzureKeyVaultConfigErrors(t *testing.T) {
	f := newKVFixture(t)
	cases := []struct {
		name string
		mod  func(*identity.Config)
		want string
	}{
		{"no url", func(c *identity.Config) { c.AzureKeyVaultURL = "" }, "requires AzureKeyVaultURL"},
		{"no key", func(c *identity.Config) { c.AzureKeyVaultKeyName = "" }, "requires AzureKeyVaultKeyName"},
		{"bad trust domain", func(c *identity.Config) { c.TrustDomain = "Not A Domain" }, "trust domain"},
		{"plain http", func(c *identity.Config) { c.AzureKeyVaultURL = "http://myvault.vault.azure.net" }, "must use https"},
		{"other scheme", func(c *identity.Config) { c.AzureKeyVaultURL = "ftp://myvault.vault.azure.net" }, "must use https"},
		{"path", func(c *identity.Config) { c.AzureKeyVaultURL = f.server.URL + "/keys/x" }, "bare https"},
		{"slash in key", func(c *identity.Config) { c.AzureKeyVaultKeyName = "a/b" }, "must not contain"},
		{"half credential", func(c *identity.Config) {
			c.AzureKeyVaultGetenv = func(k string) string {
				if k == "AZURE_CLIENT_SECRET" {
					return "x"
				}
				return ""
			}
		}, "needs AZURE_TENANT_ID"},
		{"bad secret", func(c *identity.Config) {
			c.AzureKeyVaultGetenv = f.env(map[string]string{"AZURE_CLIENT_SECRET": "wrong"})
		}, "invalid_client: AADSTS7000215"},
		{"http authority", func(c *identity.Config) {
			c.AzureKeyVaultGetenv = f.env(map[string]string{"AZURE_AUTHORITY_HOST": "http://login.example"})
		}, "AZURE_AUTHORITY_HOST"},
		{"bad tenant", func(c *identity.Config) {
			c.AzureKeyVaultGetenv = f.env(map[string]string{"AZURE_TENANT_ID": "a/b"})
		}, "AZURE_TENANT_ID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := f.config(t.TempDir())
			tc.mod(&cfg)
			_, err := identity.New(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAzureKeyVaultWorkloadIdentity(t *testing.T) {
	f := newKVFixture(t)
	tokenFile := filepath.Join(t.TempDir(), "azure-identity-token")
	if err := os.WriteFile(tokenFile, []byte("federated-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := f.config(t.TempDir())
	cfg.AzureKeyVaultGetenv = f.env(map[string]string{"AZURE_CLIENT_SECRET": "", "AZURE_FEDERATED_TOKEN_FILE": tokenFile})
	if _, err := identity.New(cfg); err != nil {
		t.Fatalf("workload identity: %v", err)
	}

	for _, content := range []string{"", "wrong-jwt"} {
		if err := os.WriteFile(tokenFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := identity.New(cfg); err == nil {
			t.Fatalf("federated token %q accepted", content)
		}
	}
	cfg.AzureKeyVaultGetenv = f.env(map[string]string{"AZURE_CLIENT_SECRET": "", "AZURE_FEDERATED_TOKEN_FILE": tokenFile + ".missing"})
	if _, err := identity.New(cfg); err == nil || !strings.Contains(err.Error(), "federated token file") {
		t.Fatalf("missing token file: %v", err)
	}
}

// TestAzureKeyVaultSignatureFormat checks the JWT-SVID signature is
// the JWS R || S form verifiable with the CA public key directly.
func TestAzureKeyVaultSignatureFormat(t *testing.T) {
	f := newKVFixture(t)
	a, err := identity.New(f.config(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := a.IssueJWTSVID(spiffeid.RequireFromString("spiffe://example.org/w"), []string{"a"}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok.Token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature %d bytes (%v)", len(sig), err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&f.key("").PublicKey, sum[:], r, s) {
		t.Fatal("JWT-SVID signature does not verify under the Key Vault key")
	}
}
