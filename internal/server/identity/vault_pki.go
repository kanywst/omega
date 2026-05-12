package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// vaultPKIAuthority signs X.509-SVIDs via HashiCorp Vault's PKI
// secrets engine. The CA root key lives in Vault and never sits on
// the omega process's disk - the principal motivation for using
// this backend over the in-tree disk default.
//
// JWT-SVID signing delegates to an embedded *localAuthority. The
// JWT signing key is therefore still on disk under --data-dir;
// see ADR 0005 for the rationale (per-token Vault Transit signing
// would add a network hop to every JWT validation, which the
// 5-minute JWT-SVID TTL makes unattractive). Operators who want
// JWT keys in an HSM too should bring up Vault Transit and add a
// second backend; that is a future PR following the same plugin
// pattern.
type vaultPKIAuthority struct {
	*localAuthority // JWT-SVID + TrustDomain + IssuerURL delegate

	addr       string
	token      string
	mount      string
	role       string
	httpClient *http.Client

	bundleMu  sync.RWMutex
	bundle    []byte
	bundleExp time.Time
	bundleTTL time.Duration
	// refreshMu serialises concurrent refreshBundle callers so a TTL
	// expiry under load triggers one HTTP round-trip to Vault, not
	// N. The full lock-and-recheck dance happens in BundlePEM.
	refreshMu sync.Mutex
}

const (
	defaultVaultPKIMount     = "pki"
	defaultVaultPKIBundleTTL = 5 * time.Minute
	defaultVaultPKITimeout   = 10 * time.Second
)

// newVaultPKIAuthority wires the HTTP client, performs a probe
// `ca_chain` fetch at startup so misconfiguration surfaces here
// instead of at the first IssueSVID call, and primes the bundle
// cache with the result.
func newVaultPKIAuthority(local *localAuthority, cfg Config) (*vaultPKIAuthority, error) {
	addr := strings.TrimRight(cfg.VaultPKIAddr, "/")
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		return nil, fmt.Errorf("identity: vault-pki: VaultPKIAddr must be http(s); got %q", cfg.VaultPKIAddr)
	}
	mount := strings.Trim(cfg.VaultPKIMount, "/")
	if mount == "" {
		mount = defaultVaultPKIMount
	}
	bundleTTL := cfg.VaultPKIBundleTTL
	if bundleTTL <= 0 {
		bundleTTL = defaultVaultPKIBundleTTL
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.VaultPKICACertFile != "" {
		// Production Vault is almost always behind a private CA; load
		// it explicitly rather than asking operators to manage the
		// system trust store on the omega host. Empty path means "use
		// the system store".
		// #nosec G304 -- VaultPKICACertFile is operator-supplied via --ca-vault-pki-ca-cert, not user input.
		caPEM, err := os.ReadFile(cfg.VaultPKICACertFile)
		if err != nil {
			return nil, fmt.Errorf("identity: vault-pki: read ca cert %s: %w", cfg.VaultPKICACertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("identity: vault-pki: ca cert %s has no PEM certificates", cfg.VaultPKICACertFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	a := &vaultPKIAuthority{
		localAuthority: local,
		addr:           addr,
		token:          cfg.VaultPKIToken,
		mount:          mount,
		role:           cfg.VaultPKIRole,
		httpClient:     &http.Client{Timeout: defaultVaultPKITimeout, Transport: transport},
		bundleTTL:      bundleTTL,
	}
	// Boot-time probe so a bad addr / token / mount fails fast.
	if _, err := a.refreshBundle(context.Background()); err != nil {
		return nil, fmt.Errorf("identity: vault-pki: initial ca_chain probe: %w", err)
	}
	return a, nil
}

// BundlePEM overrides the embedded localAuthority's bundle. The
// returned slice is always a defensive copy so callers cannot
// mutate the cached buffer. The cache itself follows the same
// `Lock; check; Unlock; fetch; Lock; store; Unlock` shape as the
// agent's JWKS cache: the network call never holds the lock.
func (a *vaultPKIAuthority) BundlePEM() []byte {
	a.bundleMu.RLock()
	if len(a.bundle) > 0 && time.Now().Before(a.bundleExp) {
		out := append([]byte(nil), a.bundle...)
		a.bundleMu.RUnlock()
		return out
	}
	stale := append([]byte(nil), a.bundle...)
	a.bundleMu.RUnlock()

	// Serialise refreshes: when the TTL expires under load, N
	// concurrent callers would otherwise each fetch ca_chain. Hold
	// refreshMu, recheck the cache (another goroutine may have
	// refreshed while we were queued), and only then fetch.
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	a.bundleMu.RLock()
	if len(a.bundle) > 0 && time.Now().Before(a.bundleExp) {
		out := append([]byte(nil), a.bundle...)
		a.bundleMu.RUnlock()
		return out
	}
	a.bundleMu.RUnlock()

	// Best-effort refresh. If the refresh fails (Vault unreachable,
	// token expired), serve the stale bundle - it's still the trust
	// anchor consumers were chaining to before the blip. Returning
	// nil would suddenly break every workload's mTLS handshake.
	if _, err := a.refreshBundle(context.Background()); err != nil {
		return stale
	}
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return append([]byte(nil), a.bundle...)
}

// IssueSVID forwards the CSR to Vault PKI's
// `POST /v1/<mount>/sign/<role>` endpoint and returns the signed
// leaf wrapped in an *SVID. The SPIFFE ID must lie in the
// configured trust domain; CSR signature verification is the
// caller's responsibility (matches the disk backend's contract).
func (a *vaultPKIAuthority) IssueSVID(id spiffeid.ID, csr *x509.CertificateRequest) (*SVID, error) {
	if id.IsZero() {
		return nil, errors.New("spiffe id is empty")
	}
	if !id.MemberOf(a.trustDomain) {
		return nil, fmt.Errorf("spiffe id %q is not in trust domain %q", id, a.trustDomain)
	}
	if csr == nil {
		return nil, errors.New("csr is nil")
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})

	body, err := json.Marshal(map[string]any{
		"csr":                  string(csrPEM),
		"common_name":          id.String(),
		"uri_sans":             id.String(),
		"format":               "pem",
		"ttl":                  svidValidity.String(),
		"exclude_cn_from_sans": true,
	})
	if err != nil {
		return nil, fmt.Errorf("vault-pki: marshal: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultVaultPKITimeout)
	defer cancel()
	// mount and role come from operator-supplied flags; URL-escape
	// both so a legal-but-unusual path segment (e.g. "team/sub-pki",
	// a role with whitespace) cannot break the request URL.
	signURL := fmt.Sprintf("%s/v1/%s/sign/%s", a.addr, urlEscapePathSegments(a.mount), url.PathEscape(a.role))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, signURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("vault-pki: new request: %w", err)
	}
	req.Header.Set("X-Vault-Token", a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault-pki: sign: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("vault-pki: sign returned %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	// 1 MiB cap on the upstream response: real Vault PKI replies are
	// a few KiB; this bounds memory if a misconfigured / malicious
	// upstream sends a huge body.
	const maxVaultSignResp = 1 << 20
	var out struct {
		Data struct {
			Certificate string   `json:"certificate"`
			CAChain     []string `json:"ca_chain"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxVaultSignResp)).Decode(&out); err != nil {
		return nil, fmt.Errorf("vault-pki: decode: %w", err)
	}
	if out.Data.Certificate == "" {
		return nil, errors.New("vault-pki: response has no certificate")
	}
	block, _ := pem.Decode([]byte(out.Data.Certificate))
	if block == nil {
		return nil, errors.New("vault-pki: certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault-pki: parse certificate: %w", err)
	}
	// Defence in depth: a Vault role misconfiguration (or a hostile
	// upstream) could return a certificate whose SAN or public key
	// is not what omega asked for. Reject mismatches before handing
	// the SVID back to the workload.
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return nil, errors.New("vault-pki: issued certificate public key does not match CSR")
	}
	wantURI := id.URL().String()
	var haveURI bool
	for _, u := range cert.URIs {
		if u.String() == wantURI {
			haveURI = true
			break
		}
	}
	if !haveURI {
		return nil, fmt.Errorf("vault-pki: issued certificate URI SANs %v do not contain requested SPIFFE ID %q", cert.URIs, wantURI)
	}
	return &SVID{
		SPIFFEID:  id,
		CertPEM:   []byte(out.Data.Certificate),
		BundlePEM: a.BundlePEM(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

// urlEscapePathSegments escapes each '/'-separated segment of p so
// the Vault mount path "team/sub-pki" survives URL building without
// collapsing into "team%2Fsub-pki" (which would not match Vault's
// router).
func urlEscapePathSegments(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		parts[i] = url.PathEscape(seg)
	}
	return strings.Join(parts, "/")
}

// refreshBundle pulls /v1/<mount>/ca_chain and replaces the cached
// bytes. The HTTP fetch is done outside the lock so cache-hit
// callers via BundlePEM are not blocked by a slow Vault. Two
// concurrent refreshes may both fetch; the last write wins, both
// observers end up reading a valid bundle.
func (a *vaultPKIAuthority) refreshBundle(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), defaultVaultPKITimeout)
		defer cancel()
	}
	chainURL := fmt.Sprintf("%s/v1/%s/ca_chain", a.addr, urlEscapePathSegments(a.mount))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chainURL, nil)
	if err != nil {
		return nil, fmt.Errorf("vault-pki: new ca_chain request: %w", err)
	}
	req.Header.Set("X-Vault-Token", a.token)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault-pki: ca_chain: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("vault-pki: ca_chain returned %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("vault-pki: read ca_chain: %w", err)
	}
	if len(body) == 0 || !bytes.Contains(body, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, fmt.Errorf("vault-pki: ca_chain response is not PEM (got %d bytes)", len(body))
	}
	a.bundleMu.Lock()
	a.bundle = body
	a.bundleExp = time.Now().Add(a.bundleTTL)
	a.bundleMu.Unlock()
	return body, nil
}
