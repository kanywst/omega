// step_ca.go implements Authority for the Smallstep step-ca upstream
// signer. Like the Vault PKI backend it is a hybrid: X.509-SVID
// signing is delegated to step-ca (the root key never sits on omega's
// disk), JWT-SVID signing stays local. ADR 0005 documents the
// rationale - per-token Vault Transit / step-ca signing would add a
// network hop to every JWT validation, and the 5-minute JWT-SVID TTL
// makes that trade-off unattractive.
//
// step-ca authenticates each `/1.0/sign` call with a one-time-token
// (OTT): a JWT signed by a JWK provisioner's private key. The
// matching public JWK lives in step-ca's `ca.json` under the
// configured provisioner. omega loads the private JWK at startup,
// signs one OTT per CSR with the audience, expiry, and SANs that
// step-ca's signing handler validates against the CSR.

package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	defaultStepCABundleTTL = 5 * time.Minute
	defaultStepCATimeout   = 10 * time.Second
	stepCAOTTLifetime      = 5 * time.Minute
)

// stepCAAuthority signs X.509-SVIDs against a remote step-ca. The
// embedded *localAuthority handles the JWT-SVID side, trust domain
// accessor, and OIDC issuer URL.
type stepCAAuthority struct {
	*localAuthority

	addr             string
	provisionerName  string
	provisionerKeyID string
	signer           jose.Signer

	rootSHA256 string // fingerprint of the bundle; embedded in OTT `sha` claim

	httpClient *http.Client

	bundleMu  sync.RWMutex
	bundle    []byte
	bundleExp time.Time
	bundleTTL time.Duration
}

func newStepCAAuthority(local *localAuthority, cfg Config) (*stepCAAuthority, error) {
	addr := strings.TrimRight(cfg.StepCAURL, "/")
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		return nil, fmt.Errorf("identity: step-ca: StepCAURL must be http(s); got %q", cfg.StepCAURL)
	}
	bundleTTL := cfg.StepCABundleTTL
	if bundleTTL <= 0 {
		bundleTTL = defaultStepCABundleTTL
	}

	signer, kid, err := parseProvisionerJWK(cfg.StepCAProvisionerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: step-ca: provisioner key: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.StepCACACertFile != "" {
		// Real step-ca deployments are almost always behind a private
		// CA; load it explicitly rather than asking operators to
		// install it in the system store on the omega host.
		// #nosec G304 -- StepCACACertFile is operator-supplied via --ca-step-ca-ca-cert, not user input.
		caPEM, err := os.ReadFile(cfg.StepCACACertFile)
		if err != nil {
			return nil, fmt.Errorf("identity: step-ca: read ca cert %s: %w", cfg.StepCACACertFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("identity: step-ca: ca cert %s has no PEM certificates", cfg.StepCACACertFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	a := &stepCAAuthority{
		localAuthority:   local,
		addr:             addr,
		provisionerName:  cfg.StepCAProvisionerName,
		provisionerKeyID: kid,
		signer:           signer,
		httpClient:       &http.Client{Timeout: defaultStepCATimeout, Transport: transport},
		bundleTTL:        bundleTTL,
	}

	// Boot-time probe so a bad URL / TLS config / unreachable step-ca
	// fails fast at startup instead of at first IssueSVID.
	if _, err := a.refreshBundle(context.Background()); err != nil {
		return nil, fmt.Errorf("identity: step-ca: initial /roots probe: %w", err)
	}
	return a, nil
}

// parseProvisionerJWK parses the PEM-wrapped private JWK and returns
// a jose.Signer plus the key id. step-ca uses the JWK `kid` to
// resolve the matching provisioner; mismatched kid → 401.
func parseProvisionerJWK(raw []byte) (jose.Signer, string, error) {
	// Accept either a raw JSON JWK or a PEM block of type
	// "JSON WEB KEY". The PEM form is friendlier on disk because
	// editors that lint trailing whitespace do not corrupt it.
	body := raw
	if block, _ := pem.Decode(raw); block != nil {
		body = block.Bytes
	}
	body = bytes.TrimSpace(body)
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(body); err != nil {
		return nil, "", fmt.Errorf("parse jwk: %w", err)
	}
	if jwk.IsPublic() {
		return nil, "", errors.New("provisioner key must be a private JWK")
	}
	if jwk.KeyID == "" {
		return nil, "", errors.New("provisioner JWK is missing kid")
	}
	alg := jose.SignatureAlgorithm(jwk.Algorithm)
	if alg == "" {
		alg = jose.ES256
	}
	opts := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", jwk.KeyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jwk.Key}, opts)
	if err != nil {
		return nil, "", fmt.Errorf("new signer: %w", err)
	}
	return signer, jwk.KeyID, nil
}

func (a *stepCAAuthority) BundlePEM() []byte {
	a.bundleMu.RLock()
	if len(a.bundle) > 0 && time.Now().Before(a.bundleExp) {
		out := append([]byte(nil), a.bundle...)
		a.bundleMu.RUnlock()
		return out
	}
	stale := append([]byte(nil), a.bundle...)
	a.bundleMu.RUnlock()

	// Best-effort refresh. A stale bundle is better than no bundle:
	// returning nil would break every workload's mTLS handshake the
	// moment step-ca burps.
	if _, err := a.refreshBundle(context.Background()); err != nil {
		return stale
	}
	a.bundleMu.RLock()
	defer a.bundleMu.RUnlock()
	return append([]byte(nil), a.bundle...)
}

// refreshBundle fetches `GET /roots.pem` and replaces the cached
// bytes. The HTTP fetch is done outside the lock so cache-hit callers
// via BundlePEM are not blocked by a slow step-ca.
func (a *stepCAAuthority) refreshBundle(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultStepCATimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.addr+"/roots.pem", nil)
	if err != nil {
		return nil, fmt.Errorf("step-ca: new request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("step-ca: GET /roots.pem: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("step-ca: /roots.pem returned %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	const maxRoots = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRoots))
	if err != nil {
		return nil, fmt.Errorf("step-ca: read /roots.pem: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("step-ca: empty /roots.pem response")
	}
	// Compute the SHA-256 fingerprint of the first root for the OTT
	// `sha` claim, which step-ca pins to detect MITM swap-attacks
	// during enrolment. Hex-encoded, no separators, matches step CLI.
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("step-ca: /roots.pem does not begin with a CERTIFICATE block")
	}
	sum := sha256.Sum256(block.Bytes)
	rootSHA := hex.EncodeToString(sum[:])

	a.bundleMu.Lock()
	a.bundle = body
	a.bundleExp = time.Now().Add(a.bundleTTL)
	a.rootSHA256 = rootSHA
	a.bundleMu.Unlock()
	return body, nil
}

// mintOTT builds and signs a one-time-token whose claims bind the
// request to exactly this SPIFFE ID and root fingerprint. step-ca
// rejects the token if its `sans` differ from the CSR's URI SANs or
// the `sha` differs from its loaded root.
func (a *stepCAAuthority) mintOTT(id spiffeid.ID) (string, error) {
	a.bundleMu.RLock()
	rootSHA := a.rootSHA256
	a.bundleMu.RUnlock()
	if rootSHA == "" {
		return "", errors.New("step-ca: bundle not loaded, cannot pin OTT to root sha")
	}
	now := time.Now()
	jti, err := randomJTI()
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss":  a.provisionerName,
		"aud":  a.addr + "/1.0/sign",
		"nbf":  now.Add(-30 * time.Second).Unix(),
		"iat":  now.Unix(),
		"exp":  now.Add(stepCAOTTLifetime).Unix(),
		"jti":  jti,
		"sha":  rootSHA,
		"sans": []string{id.String()},
		"sub":  id.String(),
	}
	return jwt.Signed(a.signer).Claims(claims).Serialize()
}

func randomJTI() (string, error) {
	var buf [16]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return "", fmt.Errorf("step-ca: random jti: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// IssueSVID forwards the CSR to step-ca's `/1.0/sign`, validates
// that the returned leaf carries the requested SPIFFE ID and CSR's
// public key, and returns the assembled SVID.
func (a *stepCAAuthority) IssueSVID(id spiffeid.ID, csr *x509.CertificateRequest) (*SVID, error) {
	if id.IsZero() {
		return nil, errors.New("spiffe id is empty")
	}
	if !id.MemberOf(a.trustDomain) {
		return nil, fmt.Errorf("spiffe id %q is not in trust domain %q", id, a.trustDomain)
	}
	if csr == nil {
		return nil, errors.New("csr is nil")
	}
	ott, err := a.mintOTT(id)
	if err != nil {
		return nil, err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	body, err := json.Marshal(map[string]any{
		"csr":       string(csrPEM),
		"ott":       ott,
		"notAfter":  time.Now().Add(svidValidity).Format(time.RFC3339),
		"notBefore": time.Now().Add(-30 * time.Second).Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("step-ca: marshal: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultStepCATimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.addr+"/1.0/sign", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("step-ca: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("step-ca: sign: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("step-ca: sign returned %d: %s", resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	const maxSignResp = 1 << 20
	var out struct {
		Crt          string   `json:"crt"`
		CA           string   `json:"ca"`
		Certificate  string   `json:"certificate"`
		CertChainPEM []string `json:"certChain"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSignResp)).Decode(&out); err != nil {
		return nil, fmt.Errorf("step-ca: decode: %w", err)
	}
	// step-ca historically returned the leaf in `crt`; newer
	// versions use `certificate`. Accept either.
	leafPEM := out.Crt
	if leafPEM == "" {
		leafPEM = out.Certificate
	}
	if leafPEM == "" {
		return nil, errors.New("step-ca: response has no leaf certificate (neither `crt` nor `certificate`)")
	}

	block, _ := pem.Decode([]byte(leafPEM))
	if block == nil {
		return nil, errors.New("step-ca: leaf certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("step-ca: parse certificate: %w", err)
	}
	// Defence in depth: mirror the Vault backend's checks. A
	// misconfigured provisioner or a hostile upstream could otherwise
	// return a cert that does not match the CSR's key or the
	// requested SPIFFE ID.
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return nil, errors.New("step-ca: issued certificate public key does not match CSR")
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
		return nil, fmt.Errorf("step-ca: issued certificate URI SANs %v do not contain requested SPIFFE ID %q", cert.URIs, wantURI)
	}
	return &SVID{
		SPIFFEID:  id,
		CertPEM:   []byte(leafPEM),
		BundlePEM: a.BundlePEM(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}
