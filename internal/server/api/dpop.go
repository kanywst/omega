package api

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/oidc"
)

// DPoP (RFC 9449) proof verification for the endpoints that accept or
// mint sender-constrained tokens.
const (
	dpopTyp = "dpop+jwt"
	// dpopProofWindow bounds how far a proof's iat may be from now, and
	// how long its jti is remembered.
	dpopProofWindow = time.Minute
	dpopMaxJTI      = 256
	// dpopMaxReplayEntries caps the replay cache; once full, proofs are
	// refused rather than accepted unchecked.
	dpopMaxReplayEntries = 100_000
)

var dpopAlgs = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
}

func dpopAlgNames() []string {
	out := make([]string, len(dpopAlgs))
	for i, a := range dpopAlgs {
		out[i] = string(a)
	}
	return out
}

// replayCache remembers hashed keys for at least `retention`: two
// generations rotate every `retention`, so a key recorded just before a
// rotation still survives one full interval, and eviction costs nothing
// per request. It is per process; the endpoints using it are
// leader-only, so one cache sees every request in an HA deployment.
type replayCache struct {
	mu        sync.Mutex
	retention time.Duration
	cur, prev map[[sha256.Size]byte]struct{}
	rotated   time.Time
}

func newReplayCache(retention time.Duration) *replayCache {
	return &replayCache{retention: retention, cur: map[[sha256.Size]byte]struct{}{}, prev: map[[sha256.Size]byte]struct{}{}}
}

// newDPoPReplayCache keeps proof jtis for the whole span a proof can be
// valid: iat may be up to one window ahead of first use and is accepted
// for one window after that.
func newDPoPReplayCache() *replayCache {
	return newReplayCache(2 * dpopProofWindow)
}

var errReplayCacheFull = errors.New("replay cache is full; retry later")

// firstUse records key and reports whether it had not been seen.
func (c *replayCache) firstUse(key string, now time.Time) (bool, error) {
	h := sha256.Sum256([]byte(key))
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.rotated) >= c.retention {
		c.prev, c.cur, c.rotated = c.cur, map[[sha256.Size]byte]struct{}{}, now
	}
	if _, ok := c.cur[h]; ok {
		return false, nil
	}
	if _, ok := c.prev[h]; ok {
		return false, nil
	}
	if len(c.cur)+len(c.prev) >= dpopMaxReplayEntries {
		return false, errReplayCacheFull
	}
	c.cur[h] = struct{}{}
	return true, nil
}

// verifyDPoPProof validates the request's DPoP header for the given
// target URI and returns the base64url SHA-256 JWK thumbprint of the
// proof key (RFC 7638), the value a cnf.jkt claim binds to.
func (s *Server) verifyDPoPProof(r *http.Request, htu string) (string, error) {
	vals := r.Header.Values("DPoP")
	if len(vals) != 1 {
		return "", fmt.Errorf("exactly one DPoP header is required, got %d", len(vals))
	}
	jws, err := jose.ParseSignedCompact(vals[0], dpopAlgs)
	if err != nil {
		return "", fmt.Errorf("parse DPoP proof: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return "", errors.New("DPoP proof must have exactly one signature")
	}
	h := jws.Signatures[0].Protected
	if typ, _ := h.ExtraHeaders[jose.HeaderType].(string); !oidc.TypMatches(typ, dpopTyp) {
		return "", fmt.Errorf("DPoP proof typ %q is not %q", typ, dpopTyp)
	}
	jwk := h.JSONWebKey
	if jwk == nil || !jwk.Valid() || !jwk.IsPublic() {
		return "", errors.New("DPoP proof must carry a valid public jwk header")
	}
	payload, err := jws.Verify(jwk)
	if err != nil {
		return "", fmt.Errorf("verify DPoP proof: %w", err)
	}
	var c struct {
		JTI string          `json:"jti"`
		HTM string          `json:"htm"`
		HTU string          `json:"htu"`
		IAT json.RawMessage `json:"iat"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("decode DPoP proof: %w", err)
	}
	if c.HTM != r.Method {
		return "", fmt.Errorf("DPoP proof htm %q does not match %s", c.HTM, r.Method)
	}
	if !sameTargetURI(c.HTU, htu) {
		return "", fmt.Errorf("DPoP proof htu %q does not match %q", c.HTU, htu)
	}
	var iat float64
	if err := json.Unmarshal(c.IAT, &iat); err != nil {
		return "", errors.New("DPoP proof has no numeric iat")
	}
	now := time.Now()
	if d := now.Sub(time.Unix(int64(iat), 0)); d > dpopProofWindow || d < -dpopProofWindow {
		return "", errors.New("DPoP proof iat is outside the accepted window")
	}
	if c.JTI == "" || len(c.JTI) > dpopMaxJTI {
		return "", fmt.Errorf("DPoP proof jti must be 1 to %d bytes", dpopMaxJTI)
	}
	sum, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("DPoP key thumbprint: %w", err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(sum)
	fresh, err := s.dpopReplay.firstUse(jkt+"|"+c.JTI, now)
	if err != nil {
		return "", err
	}
	if !fresh {
		return "", errors.New("DPoP proof jti has already been used")
	}
	return jkt, nil
}

// sameTargetURI compares htu values per RFC 9449 §4.3: query and
// fragment ignored, scheme and host case-insensitive, default ports
// dropped, path compared after decoding.
func sameTargetURI(got, want string) bool {
	norm := func(raw string) (string, bool) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", false
		}
		scheme := strings.ToLower(u.Scheme)
		host := strings.ToLower(u.Hostname())
		defaultPort := (scheme == "https" && u.Port() == "443") || (scheme == "http" && u.Port() == "80")
		if u.Port() != "" && !defaultPort {
			host += ":" + u.Port()
		}
		return scheme + "://" + host + u.Path, true
	}
	g, ok1 := norm(got)
	w, ok2 := norm(want)
	return ok1 && ok2 && g == w
}

// confirmationJKT returns the cnf.jkt of a token's claims, "" when the
// token has no cnf, and an error for a cnf the caller cannot honour.
func confirmationJKT(claims map[string]any) (string, error) {
	raw, ok := claims["cnf"]
	if !ok {
		return "", nil
	}
	cnf, ok := raw.(map[string]any)
	if !ok {
		return "", errors.New("cnf claim is malformed")
	}
	jkt, _ := cnf["jkt"].(string)
	if jkt == "" || len(cnf) != 1 {
		return "", errors.New("cnf claim must carry only a jkt DPoP binding")
	}
	return jkt, nil
}

// dpopProofOnce verifies the request's DPoP proof at most once, so two
// tokens bound to the same key can share one proof without tripping the
// replay check.
func (s *Server) dpopProofOnce(r *http.Request, htu string) func() (string, error) {
	var (
		done bool
		jkt  string
		err  error
	)
	return func() (string, error) {
		if !done {
			done = true
			if htu == "" {
				err = errors.New("DPoP-bound token presented to a server without --issuer-url")
			} else {
				jkt, err = s.verifyDPoPProof(r, htu)
			}
		}
		return jkt, err
	}
}

// checkPresentedBinding enforces a cnf claim on a token presented to
// omega: cnf.jkt needs a DPoP proof for that key, cnf.x5t#S256 needs the
// matching verified client certificate. Tokens without cnf pass; any
// other confirmation method is refused.
func checkPresentedBinding(r *http.Request, claims map[string]any, proof func() (string, error)) error {
	raw, ok := claims["cnf"]
	if !ok {
		return nil
	}
	cnf, ok := raw.(map[string]any)
	if !ok || len(cnf) != 1 {
		return errors.New("cnf claim is malformed")
	}
	if jkt, ok := cnf["jkt"].(string); ok && jkt != "" {
		got, err := proof()
		if err != nil {
			return err
		}
		if got != jkt {
			return errors.New("DPoP proof key does not match the token's cnf.jkt")
		}
		return nil
	}
	if x5t, ok := cnf["x5t#S256"].(string); ok && x5t != "" {
		var leaf *x509.Certificate
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
			leaf = r.TLS.VerifiedChains[0][0]
		}
		if leaf == nil || identity.CertThumbprintS256(leaf) != x5t {
			return errors.New("token is bound to a client certificate that was not presented")
		}
		return nil
	}
	return errors.New("cnf claim uses an unsupported confirmation method")
}
