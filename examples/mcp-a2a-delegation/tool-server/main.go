// tool-server is the MCP / A2A "tool" side of the delegation demo.
// It exposes a single endpoint, GET /tool/issues, that requires a
// Bearer JWT-SVID in the Authorization header. The token is verified
// against the Omega control plane's JWKS (`/v1/jwt/bundle`), and the
// flattened RFC 8693 act chain is returned in the response body so
// the demo script can assert that the human principal is reachable
// from the leaf agent identity.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:19000", "listen address")
		jwksURL  = flag.String("jwks-url", "http://127.0.0.1:18097/v1/jwt/bundle", "Omega JWKS endpoint")
		audience = flag.String("audience", "mcp://github-issue", "expected JWT audience for tool calls")
	)
	flag.Parse()

	ks := newKeyStore(*jwksURL)
	if err := ks.refresh(); err != nil {
		log.Fatalf("initial JWKS fetch: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /tool/issues", func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			writeErr(w, http.StatusUnauthorized, "missing Bearer token")
			return
		}
		sub, chain, err := ks.verify(token, *audience)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		// Echo a fake "issues list" so the demo client has something
		// concrete to print. Real MCP servers would dispatch to their
		// tool implementation here.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":               true,
			"caller_spiffe_id": sub,
			"delegation_chain": chain,
			"issues": []map[string]any{
				{"id": 42, "title": "demo issue (echoed by tool-server)"},
			},
		})
	})

	log.Printf("[tool-server] listening on %s (audience=%s, jwks=%s)", *addr, *audience, *jwksURL)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// keyStore holds the ES256 public keys fetched from Omega's JWKS
// endpoint. It refreshes on demand when a kid is unknown.
type keyStore struct {
	url  string
	mu   sync.RWMutex
	keys map[string]*ecdsa.PublicKey
}

func newKeyStore(url string) *keyStore {
	return &keyStore{url: url, keys: map[string]*ecdsa.PublicKey{}}
}

func (k *keyStore) refresh() error {
	resp, err := http.Get(k.url)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("JWKS status %d: %s", resp.StatusCode, body)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	out := map[string]*ecdsa.PublicKey{}
	for _, j := range jwks.Keys {
		if j.Kty != "EC" || j.Crv != "P-256" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return fmt.Errorf("decode x: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return fmt.Errorf("decode y: %w", err)
		}
		if len(x) != 32 || len(y) != 32 {
			return fmt.Errorf("jwk coordinates must be 32 bytes each (got x=%d, y=%d)", len(x), len(y))
		}
		point := make([]byte, 0, 65)
		point = append(point, 0x04)
		point = append(point, x...)
		point = append(point, y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			return fmt.Errorf("jwk point is not on the P-256 curve: %w", err)
		}
		out[j.Kid] = pub
	}
	k.mu.Lock()
	k.keys = out
	k.mu.Unlock()
	return nil
}

func (k *keyStore) lookup(kid string) (*ecdsa.PublicKey, bool) {
	k.mu.RLock()
	pub, ok := k.keys[kid]
	k.mu.RUnlock()
	return pub, ok
}

// verify parses the token, verifies the ES256 signature against the
// JWKS-resolved public key, checks audience and expiry, and returns
// the sub claim plus the flattened root -> leaf delegation chain.
func (k *keyStore) verify(token, audience string) (string, []string, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return "", nil, fmt.Errorf("parse jwt: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return "", nil, errors.New("jwt: missing header")
	}
	kid := parsed.Headers[0].KeyID
	pub, ok := k.lookup(kid)
	if !ok {
		// One re-fetch in case the CA was rotated since startup.
		if err := k.refresh(); err != nil {
			return "", nil, fmt.Errorf("refresh JWKS: %w", err)
		}
		pub, ok = k.lookup(kid)
		if !ok {
			return "", nil, fmt.Errorf("unknown kid %q", kid)
		}
	}

	var raw map[string]any
	if err := parsed.Claims(pub, &raw); err != nil {
		return "", nil, fmt.Errorf("verify jwt: %w", err)
	}

	var std jwt.Claims
	if err := parsed.Claims(pub, &std); err != nil {
		return "", nil, fmt.Errorf("verify std claims: %w", err)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		AnyAudience: jwt.Audience{audience},
		Time:        time.Now(),
	}, 30*time.Second); err != nil {
		return "", nil, fmt.Errorf("validate jwt: %w", err)
	}

	sub, _ := raw["sub"].(string)
	chain := []string{sub}
	if act, ok := raw["act"].(map[string]any); ok {
		chain = append(flattenAct(act), sub)
	}
	return sub, chain, nil
}

// flattenAct walks the nested RFC 8693 act claim from outermost to
// innermost and returns subjects in root -> leaf order (matching the
// orientation Omega's TokenExchangeResponse.delegation_chain uses).
func flattenAct(act map[string]any) []string {
	var stack []string
	for cur := act; cur != nil; {
		sub, _ := cur["sub"].(string)
		if sub != "" {
			stack = append(stack, sub)
		}
		next, _ := cur["act"].(map[string]any)
		cur = next
	}
	for i, j := 0, len(stack)-1; i < j; i, j = i+1, j-1 {
		stack[i], stack[j] = stack[j], stack[i]
	}
	return stack
}
