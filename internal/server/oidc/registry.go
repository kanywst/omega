// Package oidc is the external OIDC IdP federation layer: it accepts
// ID tokens from operator-configured upstream IdPs (Keycloak, Okta,
// Entra ID, Google Workspace, Dex, Authentik, ...), validates them
// against the IdP's JWKS, and projects the claims onto a SPIFFE ID
// the rest of omega can use as a Human principal.
//
// The package is intentionally narrow: discovery + JWKS fetch +
// signature/iss/aud/exp validation. SPIFFE ID rendering and
// JWT-SVID issuance live in the caller (api package) so the same
// validator can be reused by future surfaces (e.g. an admin UI
// session bridge) without dragging in CA dependencies.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdPConfig declares one upstream IdP that omega will accept tokens
// from. Name is the operator-facing handle used in
// `POST /v1/oidc/exchange` requests; Issuer is the OIDC discovery
// origin (its `/.well-known/openid-configuration` is fetched at
// boot); Audiences are the values an incoming token's `aud` claim
// must match.
type IdPConfig struct {
	Name      string
	Issuer    string
	Audiences []string
	// SPIFFEIDTemplate is rendered with the validated claims to
	// produce the Human SPIFFE ID. Placeholders supported by the
	// caller are documented next to its render function; the
	// registry never interprets the template itself.
	SPIFFEIDTemplate string
}

// Validate returns nil iff the config is internally consistent.
func (c IdPConfig) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("oidc: idp name is empty")
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("oidc: idp issuer is empty")
	}
	if !strings.HasPrefix(c.Issuer, "https://") && !strings.HasPrefix(c.Issuer, "http://") {
		return fmt.Errorf("oidc: idp %q: issuer must be an http(s) URL", c.Name)
	}
	if strings.TrimSpace(c.SPIFFEIDTemplate) == "" {
		return fmt.Errorf("oidc: idp %q: spiffe_id_template is empty", c.Name)
	}
	return nil
}

// Claims is the validated payload of an external ID token. Standard
// OIDC claims are surfaced as their own fields; the full claim set
// is also returned for templates that reference e.g. `groups` or
// `email_verified`.
type Claims struct {
	Issuer       string
	Subject      string
	Audience     []string
	Email        string
	PreferredUN  string
	Name         string
	Raw          map[string]any
	IssuedAt     time.Time
	ExpiresAt    time.Time
	IdPName      string // copied from IdPConfig.Name for downstream rendering
}

// Registry is the omega-server's view of all configured IdPs.
// Lookups are by Name; the underlying IdP client owns its own
// discovery and JWKS cache.
type Registry struct {
	idps map[string]*idpClient
}

// NewRegistry initialises one idpClient per config. Discovery is
// lazy (first Validate call against an IdP triggers it) so server
// startup does not depend on every configured IdP being reachable
// at boot.
func NewRegistry(configs []IdPConfig) (*Registry, error) {
	idps := make(map[string]*idpClient, len(configs))
	for _, c := range configs {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		if _, dup := idps[c.Name]; dup {
			return nil, fmt.Errorf("oidc: duplicate idp name %q", c.Name)
		}
		idps[c.Name] = newIdPClient(c)
	}
	return &Registry{idps: idps}, nil
}

// Names returns the registered IdP names in stable (lexicographic)
// order. Map iteration in Go is non-deterministic, so callers that
// log or render the names get a consistent listing across runs.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.idps))
	for n := range r.idps {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ErrUnknownIdP is returned when the caller asks for an IdP that
// was not configured at startup.
var ErrUnknownIdP = errors.New("oidc: unknown idp")

// Lookup returns the IdPConfig for name or ErrUnknownIdP.
func (r *Registry) Lookup(name string) (IdPConfig, error) {
	c, ok := r.idps[name]
	if !ok {
		return IdPConfig{}, fmt.Errorf("%w: %q", ErrUnknownIdP, name)
	}
	return c.cfg, nil
}

// Validate parses idToken, verifies its signature against the named
// IdP's JWKS, checks `iss` matches the configured issuer, `aud`
// intersects the configured audiences, and `exp` is in the future.
// Returns the projected Claims on success.
func (r *Registry) Validate(ctx context.Context, idpName, idToken string) (*Claims, error) {
	c, ok := r.idps[idpName]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIdP, idpName)
	}
	return c.validate(ctx, idToken)
}

// idpClient handles discovery, JWKS fetching, and validation for one
// upstream IdP. Discovery + JWKS are cached behind a mutex; the JWKS
// is re-fetched when validation fails with an unknown `kid`, with a
// short cooldown to prevent thrash against a misconfigured IdP.
type idpClient struct {
	cfg    IdPConfig
	http   *http.Client

	mu          sync.Mutex
	jwksURI     string
	jwks        *jose.JSONWebKeySet
	lastRefresh time.Time
}

func newIdPClient(cfg IdPConfig) *idpClient {
	return &idpClient{
		cfg:  cfg,
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// discoveryDocument is the minimal subset of OIDC Discovery 1.0
// fields we consume. Other fields are ignored even when present.
type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func (c *idpClient) ensureDiscovery(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwksURI != "" {
		return nil
	}
	url := strings.TrimRight(c.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("oidc: idp %q: build discovery request: %w", c.cfg.Name, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: idp %q: fetch discovery: %w", c.cfg.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("oidc: idp %q: discovery returned %d: %s", c.cfg.Name, resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	var doc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("oidc: idp %q: decode discovery: %w", c.cfg.Name, err)
	}
	if doc.Issuer != c.cfg.Issuer {
		return fmt.Errorf("oidc: idp %q: discovery issuer %q does not match configured %q", c.cfg.Name, doc.Issuer, c.cfg.Issuer)
	}
	if doc.JWKSURI == "" {
		return fmt.Errorf("oidc: idp %q: discovery has no jwks_uri", c.cfg.Name)
	}
	c.jwksURI = doc.JWKSURI
	return nil
}

const jwksRefreshCooldown = 30 * time.Second

func (c *idpClient) refreshJWKS(ctx context.Context) error {
	c.mu.Lock()
	if !c.lastRefresh.IsZero() && time.Since(c.lastRefresh) < jwksRefreshCooldown {
		c.mu.Unlock()
		return errors.New("oidc: jwks refresh cooldown in effect")
	}
	uri := c.jwksURI
	c.mu.Unlock()
	if uri == "" {
		return errors.New("oidc: jwks uri not yet discovered")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return fmt.Errorf("oidc: idp %q: build jwks request: %w", c.cfg.Name, err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: idp %q: fetch jwks: %w", c.cfg.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("oidc: idp %q: jwks returned %d: %s", c.cfg.Name, resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("oidc: idp %q: decode jwks: %w", c.cfg.Name, err)
	}
	c.mu.Lock()
	c.jwks = &jwks
	c.lastRefresh = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *idpClient) jwksSnapshot() *jose.JSONWebKeySet {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.jwks
}

// supportedSigAlgs is the closed set of JWS algorithms we accept on
// ID tokens. RS256 and ES256 cover essentially every production
// OIDC provider; PS256 is the OIDC Federation recommendation.
// Symmetric (HS*) algorithms are deliberately excluded because they
// would require sharing a secret with the IdP, which is incompatible
// with public OIDC discovery.
var supportedSigAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.PS256, jose.PS384, jose.PS512}

func (c *idpClient) validate(ctx context.Context, idToken string) (*Claims, error) {
	if strings.TrimSpace(idToken) == "" {
		return nil, errors.New("oidc: id_token is empty")
	}
	if err := c.ensureDiscovery(ctx); err != nil {
		return nil, err
	}
	if c.jwksSnapshot() == nil {
		if err := c.refreshJWKS(ctx); err != nil {
			return nil, err
		}
	}
	parsed, err := jwt.ParseSigned(idToken, supportedSigAlgs)
	if err != nil {
		return nil, fmt.Errorf("oidc: idp %q: parse id_token: %w", c.cfg.Name, err)
	}
	jwks := c.jwksSnapshot()
	// Look up the kid; refresh once on miss to handle key rotation.
	var keyFound bool
	if jwks != nil {
		for _, h := range parsed.Headers {
			if jwks.Key(h.KeyID) != nil {
				keyFound = true
				break
			}
		}
	}
	if !keyFound {
		if err := c.refreshJWKS(ctx); err != nil && !strings.Contains(err.Error(), "cooldown") {
			return nil, err
		}
		jwks = c.jwksSnapshot()
	}
	// One Claims call, two destinations: go-jose verifies the
	// signature once and unmarshals into every dest. Calling twice
	// would re-verify the signature against the JWKS for no benefit.
	var (
		raw map[string]any
		std jwt.Claims
	)
	if err := parsed.Claims(jwks, &raw, &std); err != nil {
		return nil, fmt.Errorf("oidc: idp %q: verify id_token: %w", c.cfg.Name, err)
	}
	if std.Issuer != c.cfg.Issuer {
		return nil, fmt.Errorf("oidc: idp %q: iss mismatch (token=%q config=%q)", c.cfg.Name, std.Issuer, c.cfg.Issuer)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		AnyAudience: jwt.Audience(c.cfg.Audiences),
		Time:        time.Now(),
	}, 30*time.Second); err != nil {
		return nil, fmt.Errorf("oidc: idp %q: claim validation: %w", c.cfg.Name, err)
	}
	cl := &Claims{
		Issuer:   std.Issuer,
		Subject:  std.Subject,
		Audience: []string(std.Audience),
		Raw:      raw,
		IdPName:  c.cfg.Name,
	}
	if std.IssuedAt != nil {
		cl.IssuedAt = std.IssuedAt.Time()
	}
	if std.Expiry != nil {
		cl.ExpiresAt = std.Expiry.Time()
	}
	if s, _ := raw["email"].(string); s != "" {
		cl.Email = s
	}
	if s, _ := raw["preferred_username"].(string); s != "" {
		cl.PreferredUN = s
	}
	if s, _ := raw["name"].(string); s != "" {
		cl.Name = s
	}
	return cl, nil
}
