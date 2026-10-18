package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/kanywst/omega/internal/server/storage"
)

// UserTokenHeader carries the JWT-SVID of the person a --ui-proxy acts
// for. It is a header of its own rather than Authorization so a token
// that leaks into a request is never mistaken for a credential: only a
// caller authenticated as a --ui-proxy over mTLS may present it.
const UserTokenHeader = "Omega-User-Token"

// DefaultUIProxyAudience is the audience a user token must carry,
// unless --ui-proxy-audience names another.
const DefaultUIProxyAudience = "omega-ui"

// DefaultUIProxyMaxTokenTTL is the longest lifetime (exp - iat) a user
// token may have, unless --ui-proxy-max-token-ttl sets another.
const DefaultUIProxyMaxTokenTTL = time.Hour

// viaCtxKey is the context key under which the --ui-proxy that
// presented the user's token is stored.
type viaCtxKey struct{}

// UIProxyConfig names the SPIFFE IDs trusted to act for a signed-in
// person and what their user tokens must look like.
type UIProxyConfig struct {
	Proxies     []string
	Audience    string
	MaxTokenTTL time.Duration
}

// WithUIProxies trusts the given SPIFFE IDs to act for a person whose
// JWT-SVID they present in UserTokenHeader (see ADR 0023). An empty
// Proxies list leaves delegation off: every user token is refused.
func (s *Server) WithUIProxies(cfg UIProxyConfig) *Server {
	if cfg.Audience == "" {
		cfg.Audience = DefaultUIProxyAudience
	}
	if cfg.MaxTokenTTL <= 0 {
		cfg.MaxTokenTTL = DefaultUIProxyMaxTokenTTL
	}
	cfg.Proxies = slices.Clone(cfg.Proxies)
	s.uiProxy = cfg
	return s
}

// ViaSPIFFEID returns the --ui-proxy that acted for the caller, or ""
// when the caller authenticated directly.
func ViaSPIFFEID(ctx context.Context) string {
	id, _ := ctx.Value(viaCtxKey{}).(string)
	return id
}

// withVia adds the acting proxy to an audit payload.
func withVia(ctx context.Context, payload map[string]any) map[string]any {
	if via := ViaSPIFFEID(ctx); via != "" {
		payload["via"] = via
	}
	return payload
}

// delegate resolves the effective caller of a request that carries a
// user token. proxy is the mTLS-authenticated caller. It answers the
// error and returns "" unless proxy is a --ui-proxy, the route accepts
// a user token, and the token is a valid user token; every refusal is
// audited with the proxy as actor.
func (s *Server) delegate(w http.ResponseWriter, r *http.Request, proxy string, delegable bool) string {
	refuse := func(status int, err error) string {
		s.audit(r.Context(), storage.AuditEvent{
			Kind: "ui_proxy.delegate", Actor: proxy, Decision: "deny",
			Payload: mustJSON(map[string]string{"route": r.Pattern, "reason": err.Error()}),
		})
		writeErr(w, status, err)
		return ""
	}
	if !slices.Contains(s.uiProxy.Proxies, proxy) {
		return refuse(http.StatusForbidden, fmt.Errorf("caller is not a --ui-proxy and may not present %s", UserTokenHeader))
	}
	if !delegable {
		return refuse(http.StatusForbidden, fmt.Errorf("this endpoint does not accept %s", UserTokenHeader))
	}
	values := r.Header.Values(UserTokenHeader)
	if len(values) != 1 || values[0] == "" {
		return refuse(http.StatusUnauthorized, fmt.Errorf("%s must hold exactly one token", UserTokenHeader))
	}
	user, err := s.verifyUserToken(values[0])
	if err != nil {
		return refuse(http.StatusUnauthorized, fmt.Errorf("%s: %w", UserTokenHeader, err))
	}
	return user
}

// verifyUserToken checks a user token and returns its subject. It must
// be a JWT-SVID this server issued through POST /v1/oidc/exchange (its
// act claim names the OIDC IdP that signed the person in, and nothing
// else), for exactly the --ui-proxy-audience, unexpired, with a
// lifetime of at most --ui-proxy-max-token-ttl, and not sender
// constrained, since the proxy presents it as a bearer.
func (s *Server) verifyUserToken(token string) (string, error) {
	id, claims, err := s.ca.ParseJWTSVIDClaims(token)
	if err != nil {
		return "", err
	}
	if aud := audienceValues(claims["aud"]); len(aud) != 1 || aud[0] != s.uiProxy.Audience {
		return "", fmt.Errorf("aud must be exactly %q", s.uiProxy.Audience)
	}
	exp, okExp := claimExpiry(claims)
	iat, okIat := claimNumericDate(claims, "iat")
	if !okExp || !okIat {
		return "", errors.New("token must carry iat and exp")
	}
	if life := exp.Sub(iat); life > s.uiProxy.MaxTokenTTL {
		return "", fmt.Errorf("token lifetime %s exceeds the accepted maximum %s", life, s.uiProxy.MaxTokenTTL)
	}
	if _, ok := claims["cnf"]; ok {
		return "", errors.New("token must not be sender-constrained (cnf)")
	}
	act, ok := claims["act"].(map[string]any)
	if !ok || act["kind"] != "oidc-idp" {
		return "", errors.New("token was not issued for a person signed in through an OIDC IdP")
	}
	if _, nested := act["act"]; nested {
		return "", errors.New("token carries a delegation chain")
	}
	return id.String(), nil
}
