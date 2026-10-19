package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/kanywst/omega/internal/server/metrics"
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
// a user token, and the token is a valid user token. A refusal is
// audited with the proxy as actor when the leader serves the request;
// a follower serving a read only logs it. Each caller gets at most one
// refusal row per refusalAuditWindow; the next row counts the refusals
// in between as "suppressed".
func (s *Server) delegate(w http.ResponseWriter, r *http.Request, proxy string, delegable bool) string {
	refuse := func(status int, err error) string {
		if ok, suppressed := s.refusals.allow(proxy, time.Now()); ok {
			payload := map[string]any{"route": r.Pattern, "reason": err.Error()}
			if suppressed > 0 {
				payload["suppressed"] = suppressed
			}
			if s.appendAudit(r.Context(), storage.AuditEvent{
				Kind: "ui_proxy.delegate", Actor: proxy, Decision: "deny",
				Payload: mustJSON(payload),
			}) != nil {
				s.refusals.unrecorded(proxy, suppressed+1)
			}
		} else {
			metrics.UIProxyRefusalsSuppressed.Inc()
			slog.Debug("ui proxy refusal suppressed", "caller", proxy, "route", r.Pattern, "reason", err.Error())
		}
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
// else), for exactly the --ui-proxy-audience, unexpired with no clock
// leeway, with a lifetime of at most --ui-proxy-max-token-ttl, and not
// sender constrained, since the proxy presents it as a bearer.
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
	if !time.Now().Before(exp) {
		return "", errors.New("token has expired")
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

// refusalAuditWindow is how often one caller's refused user tokens
// reach the audit chain, so a caller looping bad requests cannot grow
// the chain at will.
const refusalAuditWindow = time.Minute

// refusalMaxCallers bounds the callers refusalLimiter tracks. Past it a
// refusal is audited rather than suppressed.
const refusalMaxCallers = 10_000

type refusalState struct {
	until      time.Time
	suppressed int
}

// refusalLimiter lets one refusal per caller per window through to the
// audit chain and counts the rest.
type refusalLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	callers map[string]*refusalState
	pruned  time.Time
}

func newRefusalLimiter(window time.Duration) *refusalLimiter {
	return &refusalLimiter{window: window, callers: map[string]*refusalState{}}
}

// allow reports whether caller's refusal at now is audited, and how many
// of its refusals were suppressed since its last audited one.
func (l *refusalLimiter) allow(caller string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.callers[caller]
	if ok && now.Before(st.until) {
		st.suppressed++
		return false, 0
	}
	suppressed := 0
	if ok {
		suppressed = st.suppressed
	} else if len(l.callers) >= refusalMaxCallers {
		// At most one sweep a window, so a full table does not cost every
		// new caller a scan. An entry still holding a count stays until
		// its caller's next refusal records it.
		if now.Sub(l.pruned) >= l.window {
			l.pruned = now
			for k, v := range l.callers {
				if !now.Before(v.until) && v.suppressed == 0 {
					delete(l.callers, k)
				}
			}
		}
		if len(l.callers) >= refusalMaxCallers {
			return true, 0
		}
	}
	l.callers[caller] = &refusalState{until: now.Add(l.window)}
	return true, suppressed
}

// unrecorded gives back the slot allow handed out when the audit row
// could not be written, keeping its n refusals for the next row.
func (l *refusalLimiter) unrecorded(caller string, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.callers[caller]; ok {
		st.until = time.Time{}
		st.suppressed += n
	}
}
