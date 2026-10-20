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

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

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
	// kind is a fixed name for the refusal and r.Pattern a registered
	// route, so the keys stay bounded while a new kind of refusal, or one
	// on another route, still gets its own row within the window.
	refuse := func(status int, kind string, err error) string {
		key := proxy + "\x00" + kind + "\x00" + r.Pattern
		if ok, suppressed := s.refusals.allow(key, time.Now()); ok {
			payload := map[string]any{"route": r.Pattern, "reason": err.Error()}
			if suppressed > 0 {
				payload["suppressed"] = suppressed
			}
			if err := s.appendAudit(r.Context(), storage.AuditEvent{
				Kind: "ui_proxy.delegate", Actor: proxy, Decision: "deny",
				Payload: mustJSON(payload),
			}); err != nil {
				metrics.UIProxyRefusalsSuppressed.Inc()
				s.refusals.unrecorded(key, suppressed+1, !errors.Is(err, storage.ErrNotLeader))
			}
		} else {
			metrics.UIProxyRefusalsSuppressed.Inc()
			slog.Debug("ui proxy refusal suppressed", "caller", proxy, "route", r.Pattern, "reason", err.Error())
		}
		writeErr(w, status, err)
		return ""
	}
	if !slices.Contains(s.uiProxy.Proxies, proxy) {
		return refuse(http.StatusForbidden, "not-proxy", fmt.Errorf("caller is not a --ui-proxy and may not present %s", UserTokenHeader))
	}
	if !delegable {
		return refuse(http.StatusForbidden, "route", fmt.Errorf("this endpoint does not accept %s", UserTokenHeader))
	}
	values := r.Header.Values(UserTokenHeader)
	if len(values) != 1 || values[0] == "" {
		return refuse(http.StatusUnauthorized, "header", fmt.Errorf("%s must hold exactly one token", UserTokenHeader))
	}
	user, err := s.verifyUserToken(values[0])
	if err != nil {
		kind := "token"
		var te *userTokenError
		if errors.As(err, &te) {
			kind = "token-" + te.kind
		}
		return refuse(http.StatusUnauthorized, kind, fmt.Errorf("%s: %w", UserTokenHeader, err))
	}
	return user
}

// userTokenError names which check a user token failed, so each kind of
// failure gets its own refusal window.
type userTokenError struct {
	kind string
	err  error
}

func (e *userTokenError) Error() string { return e.err.Error() }
func (e *userTokenError) Unwrap() error { return e.err }

func tokenErr(kind string, err error) error { return &userTokenError{kind: kind, err: err} }

// verifyUserToken checks a user token and returns its subject. It must
// be a JWT-SVID this server issued through POST /v1/oidc/exchange (its
// act claim names the OIDC IdP that signed the person in, and nothing
// else), for exactly the --ui-proxy-audience, unexpired with no clock
// leeway, with a lifetime of at most --ui-proxy-max-token-ttl, and not
// sender constrained, since the proxy presents it as a bearer.
func (s *Server) verifyUserToken(token string) (string, error) {
	// Parsed once on its own so an unparsable token and a bad signature
	// are different kinds of refusal.
	if _, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256}); err != nil {
		return "", tokenErr("malformed", fmt.Errorf("parse jwt: %w", err))
	}
	id, claims, err := s.ca.ParseJWTSVIDClaims(token)
	if err != nil {
		if errors.Is(err, jwt.ErrExpired) {
			return "", tokenErr("expired", err)
		}
		return "", tokenErr("unverified", err)
	}
	if aud := audienceValues(claims["aud"]); len(aud) != 1 || aud[0] != s.uiProxy.Audience {
		return "", tokenErr("audience", fmt.Errorf("aud must be exactly %q", s.uiProxy.Audience))
	}
	exp, okExp := claimExpiry(claims)
	iat, okIat := claimNumericDate(claims, "iat")
	if !okExp || !okIat {
		return "", tokenErr("times", errors.New("token must carry iat and exp"))
	}
	if !time.Now().Before(exp) {
		return "", tokenErr("expired", errors.New("token has expired"))
	}
	if life := exp.Sub(iat); life > s.uiProxy.MaxTokenTTL {
		return "", tokenErr("lifetime", fmt.Errorf("token lifetime %s exceeds the accepted maximum %s", life, s.uiProxy.MaxTokenTTL))
	}
	if _, ok := claims["cnf"]; ok {
		return "", tokenErr("cnf", errors.New("token must not be sender-constrained (cnf)"))
	}
	act, ok := claims["act"].(map[string]any)
	if !ok || act["kind"] != "oidc-idp" {
		return "", tokenErr("act", errors.New("token was not issued for a person signed in through an OIDC IdP"))
	}
	if _, nested := act["act"]; nested {
		return "", tokenErr("act-chain", errors.New("token carries a delegation chain"))
	}
	return id.String(), nil
}

// refusalAuditWindow is how often one caller's refused user tokens of
// one kind reach the audit chain, so a caller looping bad requests
// cannot grow the chain at will.
const refusalAuditWindow = time.Minute

// refusalMaxCallers bounds the (caller, kind) pairs refusalLimiter tracks. Past it a
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
	max     int
	pruned  time.Time
	warned  time.Time
}

func newRefusalLimiter(window time.Duration) *refusalLimiter {
	return &refusalLimiter{window: window, callers: map[string]*refusalState{}, max: refusalMaxCallers}
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
	} else if len(l.callers) >= l.max {
		// At most one sweep a window, so a full table does not cost every
		// new caller a scan. A swept entry's count is already in the
		// metric.
		if now.Sub(l.pruned) >= l.window {
			l.pruned = now
			for k, v := range l.callers {
				if !now.Before(v.until) {
					delete(l.callers, k)
				}
			}
		}
		if len(l.callers) >= l.max {
			if now.Sub(l.warned) >= l.window {
				l.warned = now
				slog.Warn("ui proxy refusal limiter is full; auditing every refusal from new callers", "tracked", len(l.callers))
			}
			return true, 0
		}
	}
	l.callers[caller] = &refusalState{until: now.Add(l.window)}
	return true, suppressed
}

// unrecorded keeps n refusals for the next row when the audit row could
// not be written. retry reopens the window so the next refusal tries
// again; without it the window stays, so a follower, whose writes always
// fail, tries once a window rather than on every refusal.
func (l *refusalLimiter) unrecorded(caller string, n int, retry bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.callers[caller]; ok {
		st.suppressed += n
		if retry {
			st.until = time.Time{}
		}
	}
}
