package api_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/storage"
)

const (
	uiProxy    = "spiffe://omega.local/platform/ui"
	humanAdmin = "spiffe://omega.local/humans/corp/alice"
	humanUser  = "spiffe://omega.local/humans/corp/carol"
)

// oidcAct is the act claim POST /v1/oidc/exchange puts on a person's
// JWT-SVID.
var oidcAct = map[string]any{"sub": "alice@example.com", "iss": "https://idp.example.com", "idp": "corp", "kind": "oidc-idp"}

func newUIProxyEnv(t *testing.T) *domainEnv {
	t.Helper()
	return newDomainEnvWith(t, "", func(s *api.Server) {
		s.WithDomainRootAdmins([]string{rootAdmin, humanAdmin}).
			WithUIProxies(api.UIProxyConfig{Proxies: []string{uiProxy}})
	})
}

// userToken mints a JWT-SVID for id the way the server signs one.
func userToken(t *testing.T, env *domainEnv, id string, aud []string, ttl time.Duration, extra map[string]any) string {
	t.Helper()
	svid, err := env.ca.IssueJWTSVID(spiffeid.RequireFromString(id), aud, ttl, extra)
	if err != nil {
		t.Fatal(err)
	}
	return svid.Token
}

func personToken(t *testing.T, env *domainEnv, id string) string {
	t.Helper()
	return userToken(t, env, id, []string{api.DefaultUIProxyAudience}, 10*time.Minute, map[string]any{"act": oidcAct})
}

// lastAudit returns the last audit row of kind and its payload.
func lastAudit(t *testing.T, env *domainEnv, kind string) (storage.AuditEvent, map[string]any) {
	t.Helper()
	events, err := env.store.ListAudit(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Kind == kind {
			var p map[string]any
			if err := json.Unmarshal(events[i].Payload, &p); err != nil {
				t.Fatal(err)
			}
			return events[i], p
		}
	}
	t.Fatalf("no %s audit row", kind)
	return storage.AuditEvent{}, nil
}

func TestUIProxyActsForThePerson(t *testing.T) {
	env := newUIProxyEnv(t)
	proxy := env.as(t, uiProxy)
	base := env.srv.URL + "/v1/policies"
	as := map[string]string{api.UserTokenHeader: personToken(t, env, humanAdmin)}

	// The proxy on its own is an ordinary authenticated caller.
	if code, _, body := callH(t, proxy, "POST", base, api.PolicyRequest{ID: "alice-read", Text: alicePermit}, nil); code != http.StatusForbidden {
		t.Fatalf("proxy alone: %d %s", code, body)
	}
	if code, _, _ := callH(t, proxy, "GET", base+"/alice-read", nil, nil); code != http.StatusForbidden {
		t.Fatalf("proxy alone reads no policy text: %d", code)
	}

	code, h, body := callH(t, proxy, "POST", base, api.PolicyRequest{ID: "alice-read", Text: alicePermit}, as)
	if code != http.StatusCreated {
		t.Fatalf("create as the person: %d %s", code, body)
	}
	var created api.PolicyView
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.CreatedBy != humanAdmin {
		t.Fatalf("created_by = %q, want the person", created.CreatedBy)
	}
	ev, p := lastAudit(t, env, "policy.create")
	if ev.Actor != humanAdmin || p["via"] != uiProxy {
		t.Fatalf("create audit: actor %q via %v", ev.Actor, p["via"])
	}

	if code, _, body := callH(t, proxy, "GET", base+"/alice-read", nil, as); code != http.StatusOK {
		t.Fatalf("read as the person: %d %s", code, body)
	}
	if code, _, body := callH(t, proxy, "PUT", base+"/alice-read", api.PolicyRequest{Text: alicePermit2}, map[string]string{api.UserTokenHeader: as[api.UserTokenHeader], "If-Match": `"1-stale"`}); code != http.StatusPreconditionFailed {
		t.Fatalf("stale update: %d %s", code, body)
	}
	if code, _, body := callH(t, proxy, "DELETE", base+"/alice-read", nil, map[string]string{api.UserTokenHeader: as[api.UserTokenHeader], "If-Match": h.Get("ETag")}); code != http.StatusNoContent {
		t.Fatalf("delete as the person: %d %s", code, body)
	}
	ev, p = lastAudit(t, env, "policy.delete")
	if ev.Actor != humanAdmin || p["via"] != uiProxy {
		t.Fatalf("delete audit: actor %q via %v", ev.Actor, p["via"])
	}

	// A direct caller's rows carry no via.
	if code, _ := call(t, env.as(t, rootAdmin), "POST", base, api.PolicyRequest{ID: "direct", Text: alicePermit}); code != http.StatusCreated {
		t.Fatalf("direct create: %d", code)
	}
	if _, p := lastAudit(t, env, "policy.create"); p["via"] != nil {
		t.Fatalf("direct create recorded via %v", p["via"])
	}
}

func TestUIProxyPersonWhoIsNotAnAdmin(t *testing.T) {
	env := newUIProxyEnv(t)
	as := map[string]string{api.UserTokenHeader: personToken(t, env, humanUser)}
	code, _, body := callH(t, env.as(t, uiProxy), "POST", env.srv.URL+"/v1/policies", api.PolicyRequest{ID: "carol", Text: alicePermit}, as)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin person: %d %s", code, body)
	}
	ev, p := lastAudit(t, env, "policy.create")
	if ev.Decision != "deny" || ev.Actor != humanUser || p["via"] != uiProxy {
		t.Fatalf("refusal audit: %+v %v", ev, p)
	}
}

func TestUIProxyRefusesUserTokens(t *testing.T) {
	env := newUIProxyEnv(t)
	proxy := env.as(t, uiProxy)
	base := env.srv.URL + "/v1/policies"
	good := personToken(t, env, humanAdmin)
	nested := map[string]any{"sub": "x", "kind": "oidc-idp", "act": map[string]any{"sub": "y"}}

	cases := []struct {
		name   string
		client *http.Client
		method string
		url    string
		token  string
		want   int
	}{
		{"caller is not a proxy", env.as(t, bob), "GET", base, good, http.StatusForbidden},
		{"root admin is not a proxy either", env.as(t, rootAdmin), "GET", base, good, http.StatusForbidden},
		{"route does not accept a user token", proxy, "GET", env.srv.URL + "/v1/audit", good, http.StatusForbidden},
		{"empty token", proxy, "GET", base, "", http.StatusUnauthorized},
		{"not a JWT", proxy, "GET", base, "not-a-jwt", http.StatusUnauthorized},
		{"wrong audience", proxy, "GET", base, userToken(t, env, humanAdmin, []string{"target-api"}, 10*time.Minute, map[string]any{"act": oidcAct}), http.StatusUnauthorized},
		{"extra audience", proxy, "GET", base, userToken(t, env, humanAdmin, []string{api.DefaultUIProxyAudience, "x"}, 10*time.Minute, map[string]any{"act": oidcAct}), http.StatusUnauthorized},
		{"workload JWT-SVID", proxy, "GET", base, userToken(t, env, humanAdmin, []string{api.DefaultUIProxyAudience}, 10*time.Minute, nil), http.StatusUnauthorized},
		{"delegation chain", proxy, "GET", base, userToken(t, env, humanAdmin, []string{api.DefaultUIProxyAudience}, 10*time.Minute, map[string]any{"act": nested}), http.StatusUnauthorized},
		{"sender constrained", proxy, "GET", base, userToken(t, env, humanAdmin, []string{api.DefaultUIProxyAudience}, 10*time.Minute, map[string]any{"act": oidcAct, "cnf": map[string]any{"jkt": "x"}}), http.StatusUnauthorized},
		{"lifetime too long", proxy, "GET", base, userToken(t, env, humanAdmin, []string{api.DefaultUIProxyAudience}, 2*time.Hour, map[string]any{"act": oidcAct}), http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, body := callH(t, tc.client, tc.method, tc.url, nil, map[string]string{api.UserTokenHeader: tc.token})
			if code != tc.want {
				t.Fatalf("got %d %s, want %d", code, body, tc.want)
			}
			if ev, _ := lastAudit(t, env, "ui_proxy.delegate"); ev.Decision != "deny" {
				t.Fatalf("refusal not audited: %+v", ev)
			}
		})
	}

	// Two tokens are refused rather than one picked.
	req, _ := http.NewRequest("GET", base, nil)
	req.Header.Add(api.UserTokenHeader, good)
	req.Header.Add(api.UserTokenHeader, good)
	resp, err := proxy.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("two tokens: %d", resp.StatusCode)
	}

	// A write through a non-delegable gated route is refused too.
	if code, _, body := callH(t, proxy, "POST", env.srv.URL+"/v1/domains", map[string]string{"name": "media"}, map[string]string{api.UserTokenHeader: good}); code != http.StatusForbidden {
		t.Fatalf("domain create with a user token: %d %s", code, body)
	}
}

// Other JWT-SVIDs get 30s of leeway past exp; a user token gets none.
func TestUIProxyRefusesAnExpiredUserToken(t *testing.T) {
	env := newUIProxyEnv(t)
	tok := userToken(t, env, humanAdmin, []string{api.DefaultUIProxyAudience}, time.Second, map[string]any{"act": oidcAct})
	time.Sleep(2 * time.Second)
	if code, _, body := callH(t, env.as(t, uiProxy), "GET", env.srv.URL+"/v1/policies", nil, map[string]string{api.UserTokenHeader: tok}); code != http.StatusUnauthorized {
		t.Fatalf("expired user token: %d %s", code, body)
	}
}

func TestUIProxyHonoursConfiguredLimits(t *testing.T) {
	env := newDomainEnvWith(t, "", func(s *api.Server) {
		s.WithDomainRootAdmins([]string{humanAdmin}).
			WithUIProxies(api.UIProxyConfig{Proxies: []string{uiProxy}, Audience: "console", MaxTokenTTL: 3 * time.Hour})
	})
	tok := userToken(t, env, humanAdmin, []string{"console"}, 2*time.Hour, map[string]any{"act": oidcAct})
	if code, _, body := callH(t, env.as(t, uiProxy), "GET", env.srv.URL+"/v1/policies/x", nil, map[string]string{api.UserTokenHeader: tok}); code != http.StatusNotFound {
		t.Fatalf("configured audience and lifetime: %d %s", code, body)
	}
}

func TestUserTokenWithoutUIProxies(t *testing.T) {
	env := newDomainEnv(t, "")
	tok := userToken(t, env, humanAdmin, []string{api.DefaultUIProxyAudience}, 10*time.Minute, map[string]any{"act": oidcAct})
	if code, _, _ := callH(t, env.as(t, uiProxy), "GET", env.srv.URL+"/v1/policies", nil, map[string]string{api.UserTokenHeader: tok}); code != http.StatusForbidden {
		t.Fatalf("no --ui-proxy configured: %d", code)
	}
}

func TestUIProxyRefusalAuditWindow(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	type use = struct {
		Caller string
		At     time.Time
	}
	audited, suppressed := api.RefusalAllowForTest(time.Minute, []use{
		{"a", t0},
		{"a", t0.Add(10 * time.Second)},
		{"b", t0.Add(20 * time.Second)},
		{"a", t0.Add(30 * time.Second)},
		{"a", t0.Add(time.Minute)},
		{"a", t0.Add(2 * time.Minute)},
	})
	wantAudited := []bool{true, false, true, false, true, true}
	wantSuppressed := []int{0, 0, 0, 0, 2, 0}
	if !slices.Equal(audited, wantAudited) || !slices.Equal(suppressed, wantSuppressed) {
		t.Fatalf("audited %v suppressed %v, want %v %v", audited, suppressed, wantAudited, wantSuppressed)
	}
}

func TestUIProxyRefusalOfANewKindGetsItsOwnRow(t *testing.T) {
	env := newUIProxyEnv(t)
	proxy := env.as(t, uiProxy)
	wrongAud := userToken(t, env, humanAdmin, []string{"target-api"}, 10*time.Minute, map[string]any{"act": oidcAct})
	for _, tok := range []string{"", "not-a-jwt", "still-not-a-jwt", wrongAud} {
		if code, _, _ := callH(t, proxy, "GET", env.srv.URL+"/v1/policies", nil, map[string]string{api.UserTokenHeader: tok}); code != http.StatusUnauthorized {
			t.Fatalf("token %q: %d", tok, code)
		}
	}
	events, err := env.store.ListAudit(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, ev := range events {
		if ev.Kind == "ui_proxy.delegate" && ev.Actor == uiProxy {
			rows++
		}
	}
	if rows != 3 {
		t.Fatalf("got %d rows for an empty header, two unparsable tokens and a wrong audience, want 3", rows)
	}
}

// A full limiter audits rather than suppresses, so it never hides a
// refusal it cannot track.
func TestUIProxyRefusalLimiterFull(t *testing.T) {
	if first, second := api.RefusalFullForTest(3); !first || !second {
		t.Fatalf("new caller on a full limiter: audited %v %v, want true true", first, second)
	}
}

func TestUIProxyRefusalKeptWhenItsRowIsNotWritten(t *testing.T) {
	if ok, suppressed := api.RefusalUnrecordedForTest(); !ok || suppressed != 2 {
		t.Fatalf("next window after a failed write: audited %v suppressed %d, want true 2", ok, suppressed)
	}
}

func TestUIProxyRefusalsAreAuditedOncePerWindow(t *testing.T) {
	env := newUIProxyEnv(t)
	tok := personToken(t, env, humanAdmin)
	for range 3 {
		if code, _, _ := callH(t, env.as(t, bob), "GET", env.srv.URL+"/v1/policies", nil, map[string]string{api.UserTokenHeader: tok}); code != http.StatusForbidden {
			t.Fatalf("non-proxy caller: %d", code)
		}
	}
	events, err := env.store.ListAudit(t.Context(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, ev := range events {
		if ev.Kind == "ui_proxy.delegate" && ev.Actor == bob {
			rows++
		}
	}
	if rows != 1 {
		t.Fatalf("got %d ui_proxy.delegate rows for three refusals, want 1", rows)
	}
}
