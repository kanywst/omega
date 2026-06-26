package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// newExchangePolicyServer wires up a test server with token-exchange
// policy enforcement turned on and the supplied Cedar source loaded.
// Returns the server, the policy engine (so individual cases can hot-
// reload policy variants), and the store (for audit inspection).
func newExchangePolicyServer(t *testing.T, cedarSrc string) (*httptest.Server, *policy.Engine, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	pdp := policy.New()
	if cedarSrc != "" {
		policyDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(policyDir, "p.cedar"), []byte(cedarSrc), 0o644); err != nil {
			t.Fatalf("write policy: %v", err)
		}
		if err := pdp.LoadDir(policyDir); err != nil {
			t.Fatalf("load policy: %v", err)
		}
	}
	srv := httptest.NewServer(
		api.NewServer(store, ca, pdp).WithEnforceTokenExchangePolicy(true).Handler(),
	)
	t.Cleanup(srv.Close)
	return srv, pdp, store
}

func TestTokenExchangePolicyAllow(t *testing.T) {
	cedar := `permit (
  principal is Spiffe,
  action == Action::"token.exchange",
  resource is Spiffe
) when {
  principal has kind &&
  principal.kind == "ai" &&
  context.delegation_depth <= 2
};
`
	srv, _, _ := newExchangePolicyServer(t, cedar)

	human := "spiffe://omega.local/humans/u-alice"
	agent := "spiffe://omega.local/agents/claude/inst-1"
	tool := "spiffe://omega.local/svc/github/issues"

	subjectTok := issueJWT(t, srv.URL, human, []string{"omega-internal"})
	actorTok := issueJWT(t, srv.URL, agent, []string{"omega-internal"})

	resp, raw := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      subjectTok,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        actorTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: agent,
		Audience:          []string{tool},
		TTLSeconds:        60,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", resp.StatusCode, raw)
	}

	// Audit row records policy=allow with the matched policy id.
	auditOut := readAudit(t, srv.URL)
	var found bool
	for _, ev := range auditOut.Items {
		if ev.Kind != "token.exchange" {
			continue
		}
		found = true
		if ev.Decision != "allow" {
			t.Errorf("audit decision: got %q want allow", ev.Decision)
		}
		var p struct {
			Policy  string   `json:"policy"`
			Reasons []string `json:"reasons"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if p.Policy != "allow" {
			t.Errorf("audit policy field: %q", p.Policy)
		}
		if len(p.Reasons) == 0 {
			t.Errorf("audit reasons empty (want at least one matched permit policy id)")
		}
	}
	if !found {
		t.Fatalf("no token.exchange audit row")
	}
}

func TestTokenExchangePolicyDenyByDefault(t *testing.T) {
	// Empty policy set + enforce=true → Cedar default-deny.
	srv, _, _ := newExchangePolicyServer(t, "")

	human := "spiffe://omega.local/humans/u-alice"
	agent := "spiffe://omega.local/agents/claude/inst-1"
	tool := "spiffe://omega.local/svc/github/issues"

	subjectTok := issueJWT(t, srv.URL, human, []string{"omega-internal"})
	actorTok := issueJWT(t, srv.URL, agent, []string{"omega-internal"})

	resp, _ := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      subjectTok,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        actorTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: agent,
		Audience:          []string{tool},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d want 403", resp.StatusCode)
	}

	// Deny is also audited so SIEM gets the failed-attempt trail.
	auditOut := readAudit(t, srv.URL)
	var found bool
	for _, ev := range auditOut.Items {
		if ev.Kind == "token.exchange" && ev.Decision == "deny" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an audit row with kind=token.exchange decision=deny")
	}
}

func TestTokenExchangePolicyDepthLimit(t *testing.T) {
	// Only allow chains up to a single hop. The 3-hop case must deny.
	cedar := `permit (
  principal is Spiffe,
  action == Action::"token.exchange",
  resource is Spiffe
) when {
  context.delegation_depth <= 1
};
`
	srv, _, _ := newExchangePolicyServer(t, cedar)

	human := "spiffe://omega.local/humans/u-alice"
	coord := "spiffe://omega.local/agents/coordinator/inst-1"
	sub := "spiffe://omega.local/agents/researcher/inst-1"
	tool := "spiffe://omega.local/svc/notion/pages"

	humanTok := issueJWT(t, srv.URL, human, []string{"omega-internal"})
	coordTok := issueJWT(t, srv.URL, coord, []string{"omega-internal"})
	subTok := issueJWT(t, srv.URL, sub, []string{"omega-internal"})

	// Hop 1: depth 1 - must allow.
	resp1, raw1 := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      humanTok,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        coordTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: coord,
		Audience:          []string{"omega-internal"},
		TTLSeconds:        60,
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("hop1: %d %s", resp1.StatusCode, raw1)
	}
	var hop1 api.TokenExchangeResponse
	_ = json.Unmarshal(raw1, &hop1)

	// Hop 2: depth 2 - must deny.
	resp2, raw2 := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      hop1.AccessToken,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        subTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: sub,
		Audience:          []string{tool},
		TTLSeconds:        60,
	})
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("hop2: got %d want 403, body=%s", resp2.StatusCode, raw2)
	}
}

func TestTokenExchangePolicyServiceKindClassification(t *testing.T) {
	// Only humans are allowed to delegate to agents under this policy.
	// A `/svc/...` actor (kind=service) impersonating itself must deny.
	cedar := `permit (
  principal is Spiffe,
  action == Action::"token.exchange",
  resource is Spiffe
) when {
  principal has kind && principal.kind == "ai"
};
`
	srv, _, _ := newExchangePolicyServer(t, cedar)

	src := "spiffe://omega.local/svc/web/inst-1"
	subjectTok := issueJWT(t, srv.URL, src, []string{"omega-internal"})
	actorTok := issueJWT(t, srv.URL, src, []string{"omega-internal"})

	resp, _ := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      subjectTok,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        actorTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: src,
		Audience:          []string{"omega-internal"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("service-kind exchange should be denied: got %d", resp.StatusCode)
	}
}

type auditList struct {
	Items []struct {
		Kind     string          `json:"kind"`
		Actor    string          `json:"actor"`
		Subject  string          `json:"subject"`
		Decision string          `json:"decision"`
		Payload  json.RawMessage `json:"payload"`
	} `json:"items"`
}

func readAudit(t *testing.T, srvURL string) auditList {
	t.Helper()
	resp, err := http.Get(srvURL + "/v1/audit?since=0")
	if err != nil {
		t.Fatalf("audit get: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out auditList
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("audit decode: %v body=%s", err, raw)
	}
	return out
}
