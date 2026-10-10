package api_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

func TestPolicyBundleEndpoint(t *testing.T) {
	env := newDomainEnv(t, `permit (principal, action, resource);`)
	root := env.as(t, rootAdmin)

	code, body := call(t, root, "GET", env.srv.URL+"/v1/policy/bundle", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"revision"`) || !strings.Contains(string(body), "p.cedar") {
		t.Fatalf("bundle: %d %s", code, body)
	}
	req, _ := http.NewRequest("GET", env.srv.URL+"/v1/policy/bundle", nil)
	resp, err := root.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	resp.Body.Close()
	req.Header.Set("If-None-Match", etag)
	resp, err = root.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("unchanged bundle: %d", resp.StatusCode)
	}
}

func TestRecordDecisionsValidation(t *testing.T) {
	env := newDomainEnv(t, "", "spiffe://omega.local/nodes/")
	agent := env.as(t, "spiffe://omega.local/nodes/n1")
	u := env.srv.URL + "/v1/audit/decisions"
	ok := api.LocalDecision{
		ID:        "d1",
		DecidedAt: time.Now(),
		Request:   policy.EvalRequest{Subject: policy.Entity{Type: "User", ID: "u"}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}},
		Response:  policy.EvalResponse{Decision: true},
	}
	tooMany := make([]api.LocalDecision, 1001)
	for i := range tooMany {
		tooMany[i] = ok
	}
	cases := []struct {
		name string
		body api.DecisionBatch
		want int
	}{
		{"empty", api.DecisionBatch{}, http.StatusBadRequest},
		{"too many", api.DecisionBatch{Decisions: tooMany}, http.StatusBadRequest},
		{"missing id", api.DecisionBatch{Decisions: []api.LocalDecision{{DecidedAt: time.Now(), Request: ok.Request}}}, http.StatusBadRequest},
		{"malformed request", api.DecisionBatch{Decisions: []api.LocalDecision{{ID: "x", DecidedAt: time.Now()}}}, http.StatusBadRequest},
		{"valid", api.DecisionBatch{BundleRevision: "r1", Decisions: []api.LocalDecision{ok}}, http.StatusOK},
	}
	for _, tc := range cases {
		if code, body := call(t, agent, "POST", u, tc.body); code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, code, body, tc.want)
		}
	}
	events, _ := env.store.ListAudit(t.Context(), 0, 10)
	var found bool
	for _, ev := range events {
		if ev.Kind == "access.evaluate.local" && ev.Actor == "spiffe://omega.local/nodes/n1" && strings.Contains(string(ev.Payload), `"bundle_revision":"r1"`) {
			found = true
		}
	}
	if !found {
		t.Error("the decision is recorded with the agent as actor")
	}
}

func TestRecordDecisionsNeedsAListedRecorder(t *testing.T) {
	env := newDomainEnv(t, "", "spiffe://omega.local/nodes/", "spiffe://omega.local/edge/gw")
	batch := api.DecisionBatch{Decisions: []api.LocalDecision{{
		ID: "d1", DecidedAt: time.Now(),
		Request: policy.EvalRequest{Subject: policy.Entity{Type: "User", ID: "u"}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}},
	}}}
	for id, want := range map[string]int{
		"spiffe://omega.local/nodes/n2":  http.StatusOK,
		"spiffe://omega.local/edge/gw":   http.StatusOK,
		"spiffe://omega.local/edge/gw2":  http.StatusForbidden,
		"spiffe://omega.local/nodes":     http.StatusForbidden,
		"spiffe://omega.local/media/web": http.StatusForbidden,
	} {
		if code, body := call(t, env.as(t, id), "POST", env.srv.URL+"/v1/audit/decisions", batch); code != want {
			t.Errorf("%s: %d %s, want %d", id, code, body, want)
		}
	}
	events, _ := env.store.ListAudit(t.Context(), 0, 50)
	var denied int
	for _, ev := range events {
		if ev.Kind == "access.evaluate.local" && ev.Decision == "deny" && ev.Subject == "" {
			denied++
		}
	}
	if denied != 3 {
		t.Errorf("refused recorders are audited: %d", denied)
	}
}

func TestRecordDecisionsRefusedWithoutRequireAuth(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca, policy.New()).WithDecisionRecorders([]string{"spiffe://omega.local/nodes/"}).Handler())
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+"/v1/audit/decisions", "application/json", strings.NewReader(`{"decisions":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("without --require-auth: %d", resp.StatusCode)
	}
}
