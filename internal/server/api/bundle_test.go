package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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
	env := newDomainEnv(t, `permit (principal, action, resource);`, "spiffe://omega.local/nodes/")
	if code, _ := call(t, env.as(t, rootAdmin), "GET", env.srv.URL+"/v1/policy/bundle", nil); code != http.StatusForbidden {
		t.Fatalf("a caller that is not a decision recorder must not read the bundle: %d", code)
	}
	root := env.as(t, "spiffe://omega.local/nodes/n1")

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
		RequestID: "req-1",
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
		{"unsafe request id", api.DecisionBatch{Decisions: []api.LocalDecision{{ID: "x", DecidedAt: time.Now(), RequestID: "a\"b", Request: ok.Request}}}, http.StatusBadRequest},
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
		if ev.Kind == "access.evaluate.local" && ev.Actor == "spiffe://omega.local/nodes/n1" && strings.Contains(string(ev.Payload), `"bundle_revision":"r1"`) && strings.Contains(string(ev.Payload), `"request_id":"req-1"`) {
			found = true
		}
	}
	if !found {
		t.Error("the decision is recorded with the agent as actor and the PEP's request id")
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

func TestRecordDecisionsReportsHowManyWereRecorded(t *testing.T) {
	env := newDomainEnv(t, "", "spiffe://omega.local/nodes/")
	env.api.FailAuditForTest("access.evaluate.local")
	batch := api.DecisionBatch{Decisions: []api.LocalDecision{{
		ID: "d1", DecidedAt: time.Now(),
		Request: policy.EvalRequest{Subject: policy.Entity{Type: "User", ID: "u"}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}},
	}}}
	code, body := call(t, env.as(t, "spiffe://omega.local/nodes/n1"), "POST", env.srv.URL+"/v1/audit/decisions", batch)
	if code != http.StatusInternalServerError || !strings.Contains(string(body), `"recorded":0`) {
		t.Fatalf("failed append: %d %s", code, body)
	}
}

func TestRecordDecisionsRecordsALoss(t *testing.T) {
	env := newDomainEnv(t, "", "spiffe://omega.local/nodes/")
	agent := env.as(t, "spiffe://omega.local/nodes/n1")
	if code, body := call(t, agent, "POST", env.srv.URL+"/v1/audit/decisions", api.DecisionBatch{BundleRevision: "r1", Dropped: 2, DroppedIDs: []string{"a", "b"}, DroppedDigests: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, LossID: "l1"}); code != http.StatusOK {
		t.Fatalf("loss report: %d %s", code, body)
	}
	for name, b := range map[string]api.DecisionBatch{
		"negative":            {Dropped: -1},
		"count without ids":   {Dropped: 1000000, LossID: "l"},
		"ids disagree":        {Dropped: 2, DroppedIDs: []string{"a"}, LossID: "l"},
		"long loss id":        {Dropped: 1, DroppedIDs: []string{"a"}, DroppedDigests: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, LossID: strings.Repeat("l", 129)},
		"no loss id":          {Dropped: 1, DroppedIDs: []string{"a"}, DroppedDigests: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		"digests disagree":    {Dropped: 1, DroppedIDs: []string{"a"}, LossID: "l"},
		"bad digest":          {Dropped: 1, DroppedIDs: []string{"a"}, DroppedDigests: []string{"zz"}, LossID: "l"},
		"empty id":            {Dropped: 1, DroppedIDs: []string{""}, DroppedDigests: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, LossID: "l"},
		"loss with decisions": {Dropped: 1, DroppedIDs: []string{"a"}, DroppedDigests: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, LossID: "l2", Decisions: []api.LocalDecision{{ID: "x"}}},
	} {
		if code, _ := call(t, agent, "POST", env.srv.URL+"/v1/audit/decisions", b); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	events, _ := env.store.ListAudit(t.Context(), 0, 20)
	var found bool
	for _, ev := range events {
		if ev.Kind == "access.evaluate.local.dropped" && ev.Actor == "spiffe://omega.local/nodes/n1" && strings.Contains(string(ev.Payload), `"dropped":2`) {
			found = true
		}
	}
	if !found {
		t.Error("the loss must be in the chain")
	}
	for _, ev := range events {
		if strings.Contains(string(ev.Payload), `"l2"`) {
			t.Error("a rejected batch must leave no loss row behind")
		}
	}
}

func TestPolicyBundleIsSignedWhenAKeyIsSet(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	env := newDomainEnv(t, `permit (principal, action, resource);`, "spiffe://omega.local/nodes/")
	env.api.WithBundleSigningKey(key)
	code, body := call(t, env.as(t, "spiffe://omega.local/nodes/n1"), "GET", env.srv.URL+"/v1/policy/bundle", nil)
	if code != http.StatusOK {
		t.Fatalf("bundle: %d %s", code, body)
	}
	var b policy.Bundle
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckRevision(b); err != nil {
		t.Fatalf("the signature must not change the revision: %v", err)
	}
	if err := policy.VerifyBundle(b, &key.PublicKey); err != nil {
		t.Fatalf("served bundle must verify: %v", err)
	}
}

func TestRecordDecisionsRecordsEachDecisionOnce(t *testing.T) {
	env := newDomainEnv(t, "", "spiffe://omega.local/nodes/")
	agent := env.as(t, "spiffe://omega.local/nodes/n1")
	other := env.as(t, "spiffe://omega.local/nodes/n2")
	batch := api.DecisionBatch{Decisions: []api.LocalDecision{{
		ID: "same-id", DecidedAt: time.Now(),
		Request: policy.EvalRequest{Subject: policy.Entity{Type: "User", ID: "u"}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}},
	}}}
	loss := api.DecisionBatch{Dropped: 1, DroppedIDs: []string{"x"}, DroppedDigests: []string{strings.Repeat("a", 64)}, LossID: "loss-1"}
	for range 3 {
		for _, c := range []*http.Client{agent, other} {
			for _, b := range []api.DecisionBatch{batch, loss} {
				if code, body := call(t, c, "POST", env.srv.URL+"/v1/audit/decisions", b); code != http.StatusOK {
					t.Fatalf("%d %s", code, body)
				}
			}
		}
	}
	events, _ := env.store.ListAudit(t.Context(), 0, 100)
	count := map[string]int{}
	for _, ev := range events {
		count[ev.Kind+" "+ev.Actor]++
	}
	for _, k := range []string{
		"access.evaluate.local spiffe://omega.local/nodes/n1", "access.evaluate.local spiffe://omega.local/nodes/n2",
		"access.evaluate.local.dropped spiffe://omega.local/nodes/n1", "access.evaluate.local.dropped spiffe://omega.local/nodes/n2",
	} {
		if count[k] != 1 {
			t.Errorf("%s: %d rows, want 1 (resends must not duplicate; ids are per agent)", k, count[k])
		}
	}
}
