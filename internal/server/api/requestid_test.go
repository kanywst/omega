package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

const reqIDPolicy = `@id("web-get")
permit (
  principal == Spiffe::"spiffe://omega.local/alice",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);

@id("no-delete")
forbid (principal, action == Action::"DELETE", resource);
`

func newReqIDServer(t *testing.T) (*httptest.Server, *storage.Store) {
	t.Helper()
	pdp := policy.New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(reqIDPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pdp.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	return newTestServerWithStore(t, pdp)
}

// accessCalls is one valid request per /access/v1 endpoint.
var accessCalls = []struct{ path, body string }{
	{"/access/v1/evaluation", `{"subject":{"type":"Spiffe","id":"spiffe://omega.local/alice"},"action":{"name":"GET"},"resource":{"type":"HttpPath","id":"/api/foo"}}`},
	{"/access/v1/evaluations", `{"subject":{"type":"Spiffe","id":"spiffe://omega.local/alice"},"action":{"name":"GET"},"evaluations":[{"resource":{"type":"HttpPath","id":"/api/foo"}},{"resource":{"type":"HttpPath","id":"/api/bar"}}]}`},
	{"/access/v1/search/subject", `{"subjects":[{"type":"Spiffe","id":"spiffe://omega.local/alice"}],"action":{"name":"GET"},"resource":{"type":"HttpPath","id":"/api/foo"}}`},
	{"/access/v1/search/resource", `{"resources":[{"type":"HttpPath","id":"/api/foo"}],"subject":{"type":"Spiffe","id":"spiffe://omega.local/alice"},"action":{"name":"GET"}}`},
	{"/access/v1/search/action", `{"actions":[{"name":"GET"}],"subject":{"type":"Spiffe","id":"spiffe://omega.local/alice"},"resource":{"type":"HttpPath","id":"/api/foo"}}`},
}

func postWithRequestID(t *testing.T, url, body string, ids ...string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for _, id := range ids {
		req.Header.Add(policy.RequestIDHeader, id)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// AuthZEN 1.0 §10.1.3: a PDP given a request identifier MUST return
// the same identifier, and every /access/v1 endpoint is an
// Authorization API request.
func TestAccessEndpointsEchoTheRequestID(t *testing.T) {
	srv, store := newReqIDServer(t)
	for _, c := range accessCalls {
		id := "req" + strings.ReplaceAll(c.path, "/", "-")
		resp, raw := postWithRequestID(t, srv.URL+c.path, c.body, id)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", c.path, resp.StatusCode, raw)
		}
		if got := resp.Header.Get(policy.RequestIDHeader); got != id {
			t.Errorf("%s: echoed %q, want %q", c.path, got, id)
		}

		// No header in, no header out.
		resp, raw = postWithRequestID(t, srv.URL+c.path, c.body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s without id: %d %s", c.path, resp.StatusCode, raw)
		}
		if got := resp.Header.Values(policy.RequestIDHeader); len(got) != 0 {
			t.Errorf("%s without id: echoed %q", c.path, got)
		}
	}

	// Every decision row carries the id of the request that caused it:
	// one per batch entry and one per search candidate.
	events, err := store.ListAudit(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"req-access-v1-evaluation":      1,
		"req-access-v1-evaluations":     2,
		"req-access-v1-search-subject":  1,
		"req-access-v1-search-resource": 1,
		"req-access-v1-search-action":   1,
	}
	got := map[string]int{}
	without := 0
	for _, ev := range events {
		if ev.Kind != "access.evaluate" {
			continue
		}
		var p struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if p.RequestID == "" {
			without++
			continue
		}
		got[p.RequestID]++
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("audit rows with request_id %q: %d, want %d", id, got[id], n)
		}
	}
	if without != 6 {
		t.Errorf("audit rows without a request_id: %d, want 6 (the calls that sent none)", without)
	}
}

// §10.1.3 calls the id an arbitrary string, so any value is echoed
// unchanged and decided on. One omega will not store verbatim (too
// long, or with characters unsafe in logs) is recorded as its SHA-256.
func TestAccessEndpointsEchoAnyRequestIDAndHashUnsafeOnes(t *testing.T) {
	srv, store := newReqIDServer(t)
	cases := []struct {
		sent []string
		echo string
	}{
		{[]string{strings.Repeat("a", policy.MaxRequestIDBytes+1)}, strings.Repeat("a", policy.MaxRequestIDBytes+1)},
		{[]string{"has space"}, "has space"},
		{[]string{`with"quote`}, `with"quote`},
		{[]string{"one", "two"}, "one, two"},
	}
	for _, c := range accessCalls {
		for _, tc := range cases {
			resp, raw := postWithRequestID(t, srv.URL+c.path, c.body, tc.sent...)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s %q: %d %s, want 200", c.path, tc.sent, resp.StatusCode, raw)
			}
			if got := resp.Header.Values(policy.RequestIDHeader); len(got) != 1 || got[0] != tc.echo {
				t.Errorf("%s %q: echoed %q, want %q", c.path, tc.sent, got, tc.echo)
			}
		}
	}
	events, err := store.ListAudit(t.Context(), 0, 200)
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]bool{}
	for _, tc := range cases {
		_, d := policy.RequestIDForAudit(tc.echo)
		digests[d] = true
	}
	for _, ev := range events {
		var p map[string]any
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if _, ok := p["request_id"]; ok {
			t.Errorf("an unsafe id was stored verbatim: %s", ev.Payload)
		}
		d, _ := p["request_id_sha256"].(string)
		if !digests[d] {
			t.Errorf("audit row without the id's digest: %s", ev.Payload)
		}
	}
	if len(events) != 4*6 {
		t.Errorf("audit rows: %d, want %d (6 decisions per round of endpoints)", len(events), 4*6)
	}
}

// The id is echoed on a response the PDP gives before deciding, too.
func TestRequestIDIsEchoedOnAFollower503(t *testing.T) {
	srv, store := newTestServerWithStore(t, policy.New())
	store.SetLeaderForTest(true, false)
	resp, _ := postWithRequestID(t, srv.URL+accessCalls[0].path, accessCalls[0].body, "follower-1")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get(policy.RequestIDHeader); got != "follower-1" {
		t.Errorf("echoed %q on the 503", got)
	}
}

func TestEvaluationResponsesCarryDecisionContext(t *testing.T) {
	srv, _ := newReqIDServer(t)

	// §6.2: the single evaluation response is a Decision with context.
	_, raw := postWithRequestID(t, srv.URL+"/access/v1/evaluation", accessCalls[0].body)
	var single map[string]json.RawMessage
	if err := json.Unmarshal(raw, &single); err != nil {
		t.Fatal(err)
	}
	if string(single["decision"]) != "true" || string(single["context"]) != `{"reasons":["web-get"]}` || string(single["reasons"]) != `["web-get"]` {
		t.Errorf("single evaluation: %s", raw)
	}

	// §7.2: each entry of a batch is a Decision with its own context; a
	// default deny has none.
	_, raw = postWithRequestID(t, srv.URL+"/access/v1/evaluations", `{
  "subject": {"type":"Spiffe","id":"spiffe://omega.local/alice"},
  "evaluations": [
    {"action":{"name":"GET"},"resource":{"type":"HttpPath","id":"/api/foo"}},
    {"action":{"name":"DELETE"},"resource":{"type":"HttpPath","id":"/api/foo"}},
    {"action":{"name":"GET"},"resource":{"type":"HttpPath","id":"/api/bar"}}
  ]
}`)
	var batch api.BatchEvalResponse
	if err := json.Unmarshal(raw, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Evaluations) != 3 {
		t.Fatalf("batch: %s", raw)
	}
	if c := batch.Evaluations[0].Context; c == nil || len(c.Reasons) != 1 || c.Reasons[0] != "web-get" {
		t.Errorf("batch[0] context: %+v", c)
	}
	if c := batch.Evaluations[1].Context; c == nil || len(c.Reasons) != 1 || c.Reasons[0] != "no-delete" {
		t.Errorf("batch[1] context: %+v", c)
	}
	if c := batch.Evaluations[2].Context; c != nil {
		t.Errorf("batch[2] default deny context: %+v, want none", c)
	}
}

// The id lands on the otelhttp server span, so a PEP that logs its own
// id can find the trace, and the trace's evaluation spans, from it.
func TestRequestIDIsOnTheServerSpan(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	srv, _ := newReqIDServer(t)
	resp, raw := postWithRequestID(t, srv.URL+accessCalls[0].path, accessCalls[0].body, "traced-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, raw)
	}
	var server, eval sdktrace.ReadOnlySpan
	for _, sp := range rec.Ended() {
		switch sp.Name() {
		case "POST /access/v1/evaluation":
			server = sp
		case "policy.Evaluate":
			eval = sp
		}
	}
	if server == nil || eval == nil {
		t.Fatalf("spans: server %v, evaluate %v", server != nil, eval != nil)
	}
	var tagged bool
	for _, kv := range server.Attributes() {
		if kv.Key == "authzen.request_id" && kv.Value.AsString() == "traced-1" {
			tagged = true
		}
	}
	if !tagged {
		t.Errorf("server span attributes %v lack authzen.request_id", server.Attributes())
	}
	if eval.SpanContext().TraceID() != server.SpanContext().TraceID() {
		t.Error("the evaluation span is not in the request's trace")
	}
}

// A PEP learns which policies Cedar skipped, but not Cedar's error
// text, which can name what the policy reads; the audit row keeps it.
func TestEvaluationErrorsReachThePEPAsPolicyIDsOnly(t *testing.T) {
	pdp := policy.New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(`@id("all") permit (principal, action, resource);
@id("needs-clearance") forbid (principal, action, resource) when { principal.clearance < 3 };
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pdp.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	srv, store := newTestServerWithStore(t, pdp)

	_, raw := postWithRequestID(t, srv.URL+"/access/v1/evaluation", accessCalls[0].body, "err-1")
	var single map[string]json.RawMessage
	if err := json.Unmarshal(raw, &single); err != nil {
		t.Fatal(err)
	}
	// The erroring forbid denies rather than being skipped; pinned
	// here at the HTTP layer as well as in the policy package.
	if string(single["decision"]) != "false" {
		t.Errorf("decision with an erroring forbid: %s", single["decision"])
	}
	if string(single["context"]) != `{"reasons":["needs-clearance"],"errors":[{"policy":"needs-clearance"}]}` {
		t.Errorf("single evaluation context: %s", single["context"])
	}
	_, raw = postWithRequestID(t, srv.URL+"/access/v1/evaluations", accessCalls[1].body)
	if !strings.Contains(string(raw), `"errors":[{"policy":"needs-clearance"}]`) || strings.Contains(string(raw), "message") {
		t.Errorf("batch response: %s", raw)
	}

	events, err := store.ListAudit(t.Context(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		RequestID string              `json:"request_id"`
		Response  policy.EvalResponse `json:"response"`
	}
	if err := json.Unmarshal(events[0].Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.RequestID != "err-1" || p.Response.Context == nil || len(p.Response.Context.Errors) != 1 || p.Response.Context.Errors[0].Message == "" {
		t.Errorf("audit row keeps the error message: %s", events[0].Payload)
	}
}
