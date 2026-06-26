package audit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"

	"github.com/kanywst/omega/internal/server/audit"
	"github.com/kanywst/omega/internal/server/storage"
)

// startOTLPSink returns an httptest.Server that decodes
// ExportLogsServiceRequest bodies POSTed to /v1/logs and pushes them
// into the returned channel. Anything else returns 404 so an
// accidental path mismatch fails loudly in tests.
func startOTLPSink(t *testing.T) (*httptest.Server, <-chan *collogspb.ExportLogsServiceRequest) {
	t.Helper()
	recv := make(chan *collogspb.ExportLogsServiceRequest, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/logs" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-protobuf" {
			http.Error(w, "bad content-type "+got, http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req := &collogspb.ExportLogsServiceRequest{}
		if err := proto.Unmarshal(body, req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		recv <- req
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, recv
}

func TestOTLPForwarderRequiresEndpoint(t *testing.T) {
	if _, err := audit.NewOTLPForwarder(audit.OTLPConfig{}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

// The endpoint flag must honour a user-supplied path component
// (OTLP/HTTP §3.2 — signal-specific endpoints are used as-is) so a
// non-standard receiver path keeps working. Verified by spying on
// the request URL via httptest.Server.URL + Request.URL.Path.
func TestOTLPForwarderPreservesUserSuppliedPath(t *testing.T) {
	cases := []struct {
		name        string
		endpointFmt string // %s = sink.URL
		wantPath    string
	}{
		{"no path appends /v1/logs", "%s", "/v1/logs"},
		{"trailing slash trimmed then appends", "%s/", "/v1/logs"},
		{"explicit /v1/logs preserved", "%s/v1/logs", "/v1/logs"},
		{"custom path preserved as-is", "%s/teams/sec/logs", "/teams/sec/logs"},
		{"custom path trailing slash trimmed", "%s/teams/sec/logs/", "/teams/sec/logs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan string, 1)
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got <- r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(sink.Close)
			ep := fmt.Sprintf(tc.endpointFmt, sink.URL)
			fwd, err := audit.NewOTLPForwarder(audit.OTLPConfig{Endpoint: ep, Insecure: true})
			if err != nil {
				t.Fatalf("new (%s): %v", ep, err)
			}
			if err := fwd.Forward(context.Background(), []storage.AuditEvent{{Seq: 1, Ts: time.Now()}}); err != nil {
				t.Fatalf("forward: %v", err)
			}
			if p := <-got; p != tc.wantPath {
				t.Errorf("request path: got %q want %q", p, tc.wantPath)
			}
		})
	}
}

func TestOTLPForwarderForwardsAuditEvents(t *testing.T) {
	sink, recv := startOTLPSink(t)
	fwd, err := audit.NewOTLPForwarder(audit.OTLPConfig{
		Endpoint:    sink.URL, // already has http:// scheme
		Insecure:    true,
		ServiceName: "omega-server-test",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if fwd.Name() != "otlp" {
		t.Errorf("Name(): got %q want otlp", fwd.Name())
	}
	now := time.Unix(1700000000, 0).UTC()
	events := []storage.AuditEvent{
		{Seq: 1, Ts: now, Kind: "domain.create", Subject: "example", Decision: "ok", Hash: "h1", PrevHash: "GENESIS", Payload: json.RawMessage(`{"k":"v"}`)},
		{Seq: 2, Ts: now.Add(time.Second), Kind: "access.evaluate", Subject: "spiffe://omega.local/x", Decision: "deny", Hash: "h2", PrevHash: "h1"},
	}
	if err := fwd.Forward(context.Background(), events); err != nil {
		t.Fatalf("forward: %v", err)
	}
	select {
	case req := <-recv:
		if len(req.ResourceLogs) != 1 {
			t.Fatalf("ResourceLogs: got %d want 1", len(req.ResourceLogs))
		}
		rl := req.ResourceLogs[0]
		if got := attrString(rl.Resource.Attributes, "service.name"); got != "omega-server-test" {
			t.Errorf("service.name: got %q", got)
		}
		if len(rl.ScopeLogs) != 1 {
			t.Fatalf("ScopeLogs: got %d want 1", len(rl.ScopeLogs))
		}
		records := rl.ScopeLogs[0].LogRecords
		if len(records) != 2 {
			t.Fatalf("records: got %d want 2", len(records))
		}
		if got := attrString(records[0].Attributes, "omega.audit.kind"); got != "domain.create" {
			t.Errorf("record[0].kind: got %q", got)
		}
		if got := attrInt(records[0].Attributes, "omega.audit.seq"); got != 1 {
			t.Errorf("record[0].seq: got %d", got)
		}
		if got := attrString(records[1].Attributes, "omega.audit.decision"); got != "deny" {
			t.Errorf("record[1].decision: got %q", got)
		}
		if got := attrString(records[1].Attributes, "omega.audit.prev_hash"); got != "h1" {
			t.Errorf("record[1].prev_hash: got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OTLP sink never received the export request")
	}
}

func TestOTLPForwarderReturnsErrorOnSinkFailure(t *testing.T) {
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(sink.Close)
	fwd, err := audit.NewOTLPForwarder(audit.OTLPConfig{Endpoint: sink.URL, Insecure: true})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	err = fwd.Forward(context.Background(), []storage.AuditEvent{{Seq: 1, Ts: time.Now()}})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got: %v", err)
	}
}

func TestOTLPForwarderAddsHeaders(t *testing.T) {
	got := make(chan string, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sink.Close)
	fwd, err := audit.NewOTLPForwarder(audit.OTLPConfig{
		Endpoint: sink.URL,
		Insecure: true,
		Headers:  map[string]string{"X-Custom": "abc123"},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := fwd.Forward(context.Background(), []storage.AuditEvent{{Seq: 1, Ts: time.Now()}}); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if v := <-got; v != "abc123" {
		t.Errorf("X-Custom: got %q want abc123", v)
	}
}

func attrString(attrs []*commonpb.KeyValue, key string) string {
	for _, kv := range attrs {
		if kv.Key == key {
			if s, ok := kv.Value.Value.(*commonpb.AnyValue_StringValue); ok {
				return s.StringValue
			}
		}
	}
	return ""
}

func attrInt(attrs []*commonpb.KeyValue, key string) int64 {
	for _, kv := range attrs {
		if kv.Key == key {
			if iv, ok := kv.Value.Value.(*commonpb.AnyValue_IntValue); ok {
				return iv.IntValue
			}
		}
	}
	return 0
}
