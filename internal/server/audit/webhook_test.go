package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kanywst/omega/internal/server/storage"
)

func TestNewWebhookForwarderRequiresURL(t *testing.T) {
	if _, err := NewWebhookForwarder(WebhookConfig{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
	if _, err := NewWebhookForwarder(WebhookConfig{URL: "   "}); err == nil {
		t.Fatal("expected error for whitespace URL")
	}
}

func TestWebhookForwardSendsBatchAndHeaders(t *testing.T) {
	var (
		gotBody []byte
		gotSig  string
		gotCt   string
		gotN    string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCt = r.Header.Get("Content-Type")
		gotSig = r.Header.Get(SignatureHeader)
		gotN = r.Header.Get(EventCountHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	const secret = "shh"
	fwd, err := NewWebhookForwarder(WebhookConfig{URL: srv.URL, Secret: secret})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}

	events := []storage.AuditEvent{
		{Seq: 1, Kind: "decision", Subject: "spiffe://td/sa", Decision: "permit", Hash: "h1"},
		{Seq: 2, Kind: "decision", Subject: "spiffe://td/sa", Decision: "deny", Hash: "h2"},
	}
	if err := fwd.Forward(context.Background(), events); err != nil {
		t.Fatalf("forward: %v", err)
	}

	if gotCt != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotCt)
	}
	if gotN != "2" {
		t.Errorf("event count header = %q, want 2", gotN)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Errorf("signature = %q, want %q", gotSig, want)
	}

	var parsed struct {
		Events []storage.AuditEvent `json:"events"`
	}
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("body unmarshal: %v", err)
	}
	if len(parsed.Events) != 2 || parsed.Events[0].Seq != 1 || parsed.Events[1].Seq != 2 {
		t.Errorf("body events = %+v", parsed.Events)
	}
}

func TestWebhookForwardSkipsSignatureWhenNoSecret(t *testing.T) {
	var sawSig bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(SignatureHeader) != "" {
			sawSig = true
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fwd, err := NewWebhookForwarder(WebhookConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("ctor: %v", err)
	}
	if err := fwd.Forward(context.Background(), []storage.AuditEvent{{Seq: 1, Kind: "k"}}); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if sawSig {
		t.Error("signature header set despite empty secret")
	}
}

func TestWebhookForwardEmptyBatchIsNoop(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()

	fwd, _ := NewWebhookForwarder(WebhookConfig{URL: srv.URL})
	if err := fwd.Forward(context.Background(), nil); err != nil {
		t.Fatalf("forward nil: %v", err)
	}
	if err := fwd.Forward(context.Background(), []storage.AuditEvent{}); err != nil {
		t.Fatalf("forward empty: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("server hit %d times, want 0", got)
	}
}

func TestWebhookForwardNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	fwd, _ := NewWebhookForwarder(WebhookConfig{URL: srv.URL})
	err := fwd.Forward(context.Background(), []storage.AuditEvent{{Seq: 1, Kind: "k"}})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error missing status/body: %v", err)
	}
}

func TestWebhookForwardTransportError(t *testing.T) {
	// URL that will fail DNS / connect immediately.
	fwd, _ := NewWebhookForwarder(WebhookConfig{URL: "http://127.0.0.1:1"})
	err := fwd.Forward(context.Background(), []storage.AuditEvent{{Seq: 1, Kind: "k"}})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestWebhookNameStable(t *testing.T) {
	fwd, _ := NewWebhookForwarder(WebhookConfig{URL: "http://example.invalid"})
	if fwd.Name() != "webhook" {
		t.Errorf("Name() = %q, want webhook", fwd.Name())
	}
}
