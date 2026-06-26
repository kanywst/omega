package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kanywst/omega/internal/server/storage"
)

// WebhookConfig configures an HTTP POST forwarder. URL is required;
// Secret enables an HMAC-SHA256 signature header so receivers can
// authenticate batches without TLS client certs. Timeout defaults to 10s.
type WebhookConfig struct {
	URL     string
	Secret  string
	Timeout time.Duration
}

// SignatureHeader is set on every webhook POST when Secret is non-empty.
// The value is "sha256=<hex>" computed over the raw JSON body, matching
// the convention used by GitHub webhooks and Splunk HEC HMAC validation.
const SignatureHeader = "X-Omega-Signature"

// EventCountHeader carries the number of events in the batch so
// receivers can short-circuit empty pings without parsing the body.
const EventCountHeader = "X-Omega-Event-Count"

// WebhookForwarder POSTs each batch as a JSON object of the form
// {"events":[<AuditEvent>...]} to a configured URL. The batch is
// atomic: a non-2xx response or transport error fails the whole send,
// which Pump treats as "no events delivered" and retries on the next
// tick with the same watermark.
type WebhookForwarder struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewWebhookForwarder validates cfg and constructs the forwarder.
// Returns an error when URL is empty so misconfiguration fails at
// startup rather than silently dropping events.
func NewWebhookForwarder(cfg WebhookConfig) (*WebhookForwarder, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, fmt.Errorf("webhook: URL is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &WebhookForwarder{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// Name is the watermark key used in audit_forward_state. Stable across
// restarts so we can resume from where the last process left off.
func (w *WebhookForwarder) Name() string { return "webhook" }

// Forward POSTs events as one JSON batch. Returns nil only when the
// receiver responded with a 2xx status; any other outcome (transport
// error, non-2xx, body read failure) returns an error so Pump retries
// the same range on the next tick.
func (w *WebhookForwarder) Forward(ctx context.Context, events []storage.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(struct {
		Events []storage.AuditEvent `json:"events"`
	}{Events: events})
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(EventCountHeader, fmt.Sprintf("%d", len(events)))
	if w.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Secret))
		mac.Write(body)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post %s: %w", w.cfg.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook: %s returned %d: %s", w.cfg.URL, resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	// Drain so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
