package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/0-draft/omega/internal/server/storage"
)

// OTLPConfig configures the OTLP/HTTP-protobuf log forwarder. Endpoint
// is the OTLP receiver's base URL or `host:port` pair (the standard
// receiver port is 4318); `/v1/logs` is appended automatically per
// OTLP/HTTP §3.2. Insecure switches the default scheme from `https`
// to `http` when Endpoint is not already prefixed.
type OTLPConfig struct {
	Endpoint    string
	Insecure    bool
	Headers     map[string]string
	Timeout     time.Duration
	ServiceName string // used for the OTLP Resource attribute; defaults to "omega-server"
}

// OTLPForwarder implements Forwarder by POSTing one
// ExportLogsServiceRequest per batch to the configured collector
// endpoint. Each AuditEvent becomes one LogRecord; the hash chain
// fields ride as `omega.audit.{hash,prev_hash,seq}` attributes so a
// downstream pipeline (Splunk, Loki, Elastic, cloud logging) can
// dedupe on hash and detect chain breaks.
//
// Delivery is synchronous per batch: 2xx advances the Pump
// watermark, any non-2xx or transport error fails the batch and Pump
// retries the same range on the next tick. This matches the
// WebhookForwarder contract.
type OTLPForwarder struct {
	cfg      OTLPConfig
	endpoint string
	client   *http.Client
	resource *resourcepb.Resource
}

// NewOTLPForwarder validates cfg and builds the forwarder. Returns
// an error when Endpoint is empty so misconfiguration surfaces at
// startup rather than silently dropping audit events.
func NewOTLPForwarder(cfg OTLPConfig) (*OTLPForwarder, error) {
	ep := strings.TrimSpace(cfg.Endpoint)
	if ep == "" {
		return nil, errors.New("otlp: endpoint is required")
	}
	if !strings.HasPrefix(ep, "http://") && !strings.HasPrefix(ep, "https://") {
		scheme := "https"
		if cfg.Insecure {
			scheme = "http"
		}
		ep = scheme + "://" + ep
	}
	ep = strings.TrimRight(ep, "/") + "/v1/logs"
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "omega-server"
	}
	host, _ := os.Hostname()
	resAttrs := []*commonpb.KeyValue{
		strAttr("service.name", cfg.ServiceName),
	}
	if host != "" {
		resAttrs = append(resAttrs, strAttr("host.name", host))
	}
	return &OTLPForwarder{
		cfg:      cfg,
		endpoint: ep,
		client:   &http.Client{Timeout: cfg.Timeout},
		resource: &resourcepb.Resource{Attributes: resAttrs},
	}, nil
}

// Name is the watermark key in audit_forward_state. Stable across
// restarts and independent of any webhook forwarder's watermark.
func (o *OTLPForwarder) Name() string { return "otlp" }

// Forward marshals events as one ExportLogsServiceRequest and POSTs
// it to the OTLP receiver. Returns nil only on a 2xx response.
func (o *OTLPForwarder) Forward(ctx context.Context, events []storage.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	records := make([]*logspb.LogRecord, 0, len(events))
	for _, ev := range events {
		records = append(records, eventToLogRecord(ev))
	}
	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{
			Resource: o.resource,
			ScopeLogs: []*logspb.ScopeLogs{{
				Scope:      &commonpb.InstrumentationScope{Name: "github.com/0-draft/omega/audit"},
				LogRecords: records,
			}},
		}},
	}
	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("otlp: marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("User-Agent", "omega-audit-otlp/1")
	for k, v := range o.cfg.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := o.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("otlp: post %s: %w", o.endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		preview, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("otlp: %s returned %d: %s", o.endpoint, resp.StatusCode, strings.TrimSpace(string(preview)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// eventToLogRecord maps one AuditEvent onto an OTLP LogRecord. The
// audit body is a short human-readable summary; the hash chain
// fields and the raw payload ride in attributes so a downstream
// pipeline does not need to parse the body to query them.
func eventToLogRecord(ev storage.AuditEvent) *logspb.LogRecord {
	sev := logspb.SeverityNumber_SEVERITY_NUMBER_INFO
	switch ev.Decision {
	case "deny":
		sev = logspb.SeverityNumber_SEVERITY_NUMBER_WARN
	case "error":
		sev = logspb.SeverityNumber_SEVERITY_NUMBER_ERROR
	}
	attrs := []*commonpb.KeyValue{
		intAttr("omega.audit.seq", ev.Seq),
		strAttr("omega.audit.kind", ev.Kind),
		strAttr("omega.audit.hash", ev.Hash),
		strAttr("omega.audit.prev_hash", ev.PrevHash),
	}
	if ev.Actor != "" {
		attrs = append(attrs, strAttr("omega.audit.actor", ev.Actor))
	}
	if ev.Subject != "" {
		attrs = append(attrs, strAttr("omega.audit.subject", ev.Subject))
	}
	if ev.Decision != "" {
		attrs = append(attrs, strAttr("omega.audit.decision", ev.Decision))
	}
	if len(ev.Payload) > 0 {
		attrs = append(attrs, strAttr("omega.audit.payload", string(ev.Payload)))
	}
	body := ev.Kind
	if ev.Decision != "" {
		body = ev.Kind + " " + ev.Decision
	}
	return &logspb.LogRecord{
		TimeUnixNano:         uint64(ev.Ts.UnixNano()), // #nosec G115 -- post-1970 timestamp fits uint64
		ObservedTimeUnixNano: uint64(time.Now().UnixNano()),
		SeverityNumber:       sev,
		SeverityText:         ev.Decision,
		Body:                 &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: body}},
		Attributes:           attrs,
	}
}

func strAttr(k, v string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
	}
}

func intAttr(k string, v int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   k,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: v}},
	}
}
