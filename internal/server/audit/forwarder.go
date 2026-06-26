// Package audit ships audit_log entries to external sinks (SIEMs,
// log pipelines, custom HTTP collectors). It runs as a side-process to
// the API server: the API still writes the canonical chain to the
// store synchronously, and Pump asynchronously pulls fresh rows out
// and hands them to one or more Forwarders.
//
// Delivery semantics: at-least-once. Each forwarder owns a watermark
// row in the audit_forward_state table; the watermark only advances
// after the sink has acknowledged the batch. A crash between forward
// and watermark write redelivers the same events on the next start - 
// receivers should de-duplicate on AuditEvent.Hash, which is stable
// across redeliveries.
//
// Webhook is the only forwarder shipped today. OTLP-Logs export is a
// planned follow-up; the Forwarder interface is shaped so it can slot
// in without changing the Pump or the storage surface.
package audit

import (
	"context"

	"github.com/kanywst/omega/internal/server/storage"
)

// Forwarder ships a batch of audit events to one external destination.
// Implementations must treat the batch atomically: either every event
// in events is acknowledged by the sink (return nil) or none are
// considered delivered (return non-nil so Pump retries the same batch
// on the next tick).
type Forwarder interface {
	Name() string
	Forward(ctx context.Context, events []storage.AuditEvent) error
}
