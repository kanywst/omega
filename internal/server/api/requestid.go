package api

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/kanywst/omega/internal/server/policy"
)

type requestIDKey struct{}

// withRequestID implements AuthZEN 1.0 §10.1.3 for an /access/v1 route.
// It is the outermost wrapper, so the identifier is echoed unchanged on
// every response to the request, including a 503 from the leader gate
// or a 401 from caller authentication. The id is also put on the
// request context, for the audit row, and on the otelhttp server span,
// so a PEP-side id and the trace id can be joined. What is stored is
// policy.RequestIDForAudit's form: the id itself when it is short and
// plain, otherwise its SHA-256.
func withRequestID(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if id := policy.RequestIDFrom(r.Header); id != "" {
			w.Header().Set(policy.RequestIDHeader, id)
			span := trace.SpanFromContext(r.Context())
			if plain, digest := policy.RequestIDForAudit(id); plain != "" {
				span.SetAttributes(attribute.String("authzen.request_id", plain))
			} else {
				span.SetAttributes(attribute.String("authzen.request_id_sha256", digest))
			}
			r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		}
		h(w, r)
	}
}

// withRequestIDPayload adds the request id to an audit payload when the
// caller sent one, so the row can be found from the PEP's own logs.
func withRequestIDPayload(ctx context.Context, payload map[string]any) map[string]any {
	id, _ := ctx.Value(requestIDKey{}).(string)
	plain, digest := policy.RequestIDForAudit(id)
	if plain != "" {
		payload["request_id"] = plain
	}
	if digest != "" {
		payload["request_id_sha256"] = digest
	}
	return payload
}
