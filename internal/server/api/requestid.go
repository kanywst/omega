package api

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/kanywst/omega/internal/server/policy"
)

type requestIDKey struct{}

// withRequestID implements AuthZEN 1.0 §10.1.3 for an /access/v1 route.
// It is the outermost wrapper, so the identifier is echoed on every
// response to the request, including a 503 from the leader gate or a
// 401 from caller authentication. The id is also put on the request
// context, for the audit row, and on the otelhttp server span, so a
// PEP-side id and the trace id can be joined.
//
// An id omega will not accept (see policy.RequestIDFrom) is a 400
// without an echo: repeating a value refused because it is not safe to
// store or log would hand it back unchecked, and the request is not
// evaluated, so there is no decision for the id to identify.
func withRequestID(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := policy.RequestIDFrom(r.Header)
		if !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid %s header: send one value of 1 to %d bytes of letters, digits and -._~:/+=@;",
				policy.RequestIDHeader, policy.MaxRequestIDBytes))
			return
		}
		if id != "" {
			w.Header().Set(policy.RequestIDHeader, id)
			trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("authzen.request_id", id))
			r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		}
		h(w, r)
	}
}

// requestIDOf returns the AuthZEN request id withRequestID accepted for
// this request, or "" when the caller sent none.
func requestIDOf(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// withRequestIDPayload adds the request id to an audit payload when the
// caller sent one, so the row can be found from the PEP's own logs.
func withRequestIDPayload(ctx context.Context, payload map[string]any) map[string]any {
	if id := requestIDOf(ctx); id != "" {
		payload["request_id"] = id
	}
	return payload
}
