package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kanywst/omega/internal/server/metrics"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// maxDecisionBatch caps one POST /v1/audit/decisions body.
const maxDecisionBatch = 1000

// getPolicyBundle serves the policy set and directory a local evaluator
// needs. The revision is the ETag, so an unchanged bundle costs a 304.
func (s *Server) getPolicyBundle(w http.ResponseWriter, r *http.Request) {
	b, err := s.policy.Bundle()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	etag := `"` + b.Revision + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if inm := r.Header.Get("If-None-Match"); inm != "" && strings.Contains(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// LocalDecision is one decision a local evaluator made.
type LocalDecision struct {
	ID        string              `json:"id"`
	DecidedAt time.Time           `json:"decided_at"`
	Request   policy.EvalRequest  `json:"request"`
	Response  policy.EvalResponse `json:"response"`
}

// DecisionBatch is the body of POST /v1/audit/decisions.
type DecisionBatch struct {
	BundleRevision string          `json:"bundle_revision"`
	Decisions      []LocalDecision `json:"decisions"`
}

// recordDecisions appends decisions made by a local evaluator to the
// audit chain, attributed to the calling agent. A failed append answers
// 500 so the agent keeps the batch and retries; the decision id lets a
// reader spot a row written twice by such a retry.
func (s *Server) recordDecisions(w http.ResponseWriter, r *http.Request) {
	var batch DecisionBatch
	if !decodeJSONBody(w, r, &batch) {
		return
	}
	if len(batch.Decisions) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("decisions is empty"))
		return
	}
	if len(batch.Decisions) > maxDecisionBatch {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("at most %d decisions per batch", maxDecisionBatch))
		return
	}
	for i, d := range batch.Decisions {
		if d.ID == "" || d.DecidedAt.IsZero() {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("decision %d needs id and decided_at", i))
			return
		}
		if err := policy.Validate(d.Request); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("decision %d: %w", i, err))
			return
		}
	}
	agent := CallerSPIFFEID(r.Context())
	for i, d := range batch.Decisions {
		decision := "deny"
		if d.Response.Decision {
			decision = "allow"
		}
		payload, err := json.Marshal(map[string]any{
			"request":         d.Request,
			"response":        d.Response,
			"source":          "local",
			"decision_id":     d.ID,
			"decided_at":      d.DecidedAt.UTC(),
			"bundle_revision": batch.BundleRevision,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if err := s.appendAudit(r.Context(), storage.AuditEvent{
			Kind:     "access.evaluate",
			Actor:    agent,
			Subject:  d.Request.Subject.ID,
			Decision: decision,
			Payload:  payload,
		}); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("recorded %d of %d decisions: %w", i, len(batch.Decisions), err))
			return
		}
		metrics.Decisions.WithLabelValues(decision).Inc()
	}
	writeJSON(w, http.StatusOK, map[string]int{"recorded": len(batch.Decisions)})
}
