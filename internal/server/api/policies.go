package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kanywst/omega/internal/server/metrics"
	"github.com/kanywst/omega/internal/server/storage"
)

// MaxPolicyBytes caps the Cedar text of one stored policy.
const MaxPolicyBytes = 64 << 10

// Policy sources reported by the policy API.
const (
	PolicySourceAPI  = "api"
	PolicySourceFile = "file"
)

// ErrStoredPolicySet is returned by RefreshDirectory when the stored
// policies do not load. The engine keeps the last set that loaded.
var ErrStoredPolicySet = errors.New("stored policy set does not load")

var (
	errPreconditionFailed = errors.New("If-Match does not match the policy's current ETag; read it again and retry")
	errPolicyExists       = errors.New("policy already exists; update it with PUT and If-Match")
)

// PolicyView is one policy as the policy API shows it: a stored policy
// (source "api"), or a --policy-dir file (source "file", read-only),
// whose id is its file name.
type PolicyView struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	Text      string    `json:"text,omitempty"`
	Digest    string    `json:"digest"`
	Version   int64     `json:"version,omitempty"`
	ETag      string    `json:"etag,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// PolicyRequest is the body of POST /v1/policies, PUT /v1/policies/{id}
// (which takes the id from the path) and POST /v1/policies/validate.
type PolicyRequest struct {
	ID   string `json:"id,omitempty"`
	Text string `json:"text"`
}

// PolicyValidation is the 200 answer of POST /v1/policies/validate:
// the Cedar policy ids the text would define once stored.
type PolicyValidation struct {
	Valid     bool     `json:"valid"`
	PolicyIDs []string `json:"policy_ids"`
}

func storedView(p storage.Policy, withText bool) PolicyView {
	v := PolicyView{
		ID: p.ID, Source: PolicySourceAPI, Digest: p.Digest, Version: p.Version, ETag: p.ETag(),
		CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt, UpdatedBy: p.UpdatedBy, UpdatedAt: p.UpdatedAt,
	}
	if withText {
		v.Text = p.Text
	}
	return v
}

func fileView(name, text string, withText bool) PolicyView {
	v := PolicyView{ID: name, Source: PolicySourceFile, Digest: storage.PolicyDigest(text)}
	if withText {
		v.Text = text
	}
	return v
}

// loadStoredPolicies loads the stored policies into the engine. A set
// that does not load leaves the last one in force.
func (s *Server) loadStoredPolicies(ctx context.Context) error {
	items, err := s.store.ListPolicies(ctx)
	if err != nil {
		return err
	}
	recorded, err := s.store.PolicyAuditDigests(ctx)
	if err != nil {
		return err
	}
	set := make(map[string]string, len(items))
	for _, p := range items {
		set[p.ID] = p.Text
	}
	if err := matchAuditChain(items, recorded); err != nil {
		metrics.StoredPolicySetLoadFailures.Inc()
		slog.Error("stored policies differ from the audit chain; keeping the last set that loaded", "err", err)
		return fmt.Errorf("%w: %v", ErrStoredPolicySet, err)
	}
	if err := s.policy.SetStoredPolicies(set); err != nil {
		metrics.StoredPolicySetLoadFailures.Inc()
		slog.Error("stored policy set does not load; keeping the last set that loaded", "err", err)
		return fmt.Errorf("%w: %v", ErrStoredPolicySet, err)
	}
	metrics.StoredPolicies.Set(float64(len(set)))
	return nil
}

// matchAuditChain checks the stored policies against what the audit
// chain says the API last wrote, so a policy edited, added or removed in
// the database behind the API is not enforced.
func matchAuditChain(items []storage.Policy, recorded map[string]string) error {
	stored := make(map[string]bool, len(items))
	for _, p := range items {
		stored[p.ID] = true
		if want := recorded[p.ID]; want != p.Digest {
			return fmt.Errorf("policy %q has digest %s, but the audit chain last recorded %q", p.ID, p.Digest, want)
		}
	}
	for id, digest := range recorded {
		if digest != "" && !stored[id] {
			return fmt.Errorf("policy %q is in the audit chain but not in the database", id)
		}
	}
	return nil
}

// authorizePolicyWrite writes 403 and returns false unless the caller
// may change stored policies: only a --domain-root-admin may, and only
// under --require-auth. A Cedar policy is not confined to a domain, so
// a domain admin's grant does not extend to it. A refusal is audited.
func (s *Server) authorizePolicyWrite(w http.ResponseWriter, r *http.Request, kind, id string) bool {
	caller := CallerSPIFFEID(r.Context())
	var reason string
	switch {
	case !s.requireAuth:
		reason = "managing policies over the API needs --require-auth"
	case caller == "" || !slices.Contains(s.domains.rootAdmins, caller):
		reason = "caller is not a --domain-root-admin"
	default:
		return true
	}
	s.audit(r.Context(), storage.AuditEvent{
		Kind: kind, Actor: caller, Subject: id, Decision: "deny",
		Payload: mustJSON(map[string]string{"reason": reason}),
	})
	writeErr(w, http.StatusForbidden, errors.New(reason))
	return false
}

// readOnlyFile writes 409 and returns true when id names a
// --policy-dir file, which the API never changes.
func (s *Server) readOnlyFile(w http.ResponseWriter, id string) bool {
	if _, ok := s.policy.FilePolicies()[id]; !ok {
		return false
	}
	writeErr(w, http.StatusConflict, fmt.Errorf("policy %q is a --policy-dir file and is read-only over the API", id))
	return true
}

// checkPolicyRequest validates a stored policy's id and text, writing
// 400 on a problem, and returns the Cedar policy ids it defines.
func (s *Server) checkPolicyRequest(w http.ResponseWriter, id, text string) ([]string, bool) {
	if err := storage.ValidatePolicyID(id); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return nil, false
	}
	if len(text) > MaxPolicyBytes {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("policy text is %d bytes (max %d)", len(text), MaxPolicyBytes))
		return nil, false
	}
	ids, err := s.policy.CheckStored(id, text)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return nil, false
	}
	return ids, true
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	stored, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	files := s.policy.FilePolicies()
	items := make([]PolicyView, 0, len(files)+len(stored))
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		items = append(items, fileView(name, files[name], false))
	}
	for _, p := range stored {
		items = append(items, storedView(p, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if text, ok := s.policy.FilePolicies()[id]; ok {
		writeJSON(w, http.StatusOK, fileView(id, text, true))
		return
	}
	if err := storage.ValidatePolicyID(id); err != nil {
		writeErr(w, http.StatusNotFound, fmt.Errorf("policy %q not found", id))
		return
	}
	p, err := s.store.GetPolicy(r.Context(), id)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("policy %q not found", id))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		w.Header().Set("ETag", p.ETag())
		writeJSON(w, http.StatusOK, storedView(p, true))
	}
}

func (s *Server) validatePolicy(w http.ResponseWriter, r *http.Request) {
	var req PolicyRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.ID == "" {
		req.ID = "draft"
	}
	ids, ok := s.checkPolicyRequest(w, req.ID, req.Text)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, PolicyValidation{Valid: true, PolicyIDs: ids})
}

// policyEvent is the audit row of a stored policy change. It carries the
// digests rather than the text, which the policy API serves.
func policyEvent(r *http.Request, kind, id string, cur *storage.Policy, text string, version int64, cedarIDs []string) storage.AuditEvent {
	payload := map[string]any{"id": id, "old_digest": "", "new_digest": "", "version": version}
	if cur != nil {
		payload["old_digest"] = cur.Digest
	}
	if kind != "policy.delete" {
		payload["new_digest"] = storage.PolicyDigest(text)
		payload["cedar_ids"] = cedarIDs
	}
	return storage.AuditEvent{Kind: kind, Actor: CallerSPIFFEID(r.Context()), Subject: id, Decision: "ok", Payload: mustJSON(payload)}
}

// changePolicy commits a stored policy change with its audit row and
// reloads the engine. It answers the error and returns false on failure.
func (s *Server) changePolicy(w http.ResponseWriter, r *http.Request, id string, change storage.PolicyChange) (*storage.Policy, bool) {
	if s.auditFault != nil {
		inner := change
		change = func(cur *storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
			next, ev, err := inner(cur)
			if err == nil {
				err = s.auditFault(ev)
			}
			return next, ev, err
		}
	}
	p, ev, err := s.store.ChangePolicy(r.Context(), id, change)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("policy %q not found", id))
		return nil, false
	case errors.Is(err, storage.ErrAlreadyExists):
		writeErr(w, http.StatusConflict, errPolicyExists)
		return nil, false
	case errors.Is(err, errPreconditionFailed):
		writeErr(w, http.StatusPreconditionFailed, err)
		return nil, false
	case errors.Is(err, storage.ErrNotLeader):
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusServiceUnavailable, err)
		return nil, false
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
		return nil, false
	}
	metrics.AuditAppended.WithLabelValues(ev.Kind).Inc()
	s.refreshAfterWrite(r.Context())
	return p, true
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req PolicyRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if s.readOnlyFile(w, req.ID) {
		return
	}
	if err := storage.ValidatePolicyID(req.ID); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorizePolicyWrite(w, r, "policy.create", req.ID) {
		return
	}
	ids, ok := s.checkPolicyRequest(w, req.ID, req.Text)
	if !ok {
		return
	}
	p, ok := s.changePolicy(w, r, req.ID, func(cur *storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
		if cur != nil {
			return nil, storage.AuditEvent{}, storage.ErrAlreadyExists
		}
		return &storage.Policy{Text: req.Text, UpdatedBy: CallerSPIFFEID(r.Context())}, policyEvent(r, "policy.create", req.ID, nil, req.Text, 1, ids), nil
	})
	if !ok {
		return
	}
	w.Header().Set("ETag", p.ETag())
	w.Header().Set("Location", "/v1/policies/"+p.ID)
	writeJSON(w, http.StatusCreated, storedView(*p, true))
}

// ifMatch reports whether the If-Match header value matches etag. "*"
// matches any existing policy; weak tags never match.
func ifMatch(header, etag string) bool {
	for _, tag := range strings.Split(header, ",") {
		if tag = strings.TrimSpace(tag); tag == "*" || tag == etag {
			return true
		}
	}
	return false
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.readOnlyFile(w, id) {
		return
	}
	var req PolicyRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.ID != "" && req.ID != id {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("body id %q does not match the path id %q", req.ID, id))
		return
	}
	if err := storage.ValidatePolicyID(id); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorizePolicyWrite(w, r, "policy.update", id) {
		return
	}
	match := r.Header.Get("If-Match")
	if match == "" {
		writeErr(w, http.StatusPreconditionRequired, errors.New("updating a policy needs If-Match with its current ETag (or *)"))
		return
	}
	ids, ok := s.checkPolicyRequest(w, id, req.Text)
	if !ok {
		return
	}
	p, ok := s.changePolicy(w, r, id, func(cur *storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
		if cur == nil {
			return nil, storage.AuditEvent{}, storage.ErrNotFound
		}
		if !ifMatch(match, cur.ETag()) {
			return nil, storage.AuditEvent{}, errPreconditionFailed
		}
		return &storage.Policy{Text: req.Text, UpdatedBy: CallerSPIFFEID(r.Context())}, policyEvent(r, "policy.update", id, cur, req.Text, cur.Version+1, ids), nil
	})
	if !ok {
		return
	}
	w.Header().Set("ETag", p.ETag())
	writeJSON(w, http.StatusOK, storedView(*p, true))
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.readOnlyFile(w, id) {
		return
	}
	if err := storage.ValidatePolicyID(id); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if !s.authorizePolicyWrite(w, r, "policy.delete", id) {
		return
	}
	match := r.Header.Get("If-Match")
	if match == "" {
		writeErr(w, http.StatusPreconditionRequired, errors.New("deleting a policy needs If-Match with its current ETag (or *)"))
		return
	}
	if _, ok := s.changePolicy(w, r, id, func(cur *storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
		if cur == nil {
			return nil, storage.AuditEvent{}, storage.ErrNotFound
		}
		if !ifMatch(match, cur.ETag()) {
			return nil, storage.AuditEvent{}, errPreconditionFailed
		}
		return nil, policyEvent(r, "policy.delete", id, cur, "", cur.Version, nil), nil
	}); !ok {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
