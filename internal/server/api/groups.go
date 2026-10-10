package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/storage"
)

// MaxMembershipLifetime bounds a membership's expires_at. Longer-lived
// access is a membership without expiry, reviewed like any other.
const MaxMembershipLifetime = 366 * 24 * time.Hour

// GroupRequest is the body of POST /v1/domains/{name}/groups.
type GroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// GroupMemberRequest is the body of PUT .../groups/{group}/members.
type GroupMemberRequest struct {
	Principal string    `json:"principal"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// groupPath reads and validates {name} and {group}.
func groupPath(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	domain, ok := domainPathName(w, r)
	if !ok {
		return "", "", false
	}
	group := r.PathValue("group")
	if err := storage.ValidateGroupName(group); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return "", "", false
	}
	return domain, group, true
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	domain, ok := domainPathName(w, r)
	if !ok {
		return
	}
	var req GroupRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if err := storage.ValidateGroupName(req.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	id := domain + ":" + req.Name
	if !s.authorizeDomainWrite(w, r, "group.create", id, domain) {
		return
	}
	g, err := s.store.CreateGroup(r.Context(), storage.Group{Domain: domain, Name: req.Name, Description: req.Description})
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("domain %q does not exist", domain))
	case errors.Is(err, storage.ErrAlreadyExists):
		writeErr(w, http.StatusConflict, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		if !s.recordOrUndo(w, r, s.groupEvent(r, "group.create", id, nil), func(ctx context.Context) error {
			return s.store.DeleteEmptyGroup(ctx, domain, req.Name)
		}) {
			return
		}
		s.refreshAfterWrite(r.Context())
		writeJSON(w, http.StatusCreated, g)
	}
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	domain, group, ok := groupPath(w, r)
	if !ok {
		return
	}
	id := domain + ":" + group
	if !s.authorizeDomainWrite(w, r, "group.delete", id, domain) {
		return
	}
	before, err := s.store.GetGroup(r.Context(), domain, group)
	if errors.Is(err, storage.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	err = s.store.DeleteGroup(r.Context(), domain, group)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		restore := func(ctx context.Context) error { return s.store.RestoreGroup(ctx, before) }
		if !s.recordOrUndo(w, r, s.groupEvent(r, "group.delete", id, map[string]any{"members": before.Members}), restore) {
			return
		}
		s.refreshAfterWrite(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	domain, group, ok := groupPath(w, r)
	if !ok {
		return
	}
	g, err := s.store.GetGroup(r.Context(), domain, group)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		if s.hideAdmins(r) {
			g.Members = nil
		}
		writeJSON(w, http.StatusOK, g)
	}
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	domain, ok := domainPathName(w, r)
	if !ok {
		return
	}
	items, err := s.store.ListGroups(r.Context(), domain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if items == nil {
		items = []storage.Group{}
	}
	if s.hideAdmins(r) {
		for i := range items {
			items[i].Members = nil
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) putGroupMember(w http.ResponseWriter, r *http.Request) {
	domain, group, ok := groupPath(w, r)
	if !ok {
		return
	}
	var req GroupMemberRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if _, err := spiffeid.FromString(req.Principal); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("principal: %w", err))
		return
	}
	if !req.ExpiresAt.IsZero() {
		now := time.Now()
		if !req.ExpiresAt.After(now) {
			writeErr(w, http.StatusBadRequest, errors.New("expires_at must be in the future"))
			return
		}
		if req.ExpiresAt.After(now.Add(MaxMembershipLifetime)) {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("expires_at must be within %s; omit it for a membership without expiry", MaxMembershipLifetime))
			return
		}
	}
	id := domain + ":" + group
	if !s.authorizeDomainWrite(w, r, "group.member.add", id, domain) {
		return
	}
	written := storage.GroupMember{Principal: req.Principal, ExpiresAt: req.ExpiresAt.UTC()}
	if req.ExpiresAt.IsZero() {
		written.ExpiresAt = time.Time{}
	}
	prior, err := s.store.PutGroupMember(r.Context(), domain, group, written)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("group %q does not exist", id))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		payload := map[string]any{"principal": req.Principal}
		if !written.ExpiresAt.IsZero() {
			payload["expires_at"] = written.ExpiresAt
		}
		undo := func(ctx context.Context) error {
			return s.store.SwapGroupMember(ctx, domain, group, req.Principal, &written, prior)
		}
		if !s.recordOrUndo(w, r, s.groupEvent(r, "group.member.add", id, payload), undo) {
			return
		}
		s.refreshAfterWrite(r.Context())
		s.getGroup(w, r)
	}
}

func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	domain, group, ok := groupPath(w, r)
	if !ok {
		return
	}
	principal := strings.TrimSpace(r.URL.Query().Get("principal"))
	if principal == "" {
		writeErr(w, http.StatusBadRequest, errors.New("principal query parameter is required"))
		return
	}
	id := domain + ":" + group
	if !s.authorizeDomainWrite(w, r, "group.member.remove", id, domain) {
		return
	}
	removed, err := s.store.RemoveGroupMember(r.Context(), domain, group, principal)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("%q is not a member of %q", principal, id))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		undo := func(ctx context.Context) error {
			return s.store.SwapGroupMember(ctx, domain, group, principal, nil, &removed)
		}
		if !s.recordOrUndo(w, r, s.groupEvent(r, "group.member.remove", id, map[string]any{"principal": principal}), undo) {
			return
		}
		s.refreshAfterWrite(r.Context())
		s.getGroup(w, r)
	}
}

func (s *Server) groupEvent(r *http.Request, kind, id string, payload map[string]any) storage.AuditEvent {
	ev := storage.AuditEvent{Kind: kind, Actor: CallerSPIFFEID(r.Context()), Subject: id, Decision: "ok"}
	if payload != nil {
		ev.Payload = mustJSON(payload)
	}
	return ev
}
