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
			return s.store.DeleteGroup(ctx, domain, req.Name)
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
		restore := func(ctx context.Context) error {
			if _, err := s.store.CreateGroup(ctx, before); err != nil {
				return err
			}
			for _, m := range before.Members {
				if err := s.store.PutGroupMember(ctx, domain, group, m); err != nil {
					return err
				}
			}
			return nil
		}
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
	if !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(time.Now()) {
		writeErr(w, http.StatusBadRequest, errors.New("expires_at must be in the future"))
		return
	}
	id := domain + ":" + group
	if !s.authorizeDomainWrite(w, r, "group.member.add", id, domain) {
		return
	}
	before, err := s.store.GetGroup(r.Context(), domain, group)
	if errors.Is(err, storage.ErrNotFound) {
		writeErr(w, http.StatusNotFound, fmt.Errorf("group %q does not exist", id))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	var prior *storage.GroupMember
	for i := range before.Members {
		if before.Members[i].Principal == req.Principal {
			prior = &before.Members[i]
		}
	}
	err = s.store.PutGroupMember(r.Context(), domain, group, storage.GroupMember{Principal: req.Principal, ExpiresAt: req.ExpiresAt.UTC()})
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("group %q does not exist", id))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		payload := map[string]any{"principal": req.Principal}
		if !req.ExpiresAt.IsZero() {
			payload["expires_at"] = req.ExpiresAt.UTC()
		}
		undo := func(ctx context.Context) error {
			if prior != nil {
				return s.store.PutGroupMember(ctx, domain, group, *prior)
			}
			return s.store.RemoveGroupMember(ctx, domain, group, req.Principal)
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
	before, err := s.store.GetGroup(r.Context(), domain, group)
	if errors.Is(err, storage.ErrNotFound) {
		writeErr(w, http.StatusNotFound, fmt.Errorf("group %q does not exist", id))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	var prior storage.GroupMember
	for _, m := range before.Members {
		if m.Principal == principal {
			prior = m
		}
	}
	err = s.store.RemoveGroupMember(r.Context(), domain, group, principal)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("%q is not a member of %q", principal, id))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		undo := func(ctx context.Context) error { return s.store.PutGroupMember(ctx, domain, group, prior) }
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
