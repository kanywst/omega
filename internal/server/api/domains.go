package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/metrics"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// domainState carries the domain-admin configuration and the cached
// projection of the domain tree into the policy engine.
type domainState struct {
	rootAdmins []string
	mu         sync.Mutex
	loadedAt   time.Time
}

// WithDomainRootAdmins sets the principals that may create top-level
// domains and administer every domain. It only matters under
// --require-auth; without it domain writes stay open.
func (s *Server) WithDomainRootAdmins(ids []string) *Server {
	s.domains.rootAdmins = slices.Clone(ids)
	return s
}

// RefreshDirectory reloads the domain tree into the policy engine.
func (s *Server) RefreshDirectory(ctx context.Context) error {
	items, err := s.store.ListDomains(ctx)
	if err != nil {
		return err
	}
	tree := make(map[string]string, len(items))
	for _, d := range items {
		// Derive the parent from the name, as authorization does, and
		// skip rows an older version stored with an invalid name or a
		// parent that disagrees with it.
		if storage.ValidateDomainName(d.Name) != nil {
			continue
		}
		tree[d.Name] = storage.ParentOf(d.Name)
	}
	s.policy.SetDirectory(policy.Directory{TrustDomain: s.ca.TrustDomain(), Domains: tree})
	s.domains.mu.Lock()
	s.domains.loadedAt = time.Now()
	s.domains.mu.Unlock()
	return nil
}

// RunDirectorySync refreshes the projection every interval until ctx is
// done, so a replica picks up domains another replica created.
func (s *Server) RunDirectorySync(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.RefreshDirectory(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("domain directory refresh failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) refreshAfterWrite(ctx context.Context) {
	if err := s.RefreshDirectory(ctx); err != nil {
		slog.Warn("domain directory refresh failed", "err", err)
	}
}

// mayAdminister reports whether caller may administer domain: a root
// admin, or an admin of the domain or any of its ancestors. Without
// --require-auth every caller may.
func (s *Server) mayAdminister(ctx context.Context, caller, domain string) (bool, error) {
	if !s.requireAuth {
		return true, nil
	}
	if caller == "" {
		return false, nil
	}
	if slices.Contains(s.domains.rootAdmins, caller) {
		return true, nil
	}
	var chain []string
	for name := domain; name != ""; name = storage.ParentOf(name) {
		chain = append(chain, name)
	}
	admins, err := s.store.AdminsOf(ctx, chain)
	if err != nil {
		return false, err
	}
	for _, name := range chain {
		if slices.Contains(admins[name], caller) {
			return true, nil
		}
	}
	return false, nil
}

// authorizeDomainWrite writes 403 (or 500) and returns false unless the
// caller may administer domain. A refusal is audited under kind with
// target as its subject.
func (s *Server) authorizeDomainWrite(w http.ResponseWriter, r *http.Request, kind, target, domain string) bool {
	caller := CallerSPIFFEID(r.Context())
	ok, err := s.mayAdminister(r.Context(), caller, domain)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return false
	}
	if !ok {
		s.audit(r.Context(), storage.AuditEvent{
			Kind:     kind,
			Actor:    caller,
			Subject:  target,
			Decision: "deny",
			Payload:  mustJSON(map[string]string{"reason": "not an admin of the domain or any ancestor"}),
		})
		target := domain
		if target == "" {
			target = "a top-level domain"
		}
		writeErr(w, http.StatusForbidden, fmt.Errorf("caller is not an admin of %s or any domain above it", target))
		return false
	}
	return true
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) {
	var d storage.Domain
	if !decodeJSONBody(w, r, &d) {
		return
	}
	if err := storage.ValidateDomainName(d.Name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	for _, a := range d.Admins {
		if _, err := spiffeid.FromString(a); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("admin %q: %w", a, err))
			return
		}
	}
	// Creating a domain is administering its parent.
	if !s.authorizeDomainWrite(w, r, "domain.create", d.Name, storage.ParentOf(d.Name)) {
		return
	}
	caller := CallerSPIFFEID(r.Context())
	if len(d.Admins) == 0 && caller != "" {
		d.Admins = []string{caller}
	}
	created, err := s.store.CreateDomain(r.Context(), d)
	switch {
	case errors.Is(err, storage.ErrAlreadyExists):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, storage.ErrParentNotFound):
		writeErr(w, http.StatusBadRequest, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		metrics.DomainsCreated.Inc()
		s.audit(r.Context(), storage.AuditEvent{
			Kind:     "domain.create",
			Actor:    caller,
			Subject:  created.Name,
			Decision: "ok",
			Payload:  mustJSON(created),
		})
		s.refreshAfterWrite(r.Context())
		writeJSON(w, http.StatusCreated, created)
	}
}

// domainPathName reads and validates the {name} path value, writing 400
// on a bad name so nothing downstream runs for it.
func domainPathName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if err := storage.ValidateDomainName(name); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return "", false
	}
	return name, true
}

func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request) {
	name, ok := domainPathName(w, r)
	if !ok {
		return
	}
	if !s.authorizeDomainWrite(w, r, "domain.delete", name, storage.ParentOf(name)) {
		return
	}
	err := s.store.DeleteDomain(r.Context(), name)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, storage.ErrHasChildren):
		writeErr(w, http.StatusConflict, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		s.audit(r.Context(), storage.AuditEvent{
			Kind:     "domain.delete",
			Actor:    CallerSPIFFEID(r.Context()),
			Subject:  name,
			Decision: "ok",
		})
		s.refreshAfterWrite(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}
}

// DomainAdminRequest is the body of POST /v1/domains/{name}/admins.
type DomainAdminRequest struct {
	Principal string `json:"principal"`
}

func (s *Server) addDomainAdmin(w http.ResponseWriter, r *http.Request) {
	name, ok := domainPathName(w, r)
	if !ok {
		return
	}
	var req DomainAdminRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if _, err := spiffeid.FromString(req.Principal); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("principal: %w", err))
		return
	}
	if !s.authorizeDomainWrite(w, r, "domain.admin.add", name, name) {
		return
	}
	err := s.store.AddDomainAdmin(r.Context(), name, req.Principal)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		s.audit(r.Context(), storage.AuditEvent{
			Kind:     "domain.admin.add",
			Actor:    CallerSPIFFEID(r.Context()),
			Subject:  name,
			Decision: "ok",
			Payload:  mustJSON(map[string]string{"principal": req.Principal}),
		})
		s.getDomain(w, r)
	}
}

func (s *Server) removeDomainAdmin(w http.ResponseWriter, r *http.Request) {
	name, ok := domainPathName(w, r)
	if !ok {
		return
	}
	principal := strings.TrimSpace(r.URL.Query().Get("principal"))
	if principal == "" {
		writeErr(w, http.StatusBadRequest, errors.New("principal query parameter is required"))
		return
	}
	if !s.authorizeDomainWrite(w, r, "domain.admin.remove", name, name) {
		return
	}
	err := s.store.RemoveDomainAdmin(r.Context(), name, principal)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, fmt.Errorf("%q is not an admin of %q", principal, name))
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		s.audit(r.Context(), storage.AuditEvent{
			Kind:     "domain.admin.remove",
			Actor:    CallerSPIFFEID(r.Context()),
			Subject:  name,
			Decision: "ok",
			Payload:  mustJSON(map[string]string{"principal": principal}),
		})
		s.getDomain(w, r)
	}
}
