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
	// refreshMu serialises whole reloads, so a reload that read older
	// state can never apply it after one that read newer state.
	refreshMu sync.Mutex
	mu        sync.Mutex
	loadedAt  time.Time
	interval  time.Duration
}

// directoryStaleAfter is how many sync intervals may pass without a
// successful reload before policy evaluation fails closed.
const directoryStaleAfter = 3

// directoryStale reports whether the projected tree is too old to
// evaluate against: a forbid on a domain created since would not apply.
// It only applies once RunDirectorySync is running.
func (s *Server) directoryStale() bool {
	s.domains.mu.Lock()
	defer s.domains.mu.Unlock()
	return s.domains.interval > 0 && time.Since(s.domains.loadedAt) > directoryStaleAfter*s.domains.interval
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
	s.domains.refreshMu.Lock()
	defer s.domains.refreshMu.Unlock()
	items, err := s.store.ListDomains(ctx)
	if err != nil {
		return err
	}
	tree := make(map[string]string, len(items))
	var skipped int
	for _, d := range items {
		// Derive the parent from the name, as authorization does, and
		// skip rows an older version stored with an invalid name: no
		// SPIFFE path can match them, so their workloads are in no
		// domain. Say so, since a forbid on such a domain covers nothing.
		if err := storage.ValidateDomainName(d.Name); err != nil {
			slog.Warn("domain not projected into policy: invalid name from an earlier version; recreate it under a valid name", "domain", d.Name, "err", err)
			skipped++
			continue
		}
		tree[d.Name] = storage.ParentOf(d.Name)
	}
	metrics.DomainsUnprojected.Set(float64(skipped))
	td := s.ca.TrustDomain()
	if td.IsZero() && len(tree) > 0 {
		// Membership is derived from SPIFFE IDs in the local trust
		// domain; without one, no workload would be in any domain and
		// a forbid on a domain would match nothing. Refuse, so the
		// tree goes stale and evaluation fails closed.
		return errors.New("domains exist but the identity source reports no trust domain")
	}
	s.policy.SetDirectory(policy.Directory{TrustDomain: td, Domains: tree})
	s.domains.mu.Lock()
	s.domains.loadedAt = time.Now()
	s.domains.mu.Unlock()
	return nil
}

// RunDirectorySync refreshes the projection every interval until ctx is
// done, so a replica picks up domains another replica created.
func (s *Server) RunDirectorySync(ctx context.Context, interval time.Duration) {
	s.domains.mu.Lock()
	s.domains.interval = interval
	s.domains.mu.Unlock()
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
		ev := storage.AuditEvent{Kind: "domain.create", Actor: caller, Subject: created.Name, Decision: "ok", Payload: mustJSON(created)}
		if !s.recordOrUndo(w, r, ev, func(ctx context.Context) error { return s.store.DeleteDomain(ctx, created.Name) }) {
			return
		}
		metrics.DomainsCreated.Inc()
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
	// Keep what is deleted, so a failed audit can put it back.
	before, err := s.store.GetDomain(r.Context(), name)
	if errors.Is(err, storage.ErrNotFound) {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	err = s.store.DeleteDomain(r.Context(), name)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, storage.ErrHasChildren):
		writeErr(w, http.StatusConflict, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		ev := storage.AuditEvent{Kind: "domain.delete", Actor: CallerSPIFFEID(r.Context()), Subject: name, Decision: "ok", Payload: mustJSON(before)}
		if !s.recordOrUndo(w, r, ev, func(ctx context.Context) error { _, err := s.store.CreateDomain(ctx, before); return err }) {
			return
		}
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
	inserted, err := s.store.AddDomainAdmin(r.Context(), name, req.Principal)
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		ev := storage.AuditEvent{Kind: "domain.admin.add", Actor: CallerSPIFFEID(r.Context()), Subject: name, Decision: "ok", Payload: mustJSON(map[string]string{"principal": req.Principal})}
		// Undo only a grant this request inserted, never one that existed
		// or that a concurrent request added.
		undo := func(ctx context.Context) error {
			if !inserted {
				return nil
			}
			return s.store.RemoveDomainAdmin(ctx, name, req.Principal)
		}
		if !s.recordOrUndo(w, r, ev, undo) {
			return
		}
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
		ev := storage.AuditEvent{Kind: "domain.admin.remove", Actor: CallerSPIFFEID(r.Context()), Subject: name, Decision: "ok", Payload: mustJSON(map[string]string{"principal": principal})}
		if !s.recordOrUndo(w, r, ev, func(ctx context.Context) error {
			_, err := s.store.AddDomainAdmin(ctx, name, principal)
			return err
		}) {
			return
		}
		s.getDomain(w, r)
	}
}

// recordOrUndo appends the audit row for a committed change. If the
// row cannot be written it reverts the change with undo and answers 500,
// so no change to who administers what goes unrecorded.
func (s *Server) recordOrUndo(w http.ResponseWriter, r *http.Request, ev storage.AuditEvent, undo func(context.Context) error) bool {
	if err := s.appendAudit(r.Context(), ev); err != nil {
		ctx := context.WithoutCancel(r.Context())
		if uerr := undo(ctx); uerr != nil {
			slog.Error("audit append failed and the change could not be reverted", "kind", ev.Kind, "subject", ev.Subject, "err", uerr)
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("could not record %s, and reverting the change failed (%v); check the current state before retrying", ev.Kind, uerr))
			return false
		}
		// The append may have committed despite the error (a lost
		// connection on commit), so record the revert too. If that also
		// fails the chain may show the change as applied; say so.
		rev := ev
		rev.Decision = "reverted"
		if rerr := s.appendAudit(ctx, rev); rerr != nil {
			slog.Error("change reverted but the revert could not be recorded", "kind", ev.Kind, "subject", ev.Subject, "err", rerr)
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("could not record %s; the change was reverted, but the audit log may still show it as applied", ev.Kind))
			return false
		}
		writeErr(w, http.StatusInternalServerError, fmt.Errorf("could not record %s; the change was reverted", ev.Kind))
		return false
	}
	return true
}
