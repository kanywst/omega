package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/storage"
)

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateGetList(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media"}); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	created, err := s.CreateDomain(ctx, storage.Domain{Name: "media.news", Description: "news domain"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Parent != "media" {
		t.Errorf("parent auto-derive: got %q want %q", created.Parent, "media")
	}
	if created.CreatedAt.IsZero() {
		t.Error("created_at should be set")
	}

	got, err := s.GetDomain(ctx, "media.news")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "media.news" || got.Description != "news domain" || got.Parent != "media" {
		t.Errorf("get returned wrong domain: %+v", got)
	}

	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media.sports"}); err != nil {
		t.Fatalf("create second: %v", err)
	}
	list, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("list len: got %d want 3", len(list))
	}
	if list[1].Name != "media.news" || list[2].Name != "media.sports" {
		t.Errorf("list order: %+v", list)
	}
}

func TestDuplicate(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "example"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := s.CreateDomain(ctx, storage.Domain{Name: "example"})
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
}

func TestNotFound(t *testing.T) {
	s := newStore(t)
	_, err := s.GetDomain(context.Background(), "nope")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestEmptyName(t *testing.T) {
	s := newStore(t)
	if _, err := s.CreateDomain(context.Background(), storage.Domain{}); err == nil {
		t.Fatal("want error on empty name")
	}
}

func TestDomainHierarchyRules(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media.news"}); !errors.Is(err, storage.ErrParentNotFound) {
		t.Fatalf("orphan child: got %v, want ErrParentNotFound", err)
	}
	for _, bad := range []string{"Media", "media..news", "-media", "media/news", ""} {
		if _, err := s.CreateDomain(ctx, storage.Domain{Name: bad}); err == nil {
			t.Errorf("name %q must be rejected", bad)
		}
	}
	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media", Admins: []string{"spiffe://td/a", "spiffe://td/a", "spiffe://td/b"}}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media.news", Parent: "other"}); err == nil {
		t.Error("an explicit parent that disagrees with the name must be rejected")
	}
	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media.news"}); err != nil {
		t.Fatalf("child: %v", err)
	}
	d, err := s.GetDomain(ctx, "media")
	if err != nil || len(d.Admins) != 2 {
		t.Fatalf("admins deduplicated: %+v %v", d, err)
	}

	if inserted, err := s.AddDomainAdmin(ctx, "media", "spiffe://td/c"); err != nil || !inserted {
		t.Fatalf("add admin: %v %v", inserted, err)
	}
	if inserted, err := s.AddDomainAdmin(ctx, "media", "spiffe://td/c"); err != nil || inserted {
		t.Fatalf("re-adding an admin is a no-op that inserts nothing: %v %v", inserted, err)
	}
	if _, err := s.AddDomainAdmin(ctx, "nope", "spiffe://td/c"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("admin on missing domain: %v", err)
	}
	if err := s.RemoveDomainAdmin(ctx, "media", "spiffe://td/c"); err != nil {
		t.Fatalf("remove admin: %v", err)
	}
	if err := s.RemoveDomainAdmin(ctx, "media", "spiffe://td/c"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("remove twice: %v", err)
	}

	if err := s.DeleteDomain(ctx, "media"); !errors.Is(err, storage.ErrHasChildren) {
		t.Fatalf("delete with children: %v", err)
	}
	if err := s.DeleteDomain(ctx, "media.news"); err != nil {
		t.Fatalf("delete leaf: %v", err)
	}
	if err := s.DeleteDomain(ctx, "media.news"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if err := s.DeleteDomain(ctx, "media"); err != nil {
		t.Fatalf("delete now-empty parent: %v", err)
	}
	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media"}); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if d, _ := s.GetDomain(ctx, "media"); len(d.Admins) != 0 {
		t.Errorf("admin grants must not outlive their domain: %v", d.Admins)
	}
}

// TestSQLiteDomainCreateDeleteRace is the SQLite counterpart of the
// Postgres race test: a child must never outlive its parent.
func TestSQLiteDomainCreateDeleteRace(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		if _, err := s.CreateDomain(ctx, storage.Domain{Name: "race"}); err != nil {
			t.Fatalf("round %d: create parent: %v", i, err)
		}
		done := make(chan struct{}, 2)
		go func() { _, _ = s.CreateDomain(ctx, storage.Domain{Name: "race.child"}); done <- struct{}{} }()
		go func() { _ = s.DeleteDomain(ctx, "race"); done <- struct{}{} }()
		<-done
		<-done
		list, err := s.ListDomains(ctx)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, d := range list {
			names[d.Name] = true
		}
		if names["race.child"] && !names["race"] {
			t.Fatalf("round %d: race.child exists without its parent", i)
		}
		_ = s.DeleteDomain(ctx, "race.child")
		_ = s.DeleteDomain(ctx, "race")
	}
}

func TestGroups(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.CreateGroup(ctx, storage.Group{Domain: "media", Name: "oncall"}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("group in a missing domain: %v", err)
	}
	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, storage.Group{Domain: "media", Name: "On Call"}); err == nil {
		t.Error("an invalid group name must be rejected")
	}
	if _, err := s.CreateGroup(ctx, storage.Group{Domain: "media", Name: "oncall"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, storage.Group{Domain: "media", Name: "oncall"}); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("duplicate: %v", err)
	}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := s.PutGroupMember(ctx, "media", "oncall", storage.GroupMember{Principal: "spiffe://td/a", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutGroupMember(ctx, "media", "oncall", storage.GroupMember{Principal: "spiffe://td/b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutGroupMember(ctx, "media", "nope", storage.GroupMember{Principal: "spiffe://td/b"}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("member of a missing group: %v", err)
	}
	g, err := s.GetGroup(ctx, "media", "oncall")
	if err != nil || len(g.Members) != 2 || !g.Members[0].ExpiresAt.Equal(exp) || !g.Members[1].ExpiresAt.IsZero() {
		t.Fatalf("members: %+v %v", g, err)
	}
	// Re-putting a member updates its expiry instead of duplicating it.
	if _, err := s.PutGroupMember(ctx, "media", "oncall", storage.GroupMember{Principal: "spiffe://td/a"}); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.GetGroup(ctx, "media", "oncall"); len(g.Members) != 2 || !g.Members[0].ExpiresAt.IsZero() {
		t.Fatalf("expiry update: %+v", g.Members)
	}
	if err := s.DeleteDomain(ctx, "media"); !errors.Is(err, storage.ErrHasGroups) {
		t.Fatalf("deleting a domain that owns groups: %v", err)
	}
	if _, err := s.RemoveGroupMember(ctx, "media", "oncall", "spiffe://td/a"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, "media", "oncall"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, storage.Group{Domain: "media", Name: "oncall"}); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.GetGroup(ctx, "media", "oncall"); len(g.Members) != 0 {
		t.Errorf("a re-created group starts empty: %+v", g.Members)
	}
}

func TestGroupMemberCompareAndUndo(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, storage.Group{Domain: "media", Name: "oncall"}); err != nil {
		t.Fatal(err)
	}
	a := storage.GroupMember{Principal: "spiffe://td/a"}
	prior, err := s.PutGroupMember(ctx, "media", "oncall", a)
	if err != nil || prior != nil {
		t.Fatalf("first put: %v %v", prior, err)
	}
	later := storage.GroupMember{Principal: "spiffe://td/a", ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	prior, err = s.PutGroupMember(ctx, "media", "oncall", later)
	if err != nil || prior == nil || !prior.ExpiresAt.IsZero() {
		t.Fatalf("second put returns the replaced membership: %v %v", prior, err)
	}
	// Undoing the first put must not clobber the second.
	if err := s.SwapGroupMember(ctx, "media", "oncall", a.Principal, &a, nil); !errors.Is(err, storage.ErrChanged) {
		t.Fatalf("stale undo: %v", err)
	}
	// Undoing the second put restores the first.
	if err := s.SwapGroupMember(ctx, "media", "oncall", a.Principal, &later, prior); err != nil {
		t.Fatalf("undo: %v", err)
	}
	removed, err := s.RemoveGroupMember(ctx, "media", "oncall", a.Principal)
	if err != nil || removed.Principal != a.Principal {
		t.Fatalf("remove returns the row: %+v %v", removed, err)
	}
	if err := s.SwapGroupMember(ctx, "media", "oncall", a.Principal, nil, &removed); err != nil {
		t.Fatalf("undo remove: %v", err)
	}
	if err := s.DeleteEmptyGroup(ctx, "media", "oncall"); !errors.Is(err, storage.ErrChanged) {
		t.Fatalf("a group with members is not deleted by a create undo: %v", err)
	}
	g, _ := s.GetGroup(ctx, "media", "oncall")
	if err := s.DeleteGroup(ctx, "media", "oncall"); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreGroup(ctx, g); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if err := s.RestoreGroup(ctx, g); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("restore over an existing group: %v", err)
	}
	if got, _ := s.GetGroup(ctx, "media", "oncall"); len(got.Members) != 1 {
		t.Errorf("restored members: %+v", got.Members)
	}
}
