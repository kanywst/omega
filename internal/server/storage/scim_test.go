package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/kanywst/omega/internal/server/storage"
)

func TestSCIMProvisioning(t *testing.T) { exerciseSCIM(t, newStore(t)) }

func TestPostgresSCIMProvisioning(t *testing.T) { exerciseSCIM(t, openPostgresStore(t)) }

// exerciseSCIM runs the SCIM storage contract against s.
func exerciseSCIM(t *testing.T, s *storage.Store) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "people"}); err != nil {
		t.Fatal(err)
	}
	run := func(fn func(*storage.SCIMTx) error) error {
		_, err := s.SCIM(ctx, "corp", func(tx *storage.SCIMTx) (storage.AuditEvent, error) {
			return storage.AuditEvent{Kind: "scim.test", Actor: "scim:corp"}, fn(tx)
		})
		return err
	}
	members := func(name string) []string {
		g, err := s.GetGroup(ctx, "people", name)
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		var out []string
		for _, m := range g.Members {
			out = append(out, m.Principal)
		}
		return out
	}

	var alice, bob storage.SCIMUser
	var eng storage.SCIMGroup
	if err := run(func(tx *storage.SCIMTx) error {
		var err error
		if alice, err = tx.CreateUser(storage.SCIMUser{UserName: "Alice", Active: true, Principal: "spiffe://td/humans/corp/a"}); err != nil {
			return err
		}
		if bob, err = tx.CreateUser(storage.SCIMUser{UserName: "bob", Active: true, Principal: "spiffe://td/humans/corp/b"}); err != nil {
			return err
		}
		eng, err = tx.CreateGroup(storage.SCIMGroup{DisplayName: "Engineering", Domain: "people", Group: "engineering", Members: []string{alice.ID, bob.ID}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := members("engineering"); len(got) != 2 {
		t.Fatalf("members after create: %v", got)
	}
	if idp, managed, _ := s.SCIMManaged(ctx, "people", "engineering"); !managed || idp != "corp" {
		t.Fatalf("managed: %v %q", managed, idp)
	}
	// The Omega group API's writes refuse the provider's group in their
	// own transactions.
	if _, err := s.PutGroupMember(ctx, "people", "engineering", storage.GroupMember{Principal: "spiffe://td/x"}); !errors.Is(err, storage.ErrSCIMManaged) {
		t.Errorf("put member: %v", err)
	}
	if _, err := s.RemoveGroupMember(ctx, "people", "engineering", alice.Principal); !errors.Is(err, storage.ErrSCIMManaged) {
		t.Errorf("remove member: %v", err)
	}
	if err := s.SwapGroupMember(ctx, "people", "engineering", alice.Principal, nil, nil); !errors.Is(err, storage.ErrSCIMManaged) {
		t.Errorf("swap member: %v", err)
	}
	if _, err := s.DeleteGroup(ctx, "people", "engineering"); !errors.Is(err, storage.ErrSCIMManaged) {
		t.Errorf("delete: %v", err)
	}
	if err := s.DeleteEmptyGroup(ctx, "people", "engineering"); !errors.Is(err, storage.ErrSCIMManaged) {
		t.Errorf("delete empty: %v", err)
	}

	// userName is unique without regard to case.
	if err := run(func(tx *storage.SCIMTx) error {
		_, err := tx.CreateUser(storage.SCIMUser{UserName: "ALICE", Active: true, Principal: "spiffe://td/x"})
		return err
	}); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("duplicate userName: %v", err)
	}
	if err := run(func(tx *storage.SCIMTx) error {
		users, total, err := tx.ListUsers("userName", "alice", 0, 10)
		if err == nil && (len(users) != 1 || total != 1) {
			t.Errorf("filter by userName: %d of %d", len(users), total)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Deactivating a user takes it out of every group; reactivating
	// puts it back.
	setActive := func(active bool) {
		t.Helper()
		if err := run(func(tx *storage.SCIMTx) error {
			u := alice
			u.Active = active
			_, err := tx.ReplaceUser(u)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	setActive(false)
	if got := members("engineering"); len(got) != 1 || got[0] != bob.Principal {
		t.Fatalf("after deactivation: %v", got)
	}
	setActive(true)
	if got := members("engineering"); len(got) != 2 {
		t.Fatalf("after reactivation: %v", got)
	}

	// A new principal moves the user's memberships.
	if err := run(func(tx *storage.SCIMTx) error {
		u := alice
		u.Principal = "spiffe://td/humans/corp/a2"
		_, err := tx.ReplaceUser(u)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := members("engineering"); len(got) != 2 || got[0] != "spiffe://td/humans/corp/a2" {
		t.Fatalf("after principal change: %v", got)
	}

	// Rename, patch and unknown members.
	if err := run(func(tx *storage.SCIMTx) error {
		g := eng
		g.DisplayName, g.Group, g.Members = "Platform", "platform", []string{bob.ID}
		_, err := tx.ReplaceGroup(g)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetGroup(ctx, "people", "engineering"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("old name still present: %v", err)
	}
	if got := members("platform"); len(got) != 1 {
		t.Fatalf("after rename: %v", got)
	}
	if err := run(func(tx *storage.SCIMTx) error { return tx.PatchMembers(eng.ID, []string{"nope"}, nil) }); !errors.Is(err, storage.ErrUnknownMember) {
		t.Fatalf("unknown member: %v", err)
	}
	if err := run(func(tx *storage.SCIMTx) error { return tx.PatchMembers(eng.ID, []string{alice.ID}, []string{bob.ID}) }); err != nil {
		t.Fatal(err)
	}
	if got := members("platform"); len(got) != 1 || got[0] != "spiffe://td/humans/corp/a2" {
		t.Fatalf("after patch: %v", got)
	}

	// A group name an Omega group already holds is refused.
	if _, err := s.CreateGroup(ctx, storage.Group{Domain: "people", Name: "oncall"}); err != nil {
		t.Fatal(err)
	}
	if err := run(func(tx *storage.SCIMTx) error {
		_, err := tx.CreateGroup(storage.SCIMGroup{DisplayName: "oncall", Domain: "people", Group: "oncall"})
		return err
	}); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("taken name: %v", err)
	}
	if err := run(func(tx *storage.SCIMTx) error {
		_, err := tx.CreateGroup(storage.SCIMGroup{DisplayName: "x", Domain: "nowhere", Group: "x"})
		return err
	}); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("missing domain: %v", err)
	}

	// A failure inside the transaction leaves nothing behind.
	boom := errors.New("boom")
	if _, err := s.SCIM(ctx, "corp", func(tx *storage.SCIMTx) (storage.AuditEvent, error) {
		if err := tx.DeleteUser(alice.ID); err != nil {
			return storage.AuditEvent{}, err
		}
		return storage.AuditEvent{}, boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if got := members("platform"); len(got) != 1 {
		t.Fatalf("rolled back delete changed members: %v", got)
	}

	// Deleting a user and a group.
	if err := run(func(tx *storage.SCIMTx) error { return tx.DeleteUser(alice.ID) }); err != nil {
		t.Fatal(err)
	}
	if got := members("platform"); len(got) != 0 {
		t.Fatalf("after user delete: %v", got)
	}
	if err := run(func(tx *storage.SCIMTx) error { return tx.DeleteGroup(eng.ID) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetGroup(ctx, "people", "platform"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("group still present: %v", err)
	}
	if err := run(func(tx *storage.SCIMTx) error { return tx.DeleteGroup(eng.ID) }); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}

	// Every committed change is on the chain, and the chain verifies.
	events, err := s.ListAudit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, ev := range events {
		if ev.Kind == "scim.test" {
			n++
		}
	}
	if n != 9 {
		t.Errorf("scim audit rows: %d", n)
	}
	if v, err := s.VerifyAudit(ctx, nil); err != nil || !v.Valid {
		t.Fatalf("verify: %+v %v", v, err)
	}
}
