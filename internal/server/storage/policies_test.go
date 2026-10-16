package storage_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/storage"
)

func TestPolicies(t *testing.T) { exercisePolicies(t, newStore(t)) }

func TestPostgresPolicies(t *testing.T) { exercisePolicies(t, openPostgresStore(t)) }

// exercisePolicies runs the stored-policy contract against s.
func exercisePolicies(t *testing.T, s *storage.Store) {
	t.Helper()
	ctx := context.Background()
	write := func(id, text, by string) storage.PolicyChange {
		return func(cur *storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
			ev := storage.AuditEvent{Kind: "policy.test", Actor: by, Subject: id}
			if text == "" {
				return nil, ev, nil
			}
			return &storage.Policy{Text: text, UpdatedBy: by}, ev, nil
		}
	}

	p, ev, err := s.ChangePolicy(ctx, "a", write("a", "permit (principal, action, resource);", "spiffe://td/one"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.CreatedBy != "spiffe://td/one" || p.Digest != storage.PolicyDigest(p.Text) || ev.Seq == 0 {
		t.Fatalf("created %+v %+v", p, ev)
	}
	if !strings.HasPrefix(p.ETag(), `"1-`) {
		t.Fatalf("etag %s", p.ETag())
	}
	p2, _, err := s.ChangePolicy(ctx, "a", write("a", "forbid (principal, action, resource);", "spiffe://td/two"))
	if err != nil {
		t.Fatal(err)
	}
	if p2.Version != 2 || p2.CreatedBy != "spiffe://td/one" || p2.UpdatedBy != "spiffe://td/two" || p2.ETag() == p.ETag() || !p2.CreatedAt.Equal(p.CreatedAt) {
		t.Fatalf("updated %+v", p2)
	}
	got, err := s.GetPolicy(ctx, "a")
	if err != nil || got.Text != p2.Text || got.Version != 2 {
		t.Fatalf("get %+v %v", got, err)
	}
	if _, _, err := s.ChangePolicy(ctx, "b", write("b", "permit (principal, action, resource);", "x")); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListPolicies(ctx)
	if err != nil || len(all) != 2 || all[0].ID != "a" || all[1].ID != "b" {
		t.Fatalf("list %+v %v", all, err)
	}

	// A refused change writes nothing, not even its audit row.
	before, _ := s.ListAudit(ctx, 0, 1000)
	boom := errors.New("refused")
	if _, _, err := s.ChangePolicy(ctx, "a", func(*storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
		return nil, storage.AuditEvent{}, boom
	}); !errors.Is(err, boom) {
		t.Fatalf("refused: %v", err)
	}
	if _, _, err := s.ChangePolicy(ctx, "a", func(*storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
		return &storage.Policy{Text: "x"}, storage.AuditEvent{}, nil
	}); err == nil {
		t.Fatal("a change without an audit kind must fail")
	}
	after, _ := s.ListAudit(ctx, 0, 1000)
	if len(after) != len(before) {
		t.Fatalf("refused changes appended %d rows", len(after)-len(before))
	}

	if _, _, err := s.ChangePolicy(ctx, "a", write("a", "", "x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPolicy(ctx, "a"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if _, _, err := s.ChangePolicy(ctx, "a", write("a", "", "x")); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if v, err := s.VerifyAudit(ctx, nil); err != nil || !v.Valid {
		t.Fatalf("chain %+v %v", v, err)
	}
}

func TestValidatePolicyID(t *testing.T) {
	for id, ok := range map[string]bool{
		"a": true, "allow-read": true, "a_b-9": true,
		"": false, "A": false, "a.cedar": false, "a/b": false, "-a": false, "a-": false, strings.Repeat("a", 64): false,
	} {
		if err := storage.ValidatePolicyID(id); (err == nil) != ok {
			t.Errorf("%q: %v", id, err)
		}
	}
}

func TestPolicyWritesNeedLeader(t *testing.T) {
	s := newStore(t)
	s.SetLeaderForTest(true, false)
	_, _, err := s.ChangePolicy(context.Background(), "a", func(*storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
		t.Fatal("a follower must not run the change")
		return nil, storage.AuditEvent{}, nil
	})
	if !errors.Is(err, storage.ErrNotLeader) {
		t.Fatalf("follower: %v", err)
	}
}

func TestPolicyAuditDigests(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	for _, ev := range []storage.AuditEvent{
		{Kind: "policy.create", Subject: "a", Decision: "ok", Payload: []byte(`{"new_digest":"d1"}`)},
		{Kind: "policy.update", Subject: "a", Decision: "ok", Payload: []byte(`{"new_digest":"d2"}`)},
		{Kind: "policy.create", Subject: "b", Decision: "deny", Payload: []byte(`{"reason":"no"}`)},
		{Kind: "policy.create", Subject: "c", Decision: "ok", Payload: []byte(`{"new_digest":"d3"}`)},
		{Kind: "policy.delete", Subject: "c", Decision: "ok", Payload: []byte(`{"new_digest":""}`)},
	} {
		if _, err := s.AppendAudit(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.PolicyAuditDigests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["a"] != "d2" || got["c"] != "" {
		t.Fatalf("digests %v", got)
	}
}
