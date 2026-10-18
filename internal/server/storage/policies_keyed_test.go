package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Under a keyring, a policy audit row a database writer forged without
// the key is not taken as vouching for a policy.
func TestPolicyAuditDigestsCheckRowMACs(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)
	store.UseAuditKeyring(mustKeyring(t, "k1", map[string][]byte{"k1": key(1)}))
	ev, err := store.AppendAudit(ctx, AuditEvent{Kind: "policy.create", Subject: "a", Decision: "ok", Payload: []byte(`{"new_digest":"d1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := store.PolicyAuditDigests(ctx); err != nil || got["a"] != "d1" {
		t.Fatalf("a keyed row must verify: %v %v", got, err)
	}

	forge := func(keyID, hash string) error {
		t.Helper()
		if _, err := store.db.ExecContext(ctx, `INSERT INTO audit_log(ts, kind, actor, subject, decision, payload, prev_hash, hash, key_id)
			VALUES (1, 'policy.update', '', 'a', 'ok', '{"new_digest":"forged"}', ?, ?, ?)`, ev.Hash, hash, keyID); err != nil {
			t.Fatal(err)
		}
		_, err := store.PolicyAuditDigests(ctx)
		_, _ = store.db.ExecContext(ctx, `DELETE FROM audit_log WHERE hash = ?`, hash)
		return err
	}
	for name, c := range map[string]struct{ keyID, hash, want string }{
		"unkeyed":     {keyIDUnkeyed, "aa", "unkeyed row after audit keying began"},
		"unknown key": {"k9", "bb", "does not hold"},
		"bad MAC":     {"k1", "cc", "MAC does not verify"},
	} {
		if err := forge(c.keyID, c.hash); !errors.Is(err, ErrAuditRowUnverified) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
