package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustKeyring(t *testing.T, activeID string, keys map[string][]byte) *AuditKeyring {
	t.Helper()
	kr, err := NewAuditKeyring(activeID, keys)
	if err != nil {
		t.Fatalf("NewAuditKeyring: %v", err)
	}
	return kr
}

func key(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// A keyed chain verifies cleanly under its keyring.
func TestKeyedChainVerifies(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)
	store.UseAuditKeyring(mustKeyring(t, "k1", map[string][]byte{"k1": key(1)}))

	for i := 0; i < 5; i++ {
		ev, err := store.AppendAudit(ctx, AuditEvent{Kind: "k", Subject: "s"})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if ev.KeyID != "k1" {
			t.Fatalf("row %d key_id = %q, want k1", ev.Seq, ev.KeyID)
		}
	}
	res, err := store.VerifyAudit(ctx, nil)
	if err != nil || !res.Valid {
		t.Fatalf("keyed chain not valid: %+v err=%v", res, err)
	}
	if res.Count != 5 {
		t.Errorf("count = %d, want 5", res.Count)
	}
}

// Tampering a row body fails verification at that seq even under HMAC.
func TestKeyedChainTamperDetected(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)
	store.UseAuditKeyring(mustKeyring(t, "k1", map[string][]byte{"k1": key(1)}))

	for i := 0; i < 4; i++ {
		if _, err := store.AppendAudit(ctx, AuditEvent{Kind: "k"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if _, err := store.db.ExecContext(ctx,
		`UPDATE audit_log SET subject = 'tampered' WHERE seq = 2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err := store.VerifyAudit(ctx, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.FirstBadSeq != 2 || res.Valid {
		t.Errorf("got %+v, want first_bad=2 valid=false", res)
	}
}

// The whole point of keying: an attacker who recomputes a forged chain
// under a DIFFERENT key cannot pass verification under the real keyring.
// (Under the unkeyed chain this same forgery WOULD pass, because the
// algorithm is public.)
func TestForgedChainUnderWrongKeyFails(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)
	realKR := mustKeyring(t, "k1", map[string][]byte{"k1": key(1)})
	store.UseAuditKeyring(realKR)

	for i := 0; i < 3; i++ {
		if _, err := store.AppendAudit(ctx, AuditEvent{Kind: "k", Subject: "orig"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Attacker has DB write access and the public algorithm, but only a
	// WRONG key. They rewrite seq 2's body and recompute the whole tail's
	// prev_hash/hash chain under their forged key.
	forged := key(99)
	prev := genesisHash
	rows, err := store.db.QueryContext(ctx,
		`SELECT seq, ts, kind, actor, subject, decision, payload, key_id FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	type rowT struct {
		ev      AuditEvent
		tsNanos int64
		payload string
	}
	var all []rowT
	for rows.Next() {
		var r rowT
		if err := rows.Scan(&r.ev.Seq, &r.tsNanos, &r.ev.Kind, &r.ev.Actor,
			&r.ev.Subject, &r.ev.Decision, &r.payload, &r.ev.KeyID); err != nil {
			t.Fatalf("scan: %v", err)
		}
		all = append(all, r)
	}
	rows.Close()
	for _, r := range all {
		r.ev.Ts = time.Unix(0, r.tsNanos).UTC()
		r.ev.Payload = json.RawMessage(r.payload)
		if r.ev.Seq == 2 {
			r.ev.Subject = "forged"
		}
		r.ev.PrevHash = prev
		newHash := hashAuditEvent(r.ev, forged)
		if _, err := store.db.ExecContext(ctx,
			store.rebind(`UPDATE audit_log SET subject = ?, prev_hash = ?, hash = ? WHERE seq = ?`),
			r.ev.Subject, r.ev.PrevHash, newHash, r.ev.Seq); err != nil {
			t.Fatalf("rewrite seq %d: %v", r.ev.Seq, err)
		}
		prev = newHash
	}

	// The forged chain is internally consistent under the attacker's key,
	// but verification uses the real keyring -> rejected. The attacker
	// re-MAC'd every row from genesis under the wrong key, so the very
	// first row already fails to verify.
	res, err := store.VerifyAudit(ctx, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Valid || res.FirstBadSeq != 1 {
		t.Errorf("forged chain accepted or wrong seq: %+v", res)
	}
}

// Truncation below an anchored (head, count) is reported as Truncated,
// distinct from a hash mismatch.
func TestAnchoredTruncationDetected(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)
	store.UseAuditKeyring(mustKeyring(t, "k1", map[string][]byte{"k1": key(1)}))

	var head string
	for i := 0; i < 6; i++ {
		ev, err := store.AppendAudit(ctx, AuditEvent{Kind: "k"})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		head = ev.Hash
	}
	anchor := &AuditAnchor{HeadHash: head, Count: 6}

	// Anchored, intact chain: valid, not truncated.
	res, err := store.VerifyAudit(ctx, anchor)
	if err != nil || !res.Valid || res.Truncated {
		t.Fatalf("intact anchored chain: %+v err=%v", res, err)
	}

	// Delete the newest two rows: the remaining chain is internally
	// valid, but it is shorter than the anchor and no longer contains the
	// anchored head.
	if _, err := store.db.ExecContext(ctx, `DELETE FROM audit_log WHERE seq > 4`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	res, err = store.VerifyAudit(ctx, anchor)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Truncated || res.Valid || res.FirstBadSeq != 0 {
		t.Errorf("truncation not reported distinctly: %+v", res)
	}

	// Without the anchor, the truncated tail looks perfectly valid -
	// this is exactly the gap the anchor closes.
	res, err = store.VerifyAudit(ctx, nil)
	if err != nil || !res.Valid {
		t.Fatalf("unanchored truncated chain should look valid: %+v err=%v", res, err)
	}
}

// Rotation: rows written under a retired key still verify after the
// active key is rotated, as long as the retired key stays in the keyring.
func TestKeyRotationVerifiesOldRows(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)

	// Phase 1: active key k1.
	store.UseAuditKeyring(mustKeyring(t, "k1", map[string][]byte{"k1": key(1)}))
	old, err := store.AppendAudit(ctx, AuditEvent{Kind: "old"})
	if err != nil {
		t.Fatalf("append old: %v", err)
	}
	if old.KeyID != "k1" {
		t.Fatalf("old row key_id = %q", old.KeyID)
	}

	// Phase 2: rotate - k2 active, k1 retired but retained.
	store.UseAuditKeyring(mustKeyring(t, "k2", map[string][]byte{
		"k1": key(1),
		"k2": key(2),
	}))
	fresh, err := store.AppendAudit(ctx, AuditEvent{Kind: "new"})
	if err != nil {
		t.Fatalf("append new: %v", err)
	}
	if fresh.KeyID != "k2" {
		t.Fatalf("new row key_id = %q, want k2", fresh.KeyID)
	}

	// Both the k1 row and the k2 row verify under the rotated keyring.
	res, err := store.VerifyAudit(ctx, nil)
	if err != nil || !res.Valid || res.Count != 2 {
		t.Fatalf("rotated keyring verify: %+v err=%v", res, err)
	}

	// Dropping the retired key makes the old row unverifiable -> surfaced
	// as an error, not a silent pass.
	store.UseAuditKeyring(mustKeyring(t, "k2", map[string][]byte{"k2": key(2)}))
	if _, err := store.VerifyAudit(ctx, nil); err == nil {
		t.Errorf("expected error when retired key is dropped")
	}
}

// Legacy boundary: unkeyed rows written before a keyring was attached
// keep verifying (under their "unkeyed" sentinel) alongside keyed rows.
func TestUnkeyedToKeyedBoundary(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)

	legacy, err := store.AppendAudit(ctx, AuditEvent{Kind: "legacy"})
	if err != nil {
		t.Fatalf("append legacy: %v", err)
	}
	if legacy.KeyID != keyIDUnkeyed {
		t.Fatalf("legacy key_id = %q, want %q", legacy.KeyID, keyIDUnkeyed)
	}

	store.UseAuditKeyring(mustKeyring(t, "k1", map[string][]byte{"k1": key(1)}))
	keyed, err := store.AppendAudit(ctx, AuditEvent{Kind: "keyed"})
	if err != nil {
		t.Fatalf("append keyed: %v", err)
	}
	if keyed.KeyID != "k1" {
		t.Fatalf("keyed key_id = %q", keyed.KeyID)
	}

	res, err := store.VerifyAudit(ctx, nil)
	if err != nil || !res.Valid || res.Count != 2 {
		t.Fatalf("mixed chain verify: %+v err=%v", res, err)
	}
}

func TestLoadAuditKeyringFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keyring.json")
	body := `{
	  "active_key_id": "2026-06",
	  "keys": [
	    {"id": "2026-06", "secret": "` + base64.StdEncoding.EncodeToString(key(7)) + `"},
	    {"id": "2026-01", "secret": "` + base64.StdEncoding.EncodeToString(key(8)) + `"}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	kr, err := LoadAuditKeyring(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	id, secret := kr.active()
	if id != "2026-06" || len(secret) != 32 {
		t.Errorf("active = %q (%d bytes)", id, len(secret))
	}
	if _, ok := kr.lookup("2026-01"); !ok {
		t.Errorf("retired key not loadable")
	}
}

func TestLoadAuditKeyringRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"reserved active": `{"active_key_id":"unkeyed","keys":[{"id":"unkeyed","secret":"AAAAAAAAAAAAAAAAAAAAAA=="}]}`,
		"active missing":  `{"active_key_id":"nope","keys":[{"id":"k1","secret":"AAAAAAAAAAAAAAAAAAAAAA=="}]}`,
		"short key":       `{"active_key_id":"k1","keys":[{"id":"k1","secret":"AAA="}]}`,
		"no keys":         `{"active_key_id":"k1","keys":[]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "kr.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := LoadAuditKeyring(path); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestAuditKeyringReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kr.json")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	write(`{"active_key_id":"k1","keys":[{"id":"k1","secret":"` + base64.StdEncoding.EncodeToString(key(1)) + `"}]}`)
	kr, err := LoadAuditKeyring(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Rotate: k2 active, k1 retired. Reload must succeed (k1 retained).
	write(`{"active_key_id":"k2","keys":[
	  {"id":"k1","secret":"` + base64.StdEncoding.EncodeToString(key(1)) + `"},
	  {"id":"k2","secret":"` + base64.StdEncoding.EncodeToString(key(2)) + `"}]}`)
	if err := kr.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if id, _ := kr.active(); id != "k2" {
		t.Errorf("active after reload = %q, want k2", id)
	}

	// A reload that drops the previously-active key (k2) is refused.
	write(`{"active_key_id":"k3","keys":[{"id":"k3","secret":"` + base64.StdEncoding.EncodeToString(key(3)) + `"}]}`)
	if err := kr.Reload(); err == nil {
		t.Errorf("expected reload to refuse dropping previously-active key")
	}

	// Dropping an OLDER retired key (k1) is also refused, even though the
	// active key (k2) is retained — rows MAC'd under k1 would be orphaned.
	write(`{"active_key_id":"k2","keys":[{"id":"k2","secret":"` + base64.StdEncoding.EncodeToString(key(2)) + `"}]}`)
	if err := kr.Reload(); err == nil {
		t.Errorf("expected reload to refuse dropping an older retired key")
	}
	if _, ok := kr.lookup("k1"); !ok {
		t.Errorf("k1 must still be loadable after the refused reload")
	}
}

// The keyring is the trust boundary against a DB-only attacker, so a
// group/world-readable file must be rejected.
func TestLoadAuditKeyringRejectsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kr.json")
	body := `{"active_key_id":"k1","keys":[{"id":"k1","secret":"` + base64.StdEncoding.EncodeToString(key(1)) + `"}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadAuditKeyring(path); err == nil {
		t.Fatal("expected a group/world-readable keyring to be rejected")
	}
}

// Snapshot must deep-copy secrets so a caller can't mutate the live keyring.
func TestAuditKeyringSnapshotIsDeepCopied(t *testing.T) {
	kr, err := NewAuditKeyring("k1", map[string][]byte{"k1": key(1)})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	snap := kr.Snapshot()
	for i := range snap["k1"] {
		snap["k1"][i] ^= 0xff
	}
	if _, live := kr.active(); live[0] == snap["k1"][0] {
		t.Error("mutating the snapshot changed the live keyring secret")
	}
}

// TestMigrationAddsKeyIDToLegacyDB exercises the upgrade path: a database
// created before key_id existed gets the column added with the "unkeyed"
// default, and its pre-existing rows stay verifiable on the legacy path.
func TestMigrationAddsKeyIDToLegacyDB(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.db")

	// Stand up a store, then drop the key_id column to simulate a DB
	// created by an older Omega (SQLite cannot DROP COLUMN before 3.35,
	// modernc supports it; either way this reproduces the pre-migration
	// shape for the ALTER to fix).
	pre, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := pre.AppendAudit(ctx, AuditEvent{Kind: "legacy"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := pre.db.ExecContext(ctx, `ALTER TABLE audit_log DROP COLUMN key_id`); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	_ = pre.Close()

	// Re-open: applyMigrations must re-add key_id without erroring and
	// without disturbing the existing row.
	store, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	rows, err := store.ListAudit(ctx, 0, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 || rows[0].KeyID != keyIDUnkeyed {
		t.Fatalf("legacy row key_id = %q (n=%d), want %q", rows[0].KeyID, len(rows), keyIDUnkeyed)
	}
	if res, err := store.VerifyAudit(ctx, nil); err != nil || !res.Valid {
		t.Fatalf("legacy chain after migration: %+v err=%v", res, err)
	}

	// Re-opening again is a no-op (duplicate-column tolerated).
	store2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen idempotent: %v", err)
	}
	_ = store2.Close()
}

// TestKeyedChainRejectsUnkeyedDowngradeForgery locks the H1 downgrade
// fix: with a keyring loaded, an attacker with DB write access cannot
// forge an unkeyed (plain SHA-256) row chained onto the keyed head. The
// forged row is internally consistent on the legacy path, but VerifyAudit
// rejects it because keying has begun (persisted epoch + contiguous
// prefix), so the chain is reported invalid at the forged seq.
func TestKeyedChainRejectsUnkeyedDowngradeForgery(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)
	store.UseAuditKeyring(mustKeyring(t, "k1", map[string][]byte{"k1": key(1)}))

	var head string
	for i := 0; i < 3; i++ {
		ev, err := store.AppendAudit(ctx, AuditEvent{Kind: "k", Subject: "real"})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		head = ev.Hash
	}
	if res, err := store.VerifyAudit(ctx, nil); err != nil || !res.Valid {
		t.Fatalf("clean keyed chain: %+v err=%v", res, err)
	}

	// Forge an unkeyed row chained onto the real keyed head: key_id =
	// "unkeyed" + a self-computed SHA-256 (no key needed). This is the
	// exact downgrade attack the review demonstrated.
	forged := AuditEvent{
		Ts:       time.Now().UTC(),
		Kind:     "forged",
		Subject:  "attacker",
		Payload:  json.RawMessage("{}"),
		PrevHash: head,
		KeyID:    keyIDUnkeyed,
	}
	var seq int64
	if err := store.db.QueryRowContext(ctx, store.rebind(
		`INSERT INTO audit_log(ts, kind, actor, subject, decision, payload, prev_hash, hash, key_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq`),
		forged.Ts.UnixNano(), forged.Kind, forged.Actor, forged.Subject, forged.Decision,
		string(forged.Payload), forged.PrevHash, "pending", forged.KeyID,
	).Scan(&seq); err != nil {
		t.Fatalf("inject forged row: %v", err)
	}
	forged.Seq = seq
	// Plain SHA-256, computable by anyone — the heart of the downgrade.
	forgedHash := hashAuditEvent(forged, nil)
	if _, err := store.db.ExecContext(ctx, store.rebind(
		`UPDATE audit_log SET hash = ? WHERE seq = ?`), forgedHash, seq); err != nil {
		t.Fatalf("set forged hash: %v", err)
	}

	res, err := store.VerifyAudit(ctx, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Valid || res.FirstBadSeq != seq {
		t.Errorf("downgrade forgery not rejected: %+v (want valid=false first_bad=%d)", res, seq)
	}
}
