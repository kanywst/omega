package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func openAuditTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestAppendAuditChainsHashes(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)

	a, err := store.AppendAudit(ctx, AuditEvent{Kind: "k1", Subject: "s1", Decision: "ok"})
	if err != nil {
		t.Fatalf("append 1: %v", err)
	}
	if a.PrevHash != genesisHash {
		t.Errorf("first event prev_hash = %q, want GENESIS", a.PrevHash)
	}
	if a.Seq != 1 {
		t.Errorf("first event seq = %d, want 1", a.Seq)
	}
	if a.Hash == "" || a.Hash == "pending" {
		t.Errorf("first event hash not finalised: %q", a.Hash)
	}

	b, err := store.AppendAudit(ctx, AuditEvent{Kind: "k2", Subject: "s2", Decision: "deny"})
	if err != nil {
		t.Fatalf("append 2: %v", err)
	}
	if b.PrevHash != a.Hash {
		t.Errorf("second prev_hash = %q, want %q", b.PrevHash, a.Hash)
	}
	if b.Seq != 2 {
		t.Errorf("second seq = %d, want 2", b.Seq)
	}
}

func TestVerifyAuditDetectsTamper(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)

	for i := 0; i < 5; i++ {
		if _, err := store.AppendAudit(ctx, AuditEvent{Kind: "k", Subject: "s"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if res, err := store.VerifyAudit(ctx, nil); err != nil || !res.Valid {
		t.Fatalf("clean chain: %+v err=%v", res, err)
	}

	if _, err := store.db.ExecContext(ctx,
		`UPDATE audit_log SET subject = 'tampered' WHERE seq = 3`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err := store.VerifyAudit(ctx, nil)
	if err != nil {
		t.Fatalf("verify after tamper: %v", err)
	}
	if res.FirstBadSeq != 3 {
		t.Errorf("first_bad = %d, want 3", res.FirstBadSeq)
	}
	if res.Valid {
		t.Errorf("tampered chain reported valid")
	}
}

func TestListAuditPagination(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)

	for i := 0; i < 7; i++ {
		if _, err := store.AppendAudit(ctx, AuditEvent{
			Kind:    "k",
			Payload: json.RawMessage(`{"i":` + string(rune('0'+i)) + `}`),
		}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	first, err := store.ListAudit(ctx, 0, 3)
	if err != nil || len(first) != 3 {
		t.Fatalf("first page: len=%d err=%v", len(first), err)
	}
	if first[0].Seq != 1 || first[2].Seq != 3 {
		t.Errorf("first page seqs = %d..%d", first[0].Seq, first[2].Seq)
	}

	second, err := store.ListAudit(ctx, first[2].Seq, 100)
	if err != nil || len(second) != 4 {
		t.Fatalf("second page: len=%d err=%v", len(second), err)
	}
	if second[0].Seq != 4 || second[3].Seq != 7 {
		t.Errorf("second page seqs = %d..%d", second[0].Seq, second[3].Seq)
	}
}

func TestAppendAuditRequiresKind(t *testing.T) {
	ctx := context.Background()
	store := openAuditTestStore(t)
	if _, err := store.AppendAudit(ctx, AuditEvent{}); err == nil {
		t.Fatal("expected error for empty kind")
	}
}
