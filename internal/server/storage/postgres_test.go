package storage_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/kanywst/omega/internal/server/storage"
)

// pgDSN returns the Postgres DSN to test against, or skips the test if
// unset. CI / local dev is expected to spin a transient container and
// export OMEGA_TEST_POSTGRES_DSN.
func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OMEGA_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("OMEGA_TEST_POSTGRES_DSN not set; skipping Postgres-backed test")
	}
	return dsn
}

// openPostgresStore boots a Store against a freshly-created per-test
// schema so two tests in the same database can't see each other's rows.
// On cleanup the schema is dropped, taking the Store's tables with it.
func openPostgresStore(t *testing.T) *storage.Store {
	t.Helper()
	dsn := pgDSN(t)

	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	schema := "omega_test_" + hex.EncodeToString(buf[:])

	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("admin open: %v", err)
	}
	if _, err := admin.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}

	scopedDSN := withSearchPath(dsn, schema)
	store, err := storage.Open(scopedDSN)
	if err != nil {
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
		t.Fatalf("scoped open: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
		_, _ = admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close()
	})
	return store
}

func withSearchPath(dsn, schema string) string {
	const key = "options=-c%20search_path%3D"
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + key + schema
}

func TestPostgresDomainCRUD(t *testing.T) {
	s := openPostgresStore(t)
	ctx := context.Background()

	d, err := s.CreateDomain(ctx, storage.Domain{Name: "media.news", Description: "news"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.Parent != "media" {
		t.Errorf("parent auto-derive: got %q", d.Parent)
	}

	got, err := s.GetDomain(ctx, "media.news")
	if err != nil || got.Description != "news" {
		t.Fatalf("get: %+v err=%v", got, err)
	}

	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media.news"}); !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists, got %v", err)
	}

	if _, err := s.GetDomain(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPostgresAuditChainAndForward(t *testing.T) {
	s := openPostgresStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := s.AppendAudit(ctx, storage.AuditEvent{Kind: "k", Subject: "s"}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if bad, err := s.VerifyAudit(ctx); err != nil || bad != 0 {
		t.Fatalf("verify clean chain: bad=%d err=%v", bad, err)
	}

	events, err := s.ListAudit(ctx, 0, 10)
	if err != nil || len(events) != 5 {
		t.Fatalf("list: len=%d err=%v", len(events), err)
	}
	if events[0].Seq != 1 || events[4].Seq != 5 {
		t.Errorf("seq range: %d..%d", events[0].Seq, events[4].Seq)
	}

	if seq, err := s.AuditForwardSeq(ctx, "test"); err != nil || seq != 0 {
		t.Fatalf("initial seq: got %d err=%v want 0", seq, err)
	}
	if err := s.SetAuditForwardSeq(ctx, "test", 3); err != nil {
		t.Fatalf("set seq 3: %v", err)
	}
	if err := s.SetAuditForwardSeq(ctx, "test", 5); err != nil {
		t.Fatalf("set seq 5 (upsert): %v", err)
	}
	if seq, _ := s.AuditForwardSeq(ctx, "test"); seq != 5 {
		t.Errorf("after upsert: got %d, want 5", seq)
	}
}
