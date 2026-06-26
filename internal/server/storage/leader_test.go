package storage_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/kanywst/omega/internal/server/storage"
)

// randomLeaderKey picks a per-test advisory-lock key so two tests in
// the same Postgres can race for leadership independently - using the
// default key would make the second test contend with whatever the
// first one left holding the lock at goroutine teardown.
func randomLeaderKey(t *testing.T) int64 {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return int64(binary.LittleEndian.Uint64(b[:]) & 0x7fffffffffffffff)
}

// openLeaderStore opens a fresh Store against the same DSN openPostgresStore
// uses. We do NOT scope it to a per-test schema - advisory locks live at
// the Postgres cluster level, not per-schema, so two Stores fighting for
// the same key is exactly the scenario we want to exercise.
func openLeaderStore(t *testing.T) *storage.Store {
	t.Helper()
	dsn := pgDSN(t)
	store, err := storage.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func waitFor(t *testing.T, name string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", name)
}

// TestPostgresLeaderElectionSingleHolder boots two Stores racing for the
// same key and asserts only one becomes leader. Then it cancels the
// leader's context and asserts the follower promotes.
func TestPostgresLeaderElectionSingleHolder(t *testing.T) {
	if pgDSN(t) == "" {
		return
	}
	s1 := openLeaderStore(t)
	s2 := openLeaderStore(t)
	key := randomLeaderKey(t)
	cfg := storage.LeaderConfig{Key: key, PollInterval: 50 * time.Millisecond}

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	if err := s1.StartLeaderElection(ctx1, cfg); err != nil {
		t.Fatalf("s1 start: %v", err)
	}
	if err := s2.StartLeaderElection(ctx2, cfg); err != nil {
		t.Fatalf("s2 start: %v", err)
	}

	waitFor(t, "one leader", 3*time.Second, func() bool {
		return s1.IsLeader() != s2.IsLeader()
	})
	if s1.IsLeader() == s2.IsLeader() {
		t.Fatalf("expected exactly one leader, got s1=%v s2=%v", s1.IsLeader(), s2.IsLeader())
	}

	// Identify leader/follower and ensure follower's writes are rejected.
	leader, follower := s1, s2
	if !s1.IsLeader() {
		leader, follower = s2, s1
	}
	if _, err := follower.AppendAudit(context.Background(), storage.AuditEvent{Kind: "k"}); !errors.Is(err, storage.ErrNotLeader) {
		t.Fatalf("follower AppendAudit: want ErrNotLeader, got %v", err)
	}
	if _, err := leader.AppendAudit(context.Background(), storage.AuditEvent{Kind: "k"}); err != nil {
		t.Fatalf("leader AppendAudit: %v", err)
	}

	// Releasing the leader's election context should free the lock and
	// let the follower pick it up on its next poll.
	if leader == s1 {
		cancel1()
	} else {
		cancel2()
	}

	waitFor(t, "follower promotion", 5*time.Second, func() bool {
		return follower.IsLeader()
	})
}

// TestPostgresLeaderElectionRequiresPostgres confirms calling
// StartLeaderElection on a SQLite Store fails fast at startup.
func TestPostgresLeaderElectionRequiresPostgres(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(dir + "/omega.db")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer store.Close()

	if !store.IsLeader() {
		t.Fatalf("sqlite store should always report leader=true, got false")
	}
	err = store.StartLeaderElection(context.Background(), storage.LeaderConfig{})
	if err == nil {
		t.Fatalf("expected error starting election on sqlite, got nil")
	}
}

// silenceUnusedSQL keeps the database/sql import meaningful even if a
// future refactor drops it; lib/pq is always needed for the DSN test.
var _ = sql.ErrNoRows
