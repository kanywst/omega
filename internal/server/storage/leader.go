package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// ErrNotLeader is returned by write methods (AppendAudit, CreateDomain)
// when the Store has been told to gate writes on Postgres advisory-lock
// leadership and this process is currently a follower. Callers in the
// HTTP layer translate it to a 503 so writers can retry against the
// leader without changing semantics.
var ErrNotLeader = errors.New("storage: not leader")

// LeaderConfig tunes Postgres advisory-lock leader election. Key is the
// `pg_try_advisory_lock` argument shared by every replica that competes
// for leadership of one Omega cluster - anything dedicated to Omega is
// fine; the default 0x0e6a3a0001 ("omega 0001") is used when zero.
type LeaderConfig struct {
	Key          int64
	PollInterval time.Duration
}

// DefaultLeaderKey is the advisory-lock key Omega uses when LeaderConfig
// leaves Key zero. It encodes "omega 0001" as a recognisable hex value;
// operators running Omega next to other apps that use advisory locks
// can override it via the CLI to avoid clashes.
const DefaultLeaderKey = int64(0x0e6a3a0001)

// leaderState carries the runtime fields. Kept on Store directly so
// every method that wants to gate on leadership can read s.IsLeader().
type leaderState struct {
	enabled  bool        // set when StartLeaderElection was called
	isLeader atomic.Bool // updated by the election goroutine
}

// IsLeader reports whether this process currently holds the advisory
// lock. SQLite (single-writer by definition) and Postgres without
// leader election always return true so existing callers that have not
// opted into HA see no behavioural change.
func (s *Store) IsLeader() bool {
	if !s.leader.enabled {
		return true
	}
	return s.leader.isLeader.Load()
}

// SetLeaderForTest forces the leader bit without running the election
// goroutine. It is intended for tests in other packages that need to
// exercise leader-gated code paths without booting Postgres; production
// code must go through StartLeaderElection.
func (s *Store) SetLeaderForTest(enabled, isLeader bool) {
	s.leader.enabled = enabled
	s.leader.isLeader.Store(isLeader)
}

// StartLeaderElection runs an advisory-lock contention loop until ctx
// is cancelled. Only meaningful for the Postgres driver; calling it on
// SQLite is an error so misuse fails loudly at startup.
//
// The election goroutine takes one dedicated *sql.Conn out of the pool
// so the lock is held at session scope (Postgres advisory locks are
// session-scoped, not transaction-scoped). When the connection drops -
// process crash, Postgres restart, network blip - the lock is released
// by the server and another replica will pick it up on its next poll.
//
// Once the lock is acquired the goroutine blocks on a Ping loop so a
// silent connection failure is detected promptly; on Ping failure the
// dedicated conn is closed, isLeader flips back to false, and the
// outer loop tries to reacquire.
func (s *Store) StartLeaderElection(ctx context.Context, cfg LeaderConfig) error {
	if s.driver != driverPostgres {
		return fmt.Errorf("leader election: only supported on Postgres (driver=%s)", s.driver)
	}
	if cfg.Key == 0 {
		cfg.Key = DefaultLeaderKey
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	s.leader.enabled = true
	s.leader.isLeader.Store(false)
	go s.runLeaderElection(ctx, cfg)
	return nil
}

func (s *Store) runLeaderElection(ctx context.Context, cfg LeaderConfig) {
	t := time.NewTicker(cfg.PollInterval)
	defer t.Stop()

	var held *sql.Conn
	// release explicitly unlocks before returning the conn to the pool.
	// `*sql.Conn.Close()` only returns the connection to the pool - the
	// underlying TCP session, and therefore the session-scoped advisory
	// lock, would otherwise stay held until the pool decides to recycle
	// it. Without an explicit pg_advisory_unlock no other replica can
	// take the leadership when this one steps down.
	release := func() {
		if held == nil {
			return
		}
		// Use a fresh background context so a cancelled ctx (the usual
		// reason we're releasing) does not skip the unlock.
		uctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := held.ExecContext(uctx, "SELECT pg_advisory_unlock($1)", cfg.Key); err != nil {
			slog.Warn("leader election: pg_advisory_unlock failed", "err", err)
		}
		_ = held.Close()
		held = nil
		s.leader.isLeader.Store(false)
	}
	defer release()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		// Already leader: verify the dedicated conn is still alive.
		if held != nil {
			if err := held.PingContext(ctx); err != nil {
				slog.Warn("leader election: leader ping failed, releasing", "err", err)
				release()
				continue
			}
			continue
		}

		// Not leader: try to acquire on a fresh dedicated conn.
		conn, err := s.db.Conn(ctx)
		if err != nil {
			slog.Warn("leader election: get dedicated conn failed", "err", err)
			continue
		}
		var ok bool
		if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", cfg.Key).Scan(&ok); err != nil {
			slog.Warn("leader election: try_advisory_lock failed", "err", err)
			_ = conn.Close()
			continue
		}
		if !ok {
			_ = conn.Close()
			continue
		}
		held = conn
		s.leader.isLeader.Store(true)
		slog.Info("leader election: acquired", "key", cfg.Key)
	}
}
