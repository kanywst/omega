// Package storage holds the Omega control plane persistence layer.
//
// Two backends sit behind the same Store API: a single-file SQLite
// database (the default for development) and Postgres (for HA / shared
// state). Callers pass either a SQLite path (or `file:` URI) or a
// `postgres://...` DSN to Open, and every method behaves the same
// regardless of driver. The driver-specific bits are the schema (column
// types and the autoincrement keyword) and are kept in dialect tables
// in this file.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

// driverKind identifies the backing SQL dialect. Stored on Store so each
// method can select the right schema and SQL phrasing without the caller
// caring which one is in use.
type driverKind string

const (
	driverSQLite   driverKind = "sqlite"
	driverPostgres driverKind = "postgres"
)

type Store struct {
	db           *sql.DB
	driver       driverKind
	leader       leaderState
	auditKeyring *AuditKeyring
	// keyedEpochRecorded short-circuits the per-append audit_meta write
	// once the keying-epoch row exists. Guarded by auditMu (AppendAudit is
	// serialized through it).
	keyedEpochRecorded bool
}

type Domain struct {
	Name        string `json:"name"`
	Parent      string `json:"parent,omitempty"`
	Description string `json:"description,omitempty"`
	// Admins are the principals (SPIFFE IDs) that administer this domain
	// and every domain below it.
	Admins    []string  `json:"admins,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Open returns a Store backed by the driver inferred from spec.
//
//   - "postgres://..." or "postgresql://..." → Postgres (lib/pq), spec is the DSN
//   - anything else → SQLite (modernc.org/sqlite), spec is treated as a file path
//
// SQLite mode keeps the previous behaviour: WAL journal + foreign keys on.
// Postgres mode runs the parallel schema once at Open so a fresh
// database is ready to use.
func Open(spec string) (*Store, error) {
	if isPostgresDSN(spec) {
		return openPostgres(spec)
	}
	return openSQLite(spec)
}

func openSQLite(path string) (*Store, error) {
	// _txlock=immediate takes the write lock at BEGIN, so a transaction
	// that reads before it writes (a parent check, say) cannot be
	// overtaken between its read and its write; busy_timeout makes the
	// second writer wait instead of failing at once with SQLITE_BUSY.
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_txlock=immediate&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	s := &Store{db: db, driver: driverSQLite}
	if err := s.applySchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func openPostgres(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &Store{db: db, driver: driverPostgres}
	if err := s.applySchema(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func isPostgresDSN(spec string) bool {
	return strings.HasPrefix(spec, "postgres://") || strings.HasPrefix(spec, "postgresql://")
}

func (s *Store) Close() error { return s.db.Close() }

// applySchema runs the dialect-appropriate DDL. Each block is idempotent
// (CREATE TABLE IF NOT EXISTS ...), so calling Open against an existing
// database is a no-op.
func (s *Store) applySchema(ctx context.Context) error {
	for _, ddl := range s.schemaDDL() {
		if _, err := s.db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
	}
	return s.applyMigrations(ctx)
}

// applyMigrations runs forward, idempotent ALTERs that the CREATE TABLE
// IF NOT EXISTS blocks above cannot retrofit onto a database created by
// an earlier Omega version. Each statement is safe to run repeatedly: on
// a fresh DB the column already exists (it is in schemaDDL), so SQLite's
// "duplicate column name" and Postgres's IF NOT EXISTS make it a no-op.
func (s *Store) applyMigrations(ctx context.Context) error {
	for _, ddl := range s.migrationDDL() {
		if _, err := s.db.ExecContext(ctx, ddl); err != nil {
			// SQLite has no ADD COLUMN IF NOT EXISTS; tolerate the
			// duplicate-column error so re-running Open is a no-op.
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("apply migration: %w", err)
		}
	}
	return nil
}

// migrationDDL adds the audit_log.key_id column to databases created
// before the HMAC keyring landed. Existing rows default to the "unkeyed"
// sentinel so VerifyAudit checks them on the legacy SHA-256 path.
func (s *Store) migrationDDL() []string {
	if s.driver == driverPostgres {
		return []string{
			`ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS key_id TEXT NOT NULL DEFAULT 'unkeyed'`,
		}
	}
	return []string{
		`ALTER TABLE audit_log ADD COLUMN key_id TEXT NOT NULL DEFAULT 'unkeyed'`,
	}
}

func (s *Store) schemaDDL() []string {
	if s.driver == driverPostgres {
		return []string{
			`CREATE TABLE IF NOT EXISTS domains (
			   name        TEXT    PRIMARY KEY,
			   parent      TEXT    NOT NULL DEFAULT '',
			   description TEXT    NOT NULL DEFAULT '',
			   created_at  BIGINT  NOT NULL
			 )`,
			`CREATE INDEX IF NOT EXISTS idx_domains_parent ON domains(parent)`,
			`CREATE TABLE IF NOT EXISTS groups (
			   domain      TEXT   NOT NULL,
			   name        TEXT   NOT NULL,
			   description TEXT   NOT NULL DEFAULT '',
			   created_at  BIGINT NOT NULL,
			   PRIMARY KEY (domain, name)
			 )`,
			`CREATE TABLE IF NOT EXISTS group_members (
			   domain     TEXT   NOT NULL,
			   grp        TEXT   NOT NULL,
			   principal  TEXT   NOT NULL,
			   expires_at BIGINT NOT NULL DEFAULT 0,
			   PRIMARY KEY (domain, grp, principal)
			 )`,
			`CREATE TABLE IF NOT EXISTS domain_admins (
			   domain     TEXT NOT NULL,
			   principal  TEXT NOT NULL,
			   PRIMARY KEY (domain, principal)
			 )`,
			`CREATE TABLE IF NOT EXISTS audit_log (
			   seq        BIGSERIAL PRIMARY KEY,
			   ts         BIGINT  NOT NULL,
			   kind       TEXT    NOT NULL,
			   actor      TEXT    NOT NULL DEFAULT '',
			   subject    TEXT    NOT NULL DEFAULT '',
			   decision   TEXT    NOT NULL DEFAULT '',
			   payload    TEXT    NOT NULL DEFAULT '',
			   prev_hash  TEXT    NOT NULL,
			   hash       TEXT    NOT NULL UNIQUE,
			   key_id     TEXT    NOT NULL DEFAULT 'unkeyed'
			 )`,
			`CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_log(subject)`,
			`CREATE TABLE IF NOT EXISTS audit_forward_state (
			   name        TEXT   PRIMARY KEY,
			   last_seq    BIGINT NOT NULL,
			   updated_at  BIGINT NOT NULL
			 )`,
			`CREATE TABLE IF NOT EXISTS audit_meta (
			   k  TEXT   PRIMARY KEY,
			   v  BIGINT NOT NULL
			 )`,
		}
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS domains (
		   name        TEXT    PRIMARY KEY,
		   parent      TEXT    NOT NULL DEFAULT '',
		   description TEXT    NOT NULL DEFAULT '',
		   created_at  INTEGER NOT NULL
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_domains_parent ON domains(parent)`,
		`CREATE TABLE IF NOT EXISTS groups (
		   domain      TEXT   NOT NULL,
		   name        TEXT   NOT NULL,
		   description TEXT   NOT NULL DEFAULT '',
		   created_at  BIGINT NOT NULL,
		   PRIMARY KEY (domain, name)
		 )`,
		`CREATE TABLE IF NOT EXISTS group_members (
		   domain     TEXT   NOT NULL,
		   grp        TEXT   NOT NULL,
		   principal  TEXT   NOT NULL,
		   expires_at BIGINT NOT NULL DEFAULT 0,
		   PRIMARY KEY (domain, grp, principal)
		 )`,
		`CREATE TABLE IF NOT EXISTS domain_admins (
		   domain     TEXT NOT NULL,
		   principal  TEXT NOT NULL,
		   PRIMARY KEY (domain, principal)
		 )`,
		`CREATE TABLE IF NOT EXISTS audit_log (
		   seq        INTEGER PRIMARY KEY AUTOINCREMENT,
		   ts         INTEGER NOT NULL,
		   kind       TEXT    NOT NULL,
		   actor      TEXT    NOT NULL DEFAULT '',
		   subject    TEXT    NOT NULL DEFAULT '',
		   decision   TEXT    NOT NULL DEFAULT '',
		   payload    TEXT    NOT NULL DEFAULT '',
		   prev_hash  TEXT    NOT NULL,
		   hash       TEXT    NOT NULL UNIQUE,
		   key_id     TEXT    NOT NULL DEFAULT 'unkeyed'
		 )`,
		`CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_log(kind)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_log(subject)`,
		`CREATE TABLE IF NOT EXISTS audit_forward_state (
		   name        TEXT    PRIMARY KEY,
		   last_seq    INTEGER NOT NULL,
		   updated_at  INTEGER NOT NULL
		 )`,
		`CREATE TABLE IF NOT EXISTS audit_meta (
		   k  TEXT    PRIMARY KEY,
		   v  INTEGER NOT NULL
		 )`,
	}
}

// rebind translates `?`-style placeholders to the driver's native form.
// SQLite and Postgres differ here: lib/pq wants $1, $2, … instead of ?.
// Keeping the canonical SQL `?`-styled and rebinding once per call
// avoids duplicating every query string per dialect.
func (s *Store) rebind(query string) string {
	if s.driver != driverPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '?' {
			n++
			fmt.Fprintf(&b, "$%d", n)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// isUniqueViolation reports whether err comes from inserting a row that
// collides with an existing primary key / unique index. The text differs
// across drivers (`UNIQUE constraint failed` for SQLite vs the SQLSTATE
// 23505 surface from lib/pq), so we match either marker.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint") ||
		strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key value")
}
