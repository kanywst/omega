package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var policyIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)

// ValidatePolicyID checks a stored policy id: the same shape as a group
// name, so it carries no '.' or '/' and cannot be read as a file name.
func ValidatePolicyID(id string) error {
	if len(id) > 63 || !policyIDPattern.MatchString(id) {
		return fmt.Errorf("policy id %q must be 1-63 lowercase letters, digits, '-' or '_', starting and ending with a letter or digit", id)
	}
	return nil
}

// Policy is a Cedar policy document stored in the database. Version
// starts at 1 and grows by one on every update; together with Digest,
// the SHA-256 of Text, it forms the ETag a conditional update or delete
// must match.
type Policy struct {
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	Version   int64     `json:"version"`
	Digest    string    `json:"digest"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ETag is the policy's entity tag, quoted as HTTP sends it.
func (p Policy) ETag() string {
	return `"` + strconv.FormatInt(p.Version, 10) + "-" + p.Digest + `"`
}

// PolicyDigest is the hex SHA-256 of a policy's Cedar text.
func PolicyDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

const policyColumns = `id, text, version, created_by, created_at, updated_by, updated_at`

func scanPolicy(sc interface{ Scan(...any) error }) (Policy, error) {
	var (
		p                Policy
		created, updated int64
	)
	if err := sc.Scan(&p.ID, &p.Text, &p.Version, &p.CreatedBy, &created, &p.UpdatedBy, &updated); err != nil {
		return Policy{}, err
	}
	// Computed on every read rather than stored, so a text edited in the
	// database shows a digest the audit chain never recorded.
	p.Digest = PolicyDigest(p.Text)
	p.CreatedAt = time.Unix(0, created).UTC()
	p.UpdatedAt = time.Unix(0, updated).UTC()
	return p, nil
}

// ListPolicies returns every stored policy, ordered by id.
func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+policyColumns+` FROM policies ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query policies: %w", err)
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPolicy returns one stored policy.
func (s *Store) GetPolicy(ctx context.Context, id string) (Policy, error) {
	p, err := scanPolicy(s.db.QueryRowContext(ctx, s.rebind(`SELECT `+policyColumns+` FROM policies WHERE id = ?`), id))
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("query policy: %w", err)
	}
	return p, nil
}

// PolicyChange decides a write to one stored policy. It gets the row as
// it is (nil: absent), read under the row lock, and returns the row to
// write (nil: delete it) and the audit event that records the change.
// Returning an error aborts the write.
type PolicyChange func(cur *Policy) (next *Policy, ev AuditEvent, err error)

// ChangePolicy applies change to the stored policy id in one
// transaction with its audit row, so the change and its record commit
// together or not at all. The row written gets its version, digest and
// timestamps from the store. It returns the row as written (nil after a
// delete) and the appended event.
func (s *Store) ChangePolicy(ctx context.Context, id string, change PolicyChange) (*Policy, AuditEvent, error) {
	if !s.IsLeader() {
		return nil, AuditEvent{}, ErrNotLeader
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, AuditEvent{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := `SELECT ` + policyColumns + ` FROM policies WHERE id = ?`
	if s.driver == driverPostgres {
		q += " FOR UPDATE"
	}
	var cur *Policy
	p, err := scanPolicy(tx.QueryRowContext(ctx, s.rebind(q), id))
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, AuditEvent{}, fmt.Errorf("query policy: %w", err)
	default:
		cur = &p
	}
	next, ev, err := change(cur)
	if err != nil {
		return nil, AuditEvent{}, err
	}
	if ev.Kind == "" {
		return nil, AuditEvent{}, errors.New("policy change: audit kind is required")
	}
	now := time.Now().UTC()
	switch {
	case next == nil && cur == nil:
		return nil, AuditEvent{}, ErrNotFound
	case next == nil:
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM policies WHERE id = ?`), id); err != nil {
			return nil, AuditEvent{}, fmt.Errorf("delete policy: %w", err)
		}
	case cur == nil:
		w := Policy{ID: id, Text: next.Text, Version: 1, Digest: PolicyDigest(next.Text), CreatedBy: next.UpdatedBy, CreatedAt: now, UpdatedBy: next.UpdatedBy, UpdatedAt: now}
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO policies(`+policyColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`),
			w.ID, w.Text, w.Version, w.CreatedBy, w.CreatedAt.UnixNano(), w.UpdatedBy, w.UpdatedAt.UnixNano()); err != nil {
			if isUniqueViolation(err) {
				return nil, AuditEvent{}, ErrAlreadyExists
			}
			return nil, AuditEvent{}, fmt.Errorf("insert policy: %w", err)
		}
		next = &w
	default:
		w := *cur
		w.Text, w.Version, w.Digest, w.UpdatedBy, w.UpdatedAt = next.Text, cur.Version+1, PolicyDigest(next.Text), next.UpdatedBy, now
		if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE policies SET text = ?, version = ?, updated_by = ?, updated_at = ? WHERE id = ?`),
			w.Text, w.Version, w.UpdatedBy, w.UpdatedAt.UnixNano(), id); err != nil {
			return nil, AuditEvent{}, fmt.Errorf("update policy: %w", err)
		}
		next = &w
	}
	if ev, err = s.appendAuditTx(ctx, tx, ev); err != nil {
		return nil, AuditEvent{}, err
	}
	if err := tx.Commit(); err != nil {
		return nil, AuditEvent{}, fmt.Errorf("commit: %w", err)
	}
	s.auditCommitted()
	return next, ev, nil
}
