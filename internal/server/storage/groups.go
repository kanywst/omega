package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// ErrHasGroups is returned when deleting a domain that still owns groups.
var ErrHasGroups = errors.New("domain still owns groups")

var groupName = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)

// Group is a named set of principals owned by a domain. Its policy
// identity is Group::"<domain>:<name>".
type Group struct {
	Domain      string        `json:"domain"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Members     []GroupMember `json:"members,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
}

// ID is the group's policy identifier.
func (g Group) ID() string { return g.Domain + ":" + g.Name }

// GroupMember is one principal in a group. A zero ExpiresAt never expires.
type GroupMember struct {
	Principal string    `json:"principal"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Active reports whether the membership is in force at t.
func (m GroupMember) Active(t time.Time) bool {
	return m.ExpiresAt.IsZero() || t.Before(m.ExpiresAt)
}

// ValidateGroupName checks a group name: lowercase letters, digits, '-'
// and '_', starting and ending with a letter or digit.
func ValidateGroupName(name string) error {
	if len(name) > 63 || !groupName.MatchString(name) {
		return fmt.Errorf("group name %q must be 1-63 lowercase letters, digits, '-' or '_', starting and ending with a letter or digit", name)
	}
	return nil
}

// CreateGroup adds a group to an existing domain.
func (s *Store) CreateGroup(ctx context.Context, g Group) (Group, error) {
	if !s.IsLeader() {
		return Group{}, ErrNotLeader
	}
	if err := ValidateGroupName(g.Name); err != nil {
		return Group{}, err
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Group{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.lockDomain(ctx, tx, g.Domain, "FOR SHARE"); err != nil {
		return Group{}, err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM group_members WHERE domain = ? AND grp = ?`), g.Domain, g.Name); err != nil {
		return Group{}, fmt.Errorf("clear members: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		s.rebind(`INSERT INTO groups(domain, name, description, created_at) VALUES (?, ?, ?, ?)`),
		g.Domain, g.Name, g.Description, g.CreatedAt.UnixNano(),
	); err != nil {
		if isUniqueViolation(err) {
			return Group{}, ErrAlreadyExists
		}
		return Group{}, fmt.Errorf("insert group: %w", err)
	}
	g.Members = nil
	return g, tx.Commit()
}

// DeleteGroup removes a group and its memberships.
func (s *Store) DeleteGroup(ctx context.Context, domain, name string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM groups WHERE domain = ? AND name = ?`), domain, name)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM group_members WHERE domain = ? AND grp = ?`), domain, name); err != nil {
		return fmt.Errorf("delete members: %w", err)
	}
	return tx.Commit()
}

// PutGroupMember adds principal to a group, or updates its expiry.
func (s *Store) PutGroupMember(ctx context.Context, domain, name string, m GroupMember) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	q := `SELECT 1 FROM groups WHERE domain = ? AND name = ?`
	if s.driver == driverPostgres {
		q += " FOR SHARE"
	}
	var one int
	if err := tx.QueryRowContext(ctx, s.rebind(q), domain, name).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("query group: %w", err)
	}
	var exp int64
	if !m.ExpiresAt.IsZero() {
		exp = m.ExpiresAt.UnixNano()
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM group_members WHERE domain = ? AND grp = ? AND principal = ?`), domain, name, m.Principal); err != nil {
		return fmt.Errorf("replace member: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		s.rebind(`INSERT INTO group_members(domain, grp, principal, expires_at) VALUES (?, ?, ?, ?)`),
		domain, name, m.Principal, exp,
	); err != nil {
		return fmt.Errorf("insert member: %w", err)
	}
	return tx.Commit()
}

// RemoveGroupMember removes principal from a group.
func (s *Store) RemoveGroupMember(ctx context.Context, domain, name, principal string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	res, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM group_members WHERE domain = ? AND grp = ? AND principal = ?`), domain, name, principal)
	if err != nil {
		return fmt.Errorf("delete member: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetGroup returns one group with its members.
func (s *Store) GetGroup(ctx context.Context, domain, name string) (Group, error) {
	groups, err := s.listGroups(ctx, domain, name)
	if err != nil {
		return Group{}, err
	}
	if len(groups) == 0 {
		return Group{}, ErrNotFound
	}
	return groups[0], nil
}

// ListGroups returns a domain's groups, or every group when domain is "".
func (s *Store) ListGroups(ctx context.Context, domain string) ([]Group, error) {
	return s.listGroups(ctx, domain, "")
}

func (s *Store) listGroups(ctx context.Context, domain, name string) ([]Group, error) {
	q, args := `SELECT domain, name, description, created_at FROM groups`, []any{}
	switch {
	case domain != "" && name != "":
		q, args = q+` WHERE domain = ? AND name = ?`, []any{domain, name}
	case domain != "":
		q, args = q+` WHERE domain = ?`, []any{domain}
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(q+` ORDER BY domain, name`), args...)
	if err != nil {
		return nil, fmt.Errorf("query groups: %w", err)
	}
	var out []Group
	for rows.Next() {
		var (
			g       Group
			created int64
		)
		if err := rows.Scan(&g.Domain, &g.Name, &g.Description, &created); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan group: %w", err)
		}
		g.CreatedAt = time.Unix(0, created).UTC()
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	members, err := s.groupMembers(ctx, domain, name)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Members = members[out[i].ID()]
	}
	return out, nil
}

func (s *Store) groupMembers(ctx context.Context, domain, name string) (map[string][]GroupMember, error) {
	q, args := `SELECT domain, grp, principal, expires_at FROM group_members`, []any{}
	switch {
	case domain != "" && name != "":
		q, args = q+` WHERE domain = ? AND grp = ?`, []any{domain, name}
	case domain != "":
		q, args = q+` WHERE domain = ?`, []any{domain}
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(q), args...)
	if err != nil {
		return nil, fmt.Errorf("query members: %w", err)
	}
	defer rows.Close()
	out := map[string][]GroupMember{}
	for rows.Next() {
		var (
			d, g, p string
			exp     int64
		)
		if err := rows.Scan(&d, &g, &p, &exp); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		m := GroupMember{Principal: p}
		if exp != 0 {
			m.ExpiresAt = time.Unix(0, exp).UTC()
		}
		out[d+":"+g] = append(out[d+":"+g], m)
	}
	for _, v := range out {
		sort.Slice(v, func(i, j int) bool { return v[i].Principal < v[j].Principal })
	}
	return out, rows.Err()
}
