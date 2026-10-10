package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	// ErrParentNotFound is returned when a domain's parent does not exist.
	ErrParentNotFound = errors.New("parent domain does not exist")
	// ErrHasChildren is returned when deleting a domain that still has
	// child domains.
	ErrHasChildren = errors.New("domain has child domains")
)

// domainLabel is one dot-separated label of a domain name. Labels are
// lowercase so a domain maps to exactly one SPIFFE ID path prefix.
var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`)

// ValidateDomainName checks a dotted domain name such as "media.news".
func ValidateDomainName(name string) error {
	if name == "" {
		return errors.New("domain name is required")
	}
	if len(name) > 253 {
		return errors.New("domain name is longer than 253 characters")
	}
	for _, l := range strings.Split(name, ".") {
		if !domainLabel.MatchString(l) {
			return fmt.Errorf("domain label %q must be lowercase letters, digits, '-' or '_', and start and end with a letter or digit", l)
		}
	}
	return nil
}

// ParentOf returns the parent of a dotted domain name, "" for a
// top-level domain.
func ParentOf(name string) string {
	if i := strings.LastIndex(name, "."); i > 0 {
		return name[:i]
	}
	return ""
}

// CreateDomain inserts a domain and its initial admins. The parent is
// derived from the name and must already exist.
func (s *Store) CreateDomain(ctx context.Context, d Domain) (Domain, error) {
	if !s.IsLeader() {
		return Domain{}, ErrNotLeader
	}
	if err := ValidateDomainName(d.Name); err != nil {
		return Domain{}, err
	}
	parent := ParentOf(d.Name)
	if d.Parent != "" && d.Parent != parent {
		return Domain{}, fmt.Errorf("parent %q does not match the parent %q implied by the name", d.Parent, parent)
	}
	d.Parent = parent
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	d.Admins = dedupe(d.Admins)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Domain{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if parent != "" {
		var one int
		err := tx.QueryRowContext(ctx, s.rebind(`SELECT 1 FROM domains WHERE name = ?`), parent).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return Domain{}, fmt.Errorf("%w: %q", ErrParentNotFound, parent)
		}
		if err != nil {
			return Domain{}, fmt.Errorf("query parent: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		s.rebind(`INSERT INTO domains(name, parent, description, created_at) VALUES (?, ?, ?, ?)`),
		d.Name, d.Parent, d.Description, d.CreatedAt.UnixNano(),
	); err != nil {
		if isUniqueViolation(err) {
			return Domain{}, ErrAlreadyExists
		}
		return Domain{}, fmt.Errorf("insert domain: %w", err)
	}
	for _, a := range d.Admins {
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO domain_admins(domain, principal) VALUES (?, ?)`), d.Name, a); err != nil {
			return Domain{}, fmt.Errorf("insert admin: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Domain{}, fmt.Errorf("commit: %w", err)
	}
	return d, nil
}

// DeleteDomain removes a leaf domain and its admin grants.
func (s *Store) DeleteDomain(ctx context.Context, name string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var children int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM domains WHERE parent = ?`), name).Scan(&children); err != nil {
		return fmt.Errorf("count children: %w", err)
	}
	if children > 0 {
		return ErrHasChildren
	}
	res, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM domains WHERE name = ?`), name)
	if err != nil {
		return fmt.Errorf("delete domain: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM domain_admins WHERE domain = ?`), name); err != nil {
		return fmt.Errorf("delete admins: %w", err)
	}
	return tx.Commit()
}

// AddDomainAdmin grants principal admin rights on domain. Granting an
// existing admin is a no-op.
func (s *Store) AddDomainAdmin(ctx context.Context, domain, principal string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	if _, err := s.GetDomain(ctx, domain); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO domain_admins(domain, principal) VALUES (?, ?)`), domain, principal)
	if err != nil && !isUniqueViolation(err) {
		return fmt.Errorf("insert admin: %w", err)
	}
	return nil
}

// RemoveDomainAdmin revokes principal's admin rights on domain.
func (s *Store) RemoveDomainAdmin(ctx context.Context, domain, principal string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	res, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM domain_admins WHERE domain = ? AND principal = ?`), domain, principal)
	if err != nil {
		return fmt.Errorf("delete admin: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) GetDomain(ctx context.Context, name string) (Domain, error) {
	var (
		d            Domain
		createdNanos int64
	)
	err := s.db.QueryRowContext(ctx,
		s.rebind(`SELECT name, parent, description, created_at FROM domains WHERE name = ?`),
		name,
	).Scan(&d.Name, &d.Parent, &d.Description, &createdNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, ErrNotFound
	}
	if err != nil {
		return Domain{}, fmt.Errorf("query domain: %w", err)
	}
	d.CreatedAt = time.Unix(0, createdNanos).UTC()
	admins, err := s.adminsByDomain(ctx, name)
	if err != nil {
		return Domain{}, err
	}
	d.Admins = admins[name]
	return d, nil
}

func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT name, parent, description, created_at FROM domains ORDER BY name`,
	)
	if err != nil {
		return nil, fmt.Errorf("query domains: %w", err)
	}
	defer rows.Close()

	var out []Domain
	for rows.Next() {
		var (
			d            Domain
			createdNanos int64
		)
		if err := rows.Scan(&d.Name, &d.Parent, &d.Description, &createdNanos); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		d.CreatedAt = time.Unix(0, createdNanos).UTC()
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	admins, err := s.adminsByDomain(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Admins = admins[out[i].Name]
	}
	return out, nil
}

// adminsByDomain returns admins grouped by domain, for one domain or,
// when domain is "", for all of them.
func (s *Store) adminsByDomain(ctx context.Context, domain string) (map[string][]string, error) {
	q, args := `SELECT domain, principal FROM domain_admins`, []any{}
	if domain != "" {
		q, args = s.rebind(q+` WHERE domain = ?`), []any{domain}
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query admins: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var d, p string
		if err := rows.Scan(&d, &p); err != nil {
			return nil, fmt.Errorf("scan admin: %w", err)
		}
		out[d] = append(out[d], p)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out, rows.Err()
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
