package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SCIMUser is a user an external identity provider provisions over SCIM.
// Principal is the SPIFFE ID its group memberships are granted to.
type SCIMUser struct {
	ID          string
	UserName    string
	ExternalID  string
	DisplayName string
	Active      bool
	Principal   string
	Created     time.Time
	Modified    time.Time
}

// SCIMGroup is a group an identity provider provisions over SCIM. It
// owns the Omega group Domain:Group, whose members are the SPIFFE IDs of
// its active SCIM members.
type SCIMGroup struct {
	ID          string
	DisplayName string
	ExternalID  string
	Domain      string
	Group       string
	Members     []string // SCIM user ids
	Created     time.Time
	Modified    time.Time
}

// ErrUnknownMember is returned when a group names a user that does not exist.
var ErrUnknownMember = errors.New("unknown member")

// ErrSCIMManaged is returned when the Omega group API would change a
// group an identity provider owns.
var ErrSCIMManaged = errors.New("group is provisioned over SCIM")

// refuseManaged fails with ErrSCIMManaged when a provider owns the group.
// It runs inside the caller's transaction, after any group lock, so the
// check and the write cannot be split by a concurrent SCIM create.
func (s *Store) refuseManaged(ctx context.Context, tx *sql.Tx, domain, name string) error {
	var idp string
	err := tx.QueryRowContext(ctx, s.rebind(`SELECT idp FROM scim_groups WHERE domain = ? AND grp = ?`), domain, name).Scan(&idp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("query scim group: %w", err)
	}
	return fmt.Errorf("%w by %q", ErrSCIMManaged, idp)
}

// querier is satisfied by *sql.DB and *sql.Tx.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// SCIMTx is one transaction over an identity provider's SCIM state, or
// a read-only view of it (SCIMRead).
type SCIMTx struct {
	s       *Store
	tx      *sql.Tx // nil for a read-only view
	q       querier
	ctx     context.Context
	idp     string
	touched map[string]bool // group ids whose Omega membership must be rebuilt
}

// SCIMRead runs fn against the provider's SCIM state without a write
// transaction or the audit lock, so a provider's list and get calls
// never hold up writes. fn must only read.
func (s *Store) SCIMRead(ctx context.Context, idp string, fn func(*SCIMTx) error) error {
	return fn(&SCIMTx{s: s, q: s.db, ctx: ctx, idp: idp})
}

// SCIM runs fn in one transaction. When fn returns an event with a Kind,
// that event is appended to the audit chain in the same transaction, so
// a provisioning change and its record commit together or not at all.
// Before commit, every Omega group fn affected is rebuilt from its SCIM
// members.
func (s *Store) SCIM(ctx context.Context, idp string, fn func(*SCIMTx) (AuditEvent, error)) (AuditEvent, error) {
	if !s.IsLeader() {
		return AuditEvent{}, ErrNotLeader
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	t := &SCIMTx{s: s, tx: tx, q: tx, ctx: ctx, idp: idp, touched: map[string]bool{}}
	ev, err := fn(t)
	if err != nil {
		return AuditEvent{}, err
	}
	ids := make([]string, 0, len(t.touched))
	for id := range t.touched {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := t.syncGroup(id); err != nil {
			return AuditEvent{}, err
		}
	}
	if ev.Kind != "" {
		if ev, err = s.appendAuditTx(ctx, tx, ev); err != nil {
			return AuditEvent{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return AuditEvent{}, fmt.Errorf("commit: %w", err)
	}
	if ev.Kind != "" {
		s.auditCommitted()
	}
	return ev, nil
}

// SCIMManaged reports whether an identity provider owns the group, in
// which case only SCIM may change it.
func (s *Store) SCIMManaged(ctx context.Context, domain, name string) (string, bool, error) {
	var idp string
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT idp FROM scim_groups WHERE domain = ? AND grp = ?`), domain, name).Scan(&idp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("query scim group: %w", err)
	}
	return idp, true, nil
}

func newSCIMID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

const scimUserCols = `id, user_name, external_id, display_name, active, principal, created_at, updated_at`

func scanSCIMUser(sc interface{ Scan(...any) error }) (SCIMUser, error) {
	var (
		u                 SCIMUser
		active            int64
		created, modified int64
	)
	if err := sc.Scan(&u.ID, &u.UserName, &u.ExternalID, &u.DisplayName, &active, &u.Principal, &created, &modified); err != nil {
		return SCIMUser{}, err
	}
	u.Active = active != 0
	u.Created, u.Modified = time.Unix(0, created).UTC(), time.Unix(0, modified).UTC()
	return u, nil
}

// GetUser returns one user.
func (t *SCIMTx) GetUser(id string) (SCIMUser, error) {
	u, err := scanSCIMUser(t.q.QueryRowContext(t.ctx, t.s.rebind(`SELECT `+scimUserCols+` FROM scim_users WHERE idp = ? AND id = ?`), t.idp, id))
	if errors.Is(err, sql.ErrNoRows) {
		return SCIMUser{}, ErrNotFound
	}
	if err != nil {
		return SCIMUser{}, fmt.Errorf("query scim user: %w", err)
	}
	return u, nil
}

// ListUsers returns one page of users (offset from 0, at most limit),
// optionally only those whose attr ("userName", compared without regard
// to case, or "externalId") equals value, and how many match in total.
func (t *SCIMTx) ListUsers(attr, value string, offset, limit int) ([]SCIMUser, int, error) {
	where, args := ` WHERE idp = ?`, []any{t.idp}
	switch attr {
	case "":
	case "userName":
		where, args = where+` AND user_name_lc = ?`, append(args, strings.ToLower(value))
	case "externalId":
		where, args = where+` AND external_id = ?`, append(args, value)
	default:
		return nil, 0, fmt.Errorf("cannot filter users by %q", attr)
	}
	var total int
	if err := t.q.QueryRowContext(t.ctx, t.s.rebind(`SELECT COUNT(*) FROM scim_users`+where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scim users: %w", err)
	}
	rows, err := t.q.QueryContext(t.ctx, t.s.rebind(`SELECT `+scimUserCols+` FROM scim_users`+where+` ORDER BY created_at, id LIMIT ? OFFSET ?`), append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("query scim users: %w", err)
	}
	defer rows.Close()
	var out []SCIMUser
	for rows.Next() {
		u, err := scanSCIMUser(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan scim user: %w", err)
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// CreateUser inserts u under a new id. A userName already in use, in any
// letter case, fails with ErrAlreadyExists.
func (t *SCIMTx) CreateUser(u SCIMUser) (SCIMUser, error) {
	now := time.Now().UTC()
	u.ID, u.Created, u.Modified = newSCIMID(), now, now
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`INSERT INTO scim_users(idp, id, user_name, user_name_lc, external_id, display_name, active, principal, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
		t.idp, u.ID, u.UserName, strings.ToLower(u.UserName), u.ExternalID, u.DisplayName, boolInt(u.Active), u.Principal, now.UnixNano(), now.UnixNano(),
	); err != nil {
		if isUniqueViolation(err) {
			return SCIMUser{}, ErrAlreadyExists
		}
		return SCIMUser{}, fmt.Errorf("insert scim user: %w", err)
	}
	return u, nil
}

// ReplaceUser stores u over the user with its id. When the principal or
// the active flag changes, the user's groups are rebuilt.
func (t *SCIMTx) ReplaceUser(u SCIMUser) (SCIMUser, error) {
	prev, err := t.GetUser(u.ID)
	if err != nil {
		return SCIMUser{}, err
	}
	u.Created, u.Modified = prev.Created, time.Now().UTC()
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`UPDATE scim_users SET user_name = ?, user_name_lc = ?, external_id = ?, display_name = ?, active = ?, principal = ?, updated_at = ?
		WHERE idp = ? AND id = ?`),
		u.UserName, strings.ToLower(u.UserName), u.ExternalID, u.DisplayName, boolInt(u.Active), u.Principal, u.Modified.UnixNano(), t.idp, u.ID,
	); err != nil {
		if isUniqueViolation(err) {
			return SCIMUser{}, ErrAlreadyExists
		}
		return SCIMUser{}, fmt.Errorf("update scim user: %w", err)
	}
	if prev.Principal != u.Principal || prev.Active != u.Active {
		if err := t.touchGroupsOf(u.ID); err != nil {
			return SCIMUser{}, err
		}
	}
	return u, nil
}

// DeleteUser removes a user and its group memberships.
func (t *SCIMTx) DeleteUser(id string) error {
	if _, err := t.GetUser(id); err != nil {
		return err
	}
	if err := t.touchGroupsOf(id); err != nil {
		return err
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM scim_members WHERE idp = ? AND user_id = ?`), t.idp, id); err != nil {
		return fmt.Errorf("delete scim memberships: %w", err)
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM scim_users WHERE idp = ? AND id = ?`), t.idp, id); err != nil {
		return fmt.Errorf("delete scim user: %w", err)
	}
	return nil
}

func (t *SCIMTx) touchGroupsOf(userID string) error {
	rows, err := t.q.QueryContext(t.ctx, t.s.rebind(`SELECT group_id FROM scim_members WHERE idp = ? AND user_id = ?`), t.idp, userID)
	if err != nil {
		return fmt.Errorf("query scim memberships: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return err
		}
		t.touched[g] = true
	}
	return rows.Err()
}

const scimGroupCols = `id, display_name, external_id, domain, grp, created_at, updated_at`

// GetGroup returns one group with its member ids.
func (t *SCIMTx) GetGroup(id string) (SCIMGroup, error) {
	gs, _, err := t.listGroups(` AND id = ?`, []any{id}, 0, 1, true)
	if err != nil {
		return SCIMGroup{}, err
	}
	if len(gs) == 0 {
		return SCIMGroup{}, ErrNotFound
	}
	return gs[0], nil
}

// ListGroups returns one page of groups (offset from 0, at most limit),
// optionally only those whose attr ("displayName" or "externalId")
// equals value, and how many match in total. Members are loaded only
// when withMembers is set.
func (t *SCIMTx) ListGroups(attr, value string, offset, limit int, withMembers bool) ([]SCIMGroup, int, error) {
	switch attr {
	case "":
		return t.listGroups("", nil, offset, limit, withMembers)
	case "displayName":
		return t.listGroups(` AND display_name = ?`, []any{value}, offset, limit, withMembers)
	case "externalId":
		return t.listGroups(` AND external_id = ?`, []any{value}, offset, limit, withMembers)
	}
	return nil, 0, fmt.Errorf("cannot filter groups by %q", attr)
}

func (t *SCIMTx) listGroups(where string, args []any, offset, limit int, withMembers bool) ([]SCIMGroup, int, error) {
	args = append([]any{t.idp}, args...)
	var total int
	if err := t.q.QueryRowContext(t.ctx, t.s.rebind(`SELECT COUNT(*) FROM scim_groups WHERE idp = ?`+where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scim groups: %w", err)
	}
	rows, err := t.q.QueryContext(t.ctx, t.s.rebind(`SELECT `+scimGroupCols+` FROM scim_groups WHERE idp = ?`+where+` ORDER BY created_at, id LIMIT ? OFFSET ?`), append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("query scim groups: %w", err)
	}
	var out []SCIMGroup
	for rows.Next() {
		var (
			g                 SCIMGroup
			created, modified int64
		)
		if err := rows.Scan(&g.ID, &g.DisplayName, &g.ExternalID, &g.Domain, &g.Group, &created, &modified); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("scan scim group: %w", err)
		}
		g.Created, g.Modified = time.Unix(0, created).UTC(), time.Unix(0, modified).UTC()
		out = append(out, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if !withMembers || len(out) == 0 {
		return out, total, nil
	}
	ids := make([]any, len(out))
	idx := make(map[string]int, len(out))
	for i, g := range out {
		ids[i], idx[g.ID] = g.ID, i
	}
	mrows, err := t.q.QueryContext(t.ctx, t.s.rebind(`SELECT group_id, user_id FROM scim_members WHERE idp = ? AND group_id IN (?`+strings.Repeat(", ?", len(ids)-1)+`) ORDER BY group_id, user_id`), append([]any{t.idp}, ids...)...)
	if err != nil {
		return nil, 0, fmt.Errorf("query scim members: %w", err)
	}
	defer mrows.Close()
	for mrows.Next() {
		var gid, uid string
		if err := mrows.Scan(&gid, &uid); err != nil {
			return nil, 0, err
		}
		out[idx[gid]].Members = append(out[idx[gid]].Members, uid)
	}
	return out, total, mrows.Err()
}

// CreateGroup creates g and the Omega group g.Domain:g.Group it owns.
// The domain must exist, and the Omega group name must be free.
func (t *SCIMTx) CreateGroup(g SCIMGroup) (SCIMGroup, error) {
	if err := ValidateGroupName(g.Group); err != nil {
		return SCIMGroup{}, err
	}
	if err := t.s.lockDomain(t.ctx, t.tx, g.Domain, "FOR SHARE"); err != nil {
		return SCIMGroup{}, err
	}
	now := time.Now().UTC()
	g.ID, g.Created, g.Modified = newSCIMID(), now, now
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`INSERT INTO groups(domain, name, description, created_at) VALUES (?, ?, ?, ?)`),
		g.Domain, g.Group, "provisioned by "+t.idp+" over SCIM", now.UnixNano()); err != nil {
		if isUniqueViolation(err) {
			return SCIMGroup{}, ErrAlreadyExists
		}
		return SCIMGroup{}, fmt.Errorf("insert group: %w", err)
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM group_members WHERE domain = ? AND grp = ?`), g.Domain, g.Group); err != nil {
		return SCIMGroup{}, fmt.Errorf("clear members: %w", err)
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`INSERT INTO scim_groups(idp, id, display_name, external_id, domain, grp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		t.idp, g.ID, g.DisplayName, g.ExternalID, g.Domain, g.Group, now.UnixNano(), now.UnixNano()); err != nil {
		return SCIMGroup{}, fmt.Errorf("insert scim group: %w", err)
	}
	if err := t.setMembers(g.ID, g.Members); err != nil {
		return SCIMGroup{}, err
	}
	return t.GetGroup(g.ID)
}

// ReplaceGroup stores g's display name, external id and members over the
// group with its id. A new g.Group renames the Omega group.
func (t *SCIMTx) ReplaceGroup(g SCIMGroup) (SCIMGroup, error) {
	prev, err := t.GetGroup(g.ID)
	if err != nil {
		return SCIMGroup{}, err
	}
	if g.Group != prev.Group {
		if err := ValidateGroupName(g.Group); err != nil {
			return SCIMGroup{}, err
		}
		if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`UPDATE groups SET name = ? WHERE domain = ? AND name = ?`), g.Group, prev.Domain, prev.Group); err != nil {
			if isUniqueViolation(err) {
				return SCIMGroup{}, ErrAlreadyExists
			}
			return SCIMGroup{}, fmt.Errorf("rename group: %w", err)
		}
		if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM group_members WHERE domain = ? AND grp = ?`), prev.Domain, prev.Group); err != nil {
			return SCIMGroup{}, fmt.Errorf("clear members: %w", err)
		}
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`UPDATE scim_groups SET display_name = ?, external_id = ?, grp = ?, updated_at = ? WHERE idp = ? AND id = ?`),
		g.DisplayName, g.ExternalID, g.Group, time.Now().UTC().UnixNano(), t.idp, g.ID); err != nil {
		return SCIMGroup{}, fmt.Errorf("update scim group: %w", err)
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM scim_members WHERE idp = ? AND group_id = ?`), t.idp, g.ID); err != nil {
		return SCIMGroup{}, fmt.Errorf("clear scim members: %w", err)
	}
	if err := t.setMembers(g.ID, g.Members); err != nil {
		return SCIMGroup{}, err
	}
	return t.GetGroup(g.ID)
}

// PatchMembers adds and removes members of a group.
func (t *SCIMTx) PatchMembers(groupID string, add, remove []string) error {
	if _, err := t.GetGroup(groupID); err != nil {
		return err
	}
	for _, u := range remove {
		if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM scim_members WHERE idp = ? AND group_id = ? AND user_id = ?`), t.idp, groupID, u); err != nil {
			return fmt.Errorf("remove scim member: %w", err)
		}
	}
	t.touched[groupID] = true
	return t.setMembers(groupID, add)
}

// RemoveAllMembers empties a group.
func (t *SCIMTx) RemoveAllMembers(groupID string) error {
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM scim_members WHERE idp = ? AND group_id = ?`), t.idp, groupID); err != nil {
		return fmt.Errorf("clear scim members: %w", err)
	}
	t.touched[groupID] = true
	return nil
}

func (t *SCIMTx) setMembers(groupID string, users []string) error {
	for _, u := range users {
		if _, err := t.GetUser(u); err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("%w: %q", ErrUnknownMember, u)
			}
			return err
		}
		if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`INSERT INTO scim_members(idp, group_id, user_id) VALUES (?, ?, ?) ON CONFLICT (idp, group_id, user_id) DO NOTHING`),
			t.idp, groupID, u); err != nil {
			return fmt.Errorf("insert scim member: %w", err)
		}
	}
	t.touched[groupID] = true
	return nil
}

// DeleteGroup removes a group and the Omega group it owns.
func (t *SCIMTx) DeleteGroup(id string) error {
	g, err := t.GetGroup(id)
	if err != nil {
		return err
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM group_members WHERE domain = ? AND grp = ?`, []any{g.Domain, g.Group}},
		{`DELETE FROM groups WHERE domain = ? AND name = ?`, []any{g.Domain, g.Group}},
		{`DELETE FROM scim_members WHERE idp = ? AND group_id = ?`, []any{t.idp, id}},
		{`DELETE FROM scim_groups WHERE idp = ? AND id = ?`, []any{t.idp, id}},
	} {
		if _, err := t.q.ExecContext(t.ctx, t.s.rebind(q.sql), q.args...); err != nil {
			return fmt.Errorf("delete scim group: %w", err)
		}
	}
	delete(t.touched, id)
	return nil
}

// syncGroup rebuilds the Omega group's members from the SCIM group's
// active members. An inactive user is in no group.
func (t *SCIMTx) syncGroup(id string) error {
	g, err := t.GetGroup(id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`DELETE FROM group_members WHERE domain = ? AND grp = ?`), g.Domain, g.Group); err != nil {
		return fmt.Errorf("clear members: %w", err)
	}
	if _, err := t.q.ExecContext(t.ctx, t.s.rebind(`INSERT INTO group_members(domain, grp, principal, expires_at)
		SELECT DISTINCT CAST(? AS TEXT), CAST(? AS TEXT), u.principal, 0 FROM scim_members m JOIN scim_users u ON u.idp = m.idp AND u.id = m.user_id
		WHERE m.idp = ? AND m.group_id = ? AND u.active = 1`),
		g.Domain, g.Group, t.idp, id); err != nil {
		return fmt.Errorf("rebuild members: %w", err)
	}
	return nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
