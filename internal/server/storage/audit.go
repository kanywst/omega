package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sync"
	"time"
)

// AuditEvent is one entry in the tamper-evident audit chain.
//
// Each row's Hash covers (Seq, Ts, Kind, Actor, Subject, Decision, Payload,
// PrevHash). PrevHash references the previous row's Hash, so any tampering
// with an earlier row invalidates every subsequent Hash. KeyID records the
// HMAC key the row was MAC'd under (or the "unkeyed" sentinel for the
// legacy plain-SHA-256 chain), so VerifyAudit can select the right key.
type AuditEvent struct {
	Seq      int64           `json:"seq"`
	Ts       time.Time       `json:"ts"`
	Kind     string          `json:"kind"`
	Actor    string          `json:"actor,omitempty"`
	Subject  string          `json:"subject,omitempty"`
	Decision string          `json:"decision,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
	KeyID    string          `json:"key_id,omitempty"`
}

const genesisHash = "GENESIS"

// AuditAnchor is an externally-published checkpoint of the audit chain:
// at the time it was taken, the chain held Count rows and the newest
// row's hash was HeadHash. Passing it to VerifyAudit lets the verifier
// detect tail truncation below the checkpoint, which an unanchored walk
// cannot see (deleting the newest N rows leaves a shorter, still-valid
// chain). HeadHash == genesisHash with Count == 0 anchors an empty chain.
type AuditAnchor struct {
	HeadHash string
	Count    int64
}

// AuditVerification is the result of walking the chain. FirstBadSeq is
// the seq of the first row whose prev_hash linkage or MAC does not match
// (0 when the walk is clean). Truncated is set only when an AuditAnchor
// was supplied and the live tail is shorter than, or has diverged below,
// the anchored checkpoint. Valid is true only when neither failure
// occurred. Count and HeadHash describe the live chain and are suitable
// for publishing as the next anchor.
type AuditVerification struct {
	Valid       bool
	FirstBadSeq int64
	Truncated   bool
	Count       int64
	HeadHash    string
}

// UseAuditKeyring attaches an HMAC keyring to the store. When set, new
// audit rows are MAC'd under the keyring's active key; when nil (the
// default) the chain stays unkeyed for backward compatibility. Call once
// before serving traffic.
func (s *Store) UseAuditKeyring(kr *AuditKeyring) { s.auditKeyring = kr }

// auditMu serialises Append calls so the prev_hash lookup and INSERT
// happen atomically. SQLite's BEGIN IMMEDIATE would also serialise, but
// a process-local mutex keeps the contention error-free.
//
// NOTE: this mutex is process-local. Multi-replica Postgres deployments
// need an external leader-election layer before two writers can be
// active concurrently - otherwise interleaved INSERTs can break the
// hash chain. Single-writer SQLite and single-writer Postgres are fine.
var auditMu sync.Mutex

// AppendAudit writes one event to the chain. Seq, Ts, PrevHash and Hash are
// computed by the store; callers fill the rest. The stored event is
// returned, including the assigned Seq and Hash.
func (s *Store) AppendAudit(ctx context.Context, ev AuditEvent) (AuditEvent, error) {
	if !s.IsLeader() {
		return AuditEvent{}, ErrNotLeader
	}
	if ev.Kind == "" {
		return AuditEvent{}, errors.New("audit: kind is required")
	}
	if ev.Ts.IsZero() {
		ev.Ts = time.Now().UTC()
	}
	if ev.Payload == nil {
		ev.Payload = json.RawMessage("{}")
	}

	auditMu.Lock()
	defer auditMu.Unlock()

	// Select the key the row is MAC'd under. With no keyring the chain
	// stays unkeyed (legacy SHA-256) and records the "unkeyed" sentinel;
	// with a keyring the active key signs the row. A node must never MAC
	// under a key_id it cannot also load for verify, which holds here
	// because the active key is by construction present in the keyring.
	keyID := keyIDUnkeyed
	var key []byte
	if s.auditKeyring != nil {
		keyID, key = s.auditKeyring.active()
	}
	ev.KeyID = keyID

	prev, err := s.lastAuditHash(ctx)
	if err != nil {
		return AuditEvent{}, err
	}
	ev.PrevHash = prev

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditEvent{}, fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// `INSERT ... RETURNING seq` works on both SQLite (>= 3.35) and
	// Postgres, so we avoid driver-specific LastInsertId() (which lib/pq
	// does not support for serial columns).
	var seq int64
	insertSQL := s.rebind(
		`INSERT INTO audit_log(ts, kind, actor, subject, decision, payload, prev_hash, hash, key_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq`,
	)
	if err := tx.QueryRowContext(ctx, insertSQL,
		ev.Ts.UnixNano(), ev.Kind, ev.Actor, ev.Subject, ev.Decision,
		string(ev.Payload), ev.PrevHash, "pending", ev.KeyID,
	).Scan(&seq); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: insert: %w", err)
	}
	ev.Seq = seq
	ev.Hash = hashAuditEvent(ev, key)

	if _, err := tx.ExecContext(ctx,
		s.rebind(`UPDATE audit_log SET hash = ? WHERE seq = ?`),
		ev.Hash, seq,
	); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: update hash: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: commit: %w", err)
	}
	return ev, nil
}

func (s *Store) lastAuditHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return genesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("audit: last hash: %w", err)
	}
	return hash, nil
}

// ListAudit returns events with Seq > since, oldest first, capped at limit.
// limit <= 0 defaults to 100; values above 1000 are clamped.
func (s *Store) ListAudit(ctx context.Context, since int64, limit int) ([]AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.QueryContext(ctx,
		s.rebind(
			`SELECT seq, ts, kind, actor, subject, decision, payload, prev_hash, hash, key_id
			 FROM audit_log WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
		),
		since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	out := make([]AuditEvent, 0, limit)
	for rows.Next() {
		var (
			ev      AuditEvent
			tsNanos int64
			payload string
		)
		if err := rows.Scan(&ev.Seq, &tsNanos, &ev.Kind, &ev.Actor, &ev.Subject,
			&ev.Decision, &payload, &ev.PrevHash, &ev.Hash, &ev.KeyID); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		ev.Ts = time.Unix(0, tsNanos).UTC()
		ev.Payload = json.RawMessage(payload)
		out = append(out, ev)
	}
	return out, rows.Err()
}

// VerifyAudit walks the entire chain and recomputes each row's MAC under
// the key recorded in its key_id (the keyring's matching key, or the
// unkeyed SHA-256 path for "unkeyed" rows). The first row whose prev_hash
// linkage or MAC fails sets FirstBadSeq.
//
// anchor is optional. When non-nil it is an externally-published
// checkpoint (head hash + row count); VerifyAudit then reports
// Truncated when the live tail has fewer rows than the checkpoint or no
// longer contains the anchored head hash — i.e. the newest rows were
// deleted below the anchor. A clean, untruncated walk yields Valid=true.
func (s *Store) VerifyAudit(ctx context.Context, anchor *AuditAnchor) (AuditVerification, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, ts, kind, actor, subject, decision, payload, prev_hash, hash, key_id
		 FROM audit_log ORDER BY seq ASC`,
	)
	if err != nil {
		return AuditVerification{}, fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()

	res := AuditVerification{HeadHash: genesisHash}
	prev := genesisHash
	sawAnchorHead := anchor != nil && anchor.HeadHash == genesisHash
	for rows.Next() {
		var (
			ev      AuditEvent
			tsNanos int64
			payload string
		)
		if err := rows.Scan(&ev.Seq, &tsNanos, &ev.Kind, &ev.Actor, &ev.Subject,
			&ev.Decision, &payload, &ev.PrevHash, &ev.Hash, &ev.KeyID); err != nil {
			return AuditVerification{}, fmt.Errorf("audit: verify scan: %w", err)
		}
		ev.Ts = time.Unix(0, tsNanos).UTC()
		ev.Payload = json.RawMessage(payload)

		if res.FirstBadSeq == 0 {
			key, err := s.auditKeyFor(ev.KeyID)
			if err != nil {
				return AuditVerification{}, fmt.Errorf("audit: verify seq %d: %w", ev.Seq, err)
			}
			if ev.PrevHash != prev || hashAuditEvent(ev, key) != ev.Hash {
				res.FirstBadSeq = ev.Seq
			}
		}
		if anchor != nil && ev.Hash == anchor.HeadHash {
			sawAnchorHead = true
		}
		res.Count++
		res.HeadHash = ev.Hash
		prev = ev.Hash
	}
	if err := rows.Err(); err != nil {
		return AuditVerification{}, fmt.Errorf("audit: verify rows: %w", err)
	}

	if anchor != nil && res.FirstBadSeq == 0 {
		if res.Count < anchor.Count || !sawAnchorHead {
			res.Truncated = true
		}
	}
	res.Valid = res.FirstBadSeq == 0 && !res.Truncated
	return res, nil
}

// auditKeyFor returns the HMAC key for a row's key_id. The unkeyed
// sentinel yields a nil key (legacy SHA-256). For any other id the
// keyring must hold the key, otherwise the row cannot be verified and the
// caller surfaces that as an error rather than silently passing.
func (s *Store) auditKeyFor(keyID string) ([]byte, error) {
	if keyID == "" || keyID == keyIDUnkeyed {
		return nil, nil
	}
	if s.auditKeyring == nil {
		return nil, fmt.Errorf("row MAC'd under key %q but no keyring is loaded", keyID)
	}
	key, ok := s.auditKeyring.lookup(keyID)
	if !ok {
		return nil, fmt.Errorf("row MAC'd under key %q which is not in the keyring", keyID)
	}
	return key, nil
}

// hashAuditEvent computes a row's chained MAC. With a nil key it is the
// legacy unkeyed SHA-256 (backward compatible); with a key it is
// HMAC-SHA-256, which a DB-only attacker cannot forge without the key.
func hashAuditEvent(ev AuditEvent, key []byte) string {
	var h hash.Hash
	if len(key) == 0 {
		h = sha256.New()
	} else {
		h = hmac.New(sha256.New, key)
	}
	fmt.Fprintf(h, "%d|%d|%s|%s|%s|%s|", ev.Seq, ev.Ts.UnixNano(), ev.Kind, ev.Actor, ev.Subject, ev.Decision)
	h.Write([]byte(ev.Payload))
	h.Write([]byte("|"))
	h.Write([]byte(ev.PrevHash))
	return hex.EncodeToString(h.Sum(nil))
}
