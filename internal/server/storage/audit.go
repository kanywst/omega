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

	// Record the keying epoch: the seq of the first keyed row. ON CONFLICT
	// DO NOTHING means only that first keyed write sets it; later writes
	// are no-ops. VerifyAudit uses it to reject any unkeyed row at or
	// after keying began, which a forged downgrade cannot evade. The
	// in-memory flag skips this write after the row is known to exist, so
	// only the first keyed append per process pays for it.
	if s.auditKeyring != nil && !s.keyedEpochRecorded {
		if _, err := tx.ExecContext(ctx,
			s.rebind(`INSERT INTO audit_meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO NOTHING`),
			auditMetaKeyedFromSeq, seq,
		); err != nil {
			return AuditEvent{}, fmt.Errorf("audit: record keying epoch: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return AuditEvent{}, fmt.Errorf("audit: commit: %w", err)
	}
	// After a committed keyed append the epoch row is guaranteed present
	// (we just inserted it or it already existed), so later appends can
	// skip the audit_meta write. Set only post-commit so a rolled-back tx
	// doesn't leave the flag ahead of the persisted row.
	if s.auditKeyring != nil {
		s.keyedEpochRecorded = true
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
// When a keyring is loaded, VerifyAudit additionally rejects downgrade
// forgeries — an attacker writing an unkeyed (plain SHA-256) row chained
// onto the keyed head. Two complementary checks catch this:
//   - the persisted keying epoch: any unkeyed row at or after the seq
//     where keying began is forged;
//   - contiguous-prefix: once a keyed row has been seen in the walk, any
//     later unkeyed row is a downgrade.
//
// Legacy rows written before keying was enabled (seq below the epoch)
// stay verifiable on the SHA-256 path, so the legitimate
// legacy-then-enable-keying migration still verifies.
//
// anchor is optional. When non-nil it is an externally-published
// checkpoint (head hash + row count); VerifyAudit then reports
// Truncated when the live tail has fewer rows than the checkpoint or no
// longer contains the anchored head hash — i.e. the newest rows were
// deleted below the anchor. A clean, untruncated walk yields Valid=true.
func (s *Store) VerifyAudit(ctx context.Context, anchor *AuditAnchor) (AuditVerification, error) {
	var (
		keyedFrom int64
		hasEpoch  bool
	)
	if s.auditKeyring != nil {
		var err error
		keyedFrom, hasEpoch, err = s.auditKeyedFromSeq(ctx)
		if err != nil {
			return AuditVerification{}, err
		}
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT seq, ts, kind, actor, subject, decision, payload, prev_hash, hash, key_id
		 FROM audit_log ORDER BY seq ASC`,
	)
	if err != nil {
		return AuditVerification{}, fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()

	// Take one consistent snapshot of the keyring up front so per-row key
	// lookups are lock-free and unaffected by a concurrent SIGHUP rotation
	// mid-walk.
	var keySnap map[string][]byte
	if s.auditKeyring != nil {
		keySnap = s.auditKeyring.Snapshot()
	}

	res := AuditVerification{HeadHash: genesisHash}
	prev := genesisHash
	sawAnchorHead := anchor != nil && anchor.HeadHash == genesisHash
	sawKeyed := false
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
		isUnkeyed := ev.KeyID == "" || ev.KeyID == keyIDUnkeyed

		if res.FirstBadSeq == 0 {
			switch {
			case s.auditKeyring != nil && isUnkeyed && hasEpoch && ev.Seq >= keyedFrom:
				// Downgrade: an unkeyed row at/after keying began. A
				// forged row chained onto the keyed head lands here.
				res.FirstBadSeq = ev.Seq
			case s.auditKeyring != nil && isUnkeyed && sawKeyed:
				// Downgrade (defense in depth): unkeyed row after a keyed
				// row breaks the contiguous keyed suffix.
				res.FirstBadSeq = ev.Seq
			default:
				// isUnkeyed rows that reach here are legitimate legacy
				// (pre-keying) rows → nil key → legacy SHA-256. Keyed rows
				// resolve their secret from the snapshot.
				var key []byte
				resolvable := true
				if !isUnkeyed {
					k, ok := keySnap[ev.KeyID]
					if s.auditKeyring == nil || !ok {
						// A keyed row whose key can't be resolved (no keyring
						// loaded, or the id isn't in it) is unverifiable —
						// report it as the first bad row rather than aborting
						// the whole walk with a 500, which a DB-write attacker
						// could otherwise trigger to DoS verification.
						res.FirstBadSeq = ev.Seq
						resolvable = false
					} else {
						key = k
					}
				}
				if resolvable {
					want := macAuditEvent(ev, key)
					got, derr := hex.DecodeString(ev.Hash)
					if ev.PrevHash != prev || derr != nil || !hmac.Equal(want, got) {
						res.FirstBadSeq = ev.Seq
					}
				}
			}
		}
		if !isUnkeyed {
			sawKeyed = true
		}
		if anchor != nil && ev.Hash == anchor.HeadHash {
			sawAnchorHead = true
		}
		res.Count++
		res.HeadHash = ev.Hash
		prev = ev.Hash
		if res.FirstBadSeq != 0 {
			// The chain is broken at this seq; rows past a tampered/forged
			// row can't be trusted or meaningfully counted, so stop walking
			// (valid is already false). The anchor truncation check below is
			// moot once first_bad_seq is set.
			break
		}
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

// auditMetaKeyedFromSeq is the audit_meta key under which the seq of the
// first keyed row is recorded. It marks the boundary below which legacy
// unkeyed rows are legitimate and at/above which an unkeyed row is forged.
const auditMetaKeyedFromSeq = "keyed_from_seq"

// auditKeyedFromSeq reads the persisted keying epoch. ok is false when no
// keyed row has ever been written (so the whole chain is legacy/unkeyed).
func (s *Store) auditKeyedFromSeq(ctx context.Context) (seq int64, ok bool, err error) {
	err = s.db.QueryRowContext(ctx,
		s.rebind(`SELECT v FROM audit_meta WHERE k = ?`), auditMetaKeyedFromSeq,
	).Scan(&seq)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("audit: read keying epoch: %w", err)
	}
	return seq, true, nil
}

// macAuditEvent computes a row's chained MAC as raw bytes.
//
// With a nil key it is the legacy unkeyed SHA-256 over
// (seq|ts|kind|actor|subject|decision|payload|prev_hash) — byte-for-byte
// identical to the original chain, so default (no-keyring) mode stays
// compatible.
//
// With a key it is HMAC-SHA-256 over the same fields PLUS the
// domain-separated key_id. Folding key_id into the keyed MAC authenticates
// the selector that picks the verify key: an attacker cannot swap a keyed
// row's key_id (e.g. downgrade it to "unkeyed" to force the legacy
// SHA-256 path) without invalidating the MAC.
func macAuditEvent(ev AuditEvent, key []byte) []byte {
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
	if len(key) != 0 {
		h.Write([]byte("|keyid|"))
		h.Write([]byte(ev.KeyID))
	}
	return h.Sum(nil)
}

// hashAuditEvent is the hex-encoded MAC stored in audit_log.hash.
func hashAuditEvent(ev AuditEvent, key []byte) string {
	return hex.EncodeToString(macAuditEvent(ev, key))
}
