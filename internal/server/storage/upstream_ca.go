package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// UpstreamCA is one CA an external issuer (Vault PKI, step-ca, AWS
// Private CA) published, as Omega last saw it. KeptUntil is zero while
// the issuer still publishes the CA; once the issuer stops, Omega keeps
// trusting it from KeptAt until KeptUntil (--upstream-ca-grace).
type UpstreamCA struct {
	DER       []byte
	KeptAt    time.Time
	KeptUntil time.Time
}

// Fingerprint is the hex SHA-256 of the DER certificate.
func (c UpstreamCA) Fingerprint() string {
	sum := sha256.Sum256(c.DER)
	return hex.EncodeToString(sum[:])
}

// UpstreamCAs returns the CAs stored for one trust domain and issuer
// backend, in fingerprint order. Every replica reads them, so all of
// them serve the CAs one replica kept through an issuer's rotation.
func (s *Store) UpstreamCAs(ctx context.Context, trustDomain, backend string) ([]UpstreamCA, error) {
	rows, err := s.db.QueryContext(ctx,
		s.rebind(`SELECT der, kept_at, kept_until FROM upstream_cas WHERE trust_domain = ? AND backend = ? ORDER BY fingerprint`),
		trustDomain, backend)
	if err != nil {
		return nil, fmt.Errorf("query upstream cas: %w", err)
	}
	defer rows.Close()
	var out []UpstreamCA
	for rows.Next() {
		var (
			der           []byte
			keptAt, until int64
		)
		if err := rows.Scan(&der, &keptAt, &until); err != nil {
			return nil, fmt.Errorf("scan upstream ca: %w", err)
		}
		c := UpstreamCA{DER: der}
		if keptAt != 0 {
			c.KeptAt = time.Unix(0, keptAt).UTC()
		}
		if until != 0 {
			c.KeptUntil = time.Unix(0, until).UTC()
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReplaceUpstreamCAs replaces the CAs stored for one trust domain and
// issuer backend with cas, in one transaction. Like every write, it is
// refused with ErrNotLeader on a replica that is not the leader.
func (s *Store) ReplaceUpstreamCAs(ctx context.Context, trustDomain, backend string, cas []UpstreamCA) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM upstream_cas WHERE trust_domain = ? AND backend = ?`), trustDomain, backend); err != nil {
		return fmt.Errorf("clear upstream cas: %w", err)
	}
	for _, c := range cas {
		if len(c.DER) == 0 {
			return errors.New("upstream ca has no certificate")
		}
		var keptAt, until int64
		if !c.KeptUntil.IsZero() {
			keptAt, until = c.KeptAt.UnixNano(), c.KeptUntil.UnixNano()
		}
		if _, err := tx.ExecContext(ctx,
			s.rebind(`INSERT INTO upstream_cas(trust_domain, backend, fingerprint, der, kept_at, kept_until) VALUES (?, ?, ?, ?, ?, ?)`),
			trustDomain, backend, c.Fingerprint(), c.DER, keptAt, until,
		); err != nil {
			return fmt.Errorf("insert upstream ca: %w", err)
		}
	}
	return tx.Commit()
}

// LoadBundleSequence returns the last spiffe_sequence stored for a trust
// domain and the digest of the trust material it was served for, or
// zero and "" when none is stored.
func (s *Store) LoadBundleSequence(ctx context.Context, trustDomain string) (int64, string, error) {
	var (
		seq    int64
		digest string
	)
	err := s.db.QueryRowContext(ctx,
		s.rebind(`SELECT seq, digest FROM bundle_sequence WHERE trust_domain = ?`), trustDomain,
	).Scan(&seq, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("query bundle sequence: %w", err)
	}
	return seq, digest, nil
}

// SaveBundleSequence stores seq as the trust domain's spiffe_sequence
// for the trust material digest names. The stored sequence only moves
// forward: a lower or equal seq, from a replica that saw the change
// later, leaves the row as it is. Refused with ErrNotLeader on a
// replica that is not the leader.
func (s *Store) SaveBundleSequence(ctx context.Context, trustDomain string, seq int64, digest string) error {
	if !s.IsLeader() {
		return ErrNotLeader
	}
	_, err := s.db.ExecContext(ctx,
		s.rebind(`INSERT INTO bundle_sequence(trust_domain, seq, digest, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (trust_domain) DO UPDATE SET seq = excluded.seq, digest = excluded.digest, updated_at = excluded.updated_at
		 WHERE bundle_sequence.seq < excluded.seq`),
		trustDomain, seq, digest, time.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("save bundle sequence: %w", err)
	}
	return nil
}
