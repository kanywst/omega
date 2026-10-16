package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// BundleSequenceStore keeps a trust domain's spiffe_sequence across
// restarts and replicas, with a digest of the trust material it was
// served for. Save never moves the stored sequence back; on a replica
// that may not write it returns an error wrapping ErrStoreNotLeader.
type BundleSequenceStore interface {
	LoadBundleSequence(ctx context.Context, trustDomain string) (int64, string, error)
	SaveBundleSequence(ctx context.Context, trustDomain string, seq int64, digest string) error
}

// bundleMaterial is what a peer verifies against: the X.509 trust
// anchors and the JWT signing keys.
type bundleMaterial interface {
	BundlePEM() []byte
	JWTBundle() ([]byte, error)
}

// DurableSequence backs spiffe_sequence with a store, so the sequence
// never goes back across a restart: it advances whenever the trust
// material changes, from the highest value any process stored, and by
// as many changes as the source counted when it counts them. A replica
// whose store refuses writes re-reads the stored sequence now and then,
// so it takes up the leader's number for the same material. It
// implements BundleSequencer for every identity source.
type DurableSequence struct {
	src         bundleMaterial
	store       BundleSequenceStore
	trustDomain string
	now         func() time.Time

	// ioMu is held by the one caller reading or writing the store; the
	// others serve the last sequence meanwhile instead of waiting.
	ioMu sync.Mutex

	mu     sync.Mutex
	seq    int64
	digest string
	// srcSeq is the source's own count when seq was last set.
	srcSeq int64
	// retryAt holds off store reads after a failed one.
	retryAt time.Time
	// resyncAt, set on a replica that may not write, is when it next
	// re-reads the stored sequence for unchanged material.
	resyncAt time.Time
}

// sequenceRecheck is how long a failed store read holds off the next
// one, and how often a replica that may not write re-reads the stored
// sequence.
const sequenceRecheck = 30 * time.Second

// maxStoredSequence bounds a stored spiffe_sequence Omega will continue
// from.
const maxStoredSequence = 1 << 48

// NewDurableSequence returns the spiffe_sequence of src's trust material
// in trustDomain, kept in store. It reads the store once to number the
// current material, and fails if it cannot: starting from 1 instead
// would serve a lower sequence than before the restart.
func NewDurableSequence(src bundleMaterial, store BundleSequenceStore, trustDomain string) (*DurableSequence, error) {
	d := &DurableSequence{src: src, store: store, trustDomain: trustDomain, now: time.Now}
	if _, err := d.next(); err != nil {
		return nil, err
	}
	return d, nil
}

// BundleSequence implements BundleSequencer. It reads the store only
// when the trust material differs from what it last served, so an
// unchanged bundle costs no I/O. If the store or the trust material
// cannot be read, it serves the last sequence, which never goes back,
// and tries again later.
func (d *DurableSequence) BundleSequence() int64 {
	seq, err := d.next()
	if err != nil {
		slog.Warn("identity: could not number the trust bundle; serving the last spiffe_sequence", "err", err)
	}
	return seq
}

func (d *DurableSequence) next() (int64, error) {
	var srcSeq int64
	if s, ok := d.src.(BundleSequencer); ok {
		// An external issuer refreshes its bundle here, so the digest
		// below is of the bundle a caller reads next.
		srcSeq = s.BundleSequence()
	}
	// A partial digest would look like a change and move the stored
	// sequence for good, so an error leaves everything as it is.
	digest, err := materialDigest(d.src)
	now := d.now()
	d.mu.Lock()
	last := d.seq
	current := digest == d.digest && (d.resyncAt.IsZero() || now.Before(d.resyncAt))
	holdOff := now.Before(d.retryAt)
	d.mu.Unlock()
	if err != nil {
		return last, err
	}
	if current || holdOff || !d.ioMu.TryLock() {
		return last, nil
	}
	defer d.ioMu.Unlock()
	return d.number(digest, srcSeq)
}

// number reads the stored sequence and numbers digest. It runs under
// ioMu, never under mu, so a slow store holds up no other caller.
func (d *DurableSequence) number(digest string, srcSeq int64) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	stored, storedDigest, err := d.store.LoadBundleSequence(ctx, d.trustDomain)
	if err == nil && (stored < 0 || stored > maxStoredSequence) {
		// No run of trust material changes gets near this; a value
		// beyond it was written by something other than Omega, and
		// adding to it could overflow.
		err = fmt.Errorf("stored spiffe_sequence %d is out of range", stored)
	}
	d.mu.Lock()
	if err != nil {
		d.retryAt = d.now().Add(sequenceRecheck)
		last := d.seq
		d.mu.Unlock()
		return last, err
	}
	if digest == d.digest {
		// A replica that may not write, checking for the leader's
		// number for the material it already serves.
		if storedDigest == digest && stored > d.seq {
			d.seq = stored
		}
		d.resyncAt = d.now().Add(sequenceRecheck)
		last := d.seq
		d.mu.Unlock()
		return last, nil
	}
	var seq int64
	if storedDigest == digest && (stored > d.seq || d.seq == 0) {
		// Another process (or this one before a restart) already
		// numbered this material.
		seq = stored
	} else {
		// Two rotations between reads advance it by two, as the source
		// counted them.
		step := srcSeq - d.srcSeq
		if d.seq == 0 || step < 1 {
			step = 1
		}
		seq = max(d.seq, stored) + step
	}
	d.seq, d.digest, d.srcSeq = seq, digest, srcSeq
	d.mu.Unlock()
	if seq == stored && storedDigest == digest {
		return seq, nil
	}
	err = d.store.SaveBundleSequence(ctx, d.trustDomain, seq, digest)
	var resyncAt time.Time
	switch {
	case errors.Is(err, ErrStoreNotLeader):
		resyncAt = d.now().Add(sequenceRecheck)
	case err != nil:
		slog.Warn("identity: could not store the spiffe_sequence; a restart may serve it again for other trust material", "err", err)
	}
	d.mu.Lock()
	d.resyncAt = resyncAt
	d.mu.Unlock()
	return seq, nil
}

// materialDigest is the SHA-256 of the trust anchors and JWT keys.
func materialDigest(src bundleMaterial) (string, error) {
	jwks, err := src.JWTBundle()
	if err != nil {
		return "", fmt.Errorf("jwt bundle: %w", err)
	}
	h := sha256.New()
	h.Write(src.BundlePEM())
	h.Write([]byte{0})
	h.Write(jwks)
	return hex.EncodeToString(h.Sum(nil)), nil
}
