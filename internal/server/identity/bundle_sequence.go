package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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
// as many changes as the source counted when it counts them. Replicas
// that serve the same material serve the same sequence. It implements
// BundleSequencer for every identity source.
type DurableSequence struct {
	src         bundleMaterial
	store       BundleSequenceStore
	trustDomain string

	mu     sync.Mutex
	seq    int64
	digest string
	// srcSeq is the source's own count when seq was last set.
	srcSeq int64
}

// NewDurableSequence returns the spiffe_sequence of src's trust material
// in trustDomain, kept in store. It reads the store once to number the
// current material, and fails if it cannot: starting from 1 instead
// would serve a lower sequence than before the restart.
func NewDurableSequence(src bundleMaterial, store BundleSequenceStore, trustDomain string) (*DurableSequence, error) {
	d := &DurableSequence{src: src, store: store, trustDomain: trustDomain}
	if _, err := d.next(); err != nil {
		return nil, err
	}
	return d, nil
}

// BundleSequence implements BundleSequencer. It reads the store only
// when the trust material differs from what it last served, so an
// unchanged bundle costs no I/O. If the store cannot be read, it serves
// the last sequence, which never goes back, and reads the store again
// on the next call. The same holds while the trust material cannot be
// read.
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
	digest, err := materialDigest(d.src)
	if err != nil {
		// A partial digest would look like a change and move the
		// stored sequence for good.
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.seq, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if digest == d.digest {
		return d.seq, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	stored, storedDigest, err := d.store.LoadBundleSequence(ctx, d.trustDomain)
	if err != nil {
		// The digest is not recorded, so the next call tries again.
		return d.seq, err
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
	if seq != stored || storedDigest != digest {
		if err := d.store.SaveBundleSequence(ctx, d.trustDomain, seq, digest); err != nil && !errors.Is(err, ErrStoreNotLeader) {
			slog.Warn("identity: could not store the spiffe_sequence; a restart may serve it again for other trust material", "err", err)
		}
	}
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
