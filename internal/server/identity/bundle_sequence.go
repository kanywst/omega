package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// material changes, from the highest value any process stored. Replicas
// that serve the same material serve the same sequence. It implements
// BundleSequencer for every identity source.
type DurableSequence struct {
	src         bundleMaterial
	store       BundleSequenceStore
	trustDomain string

	mu     sync.Mutex
	seq    int64
	digest string
}

// NewDurableSequence returns the spiffe_sequence of src's trust material
// in trustDomain, kept in store.
func NewDurableSequence(src bundleMaterial, store BundleSequenceStore, trustDomain string) *DurableSequence {
	return &DurableSequence{src: src, store: store, trustDomain: trustDomain}
}

// BundleSequence implements BundleSequencer. It reads the store only
// when the trust material differs from what it last served, so an
// unchanged bundle costs no I/O.
func (d *DurableSequence) BundleSequence() int64 {
	if s, ok := d.src.(BundleSequencer); ok {
		// An external issuer refreshes its bundle here, so the digest
		// below is of the bundle a caller reads next.
		_ = s.BundleSequence()
	}
	digest := materialDigest(d.src)
	d.mu.Lock()
	defer d.mu.Unlock()
	if digest == d.digest {
		return d.seq
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	stored, storedDigest, err := d.store.LoadBundleSequence(ctx, d.trustDomain)
	if err != nil {
		// Go on from this process's own count, which never goes back
		// while the process runs; the next change reads the store again.
		slog.Warn("identity: could not read the stored spiffe_sequence", "err", err)
		d.seq, d.digest = d.seq+1, digest
		return d.seq
	}
	var seq int64
	if storedDigest == digest && (stored > d.seq || d.seq == 0) {
		// Another process (or this one before a restart) already
		// numbered this material.
		seq = stored
	} else {
		seq = max(d.seq, stored) + 1
	}
	d.seq, d.digest = seq, digest
	if seq != stored || storedDigest != digest {
		if err := d.store.SaveBundleSequence(ctx, d.trustDomain, seq, digest); err != nil && !errors.Is(err, ErrStoreNotLeader) {
			slog.Warn("identity: could not store the spiffe_sequence; a restart may serve it again for other trust material", "err", err)
		}
	}
	return seq
}

// materialDigest is the SHA-256 of the trust anchors and JWT keys.
func materialDigest(src bundleMaterial) string {
	h := sha256.New()
	h.Write(src.BundlePEM())
	h.Write([]byte{0})
	if jwks, err := src.JWTBundle(); err == nil {
		h.Write(jwks)
	}
	return hex.EncodeToString(h.Sum(nil))
}
