package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamCAGrace is the suggested grace for --upstream-ca-grace: how long
// a CA that an external issuer (Vault PKI, step-ca, AWS Private CA) stopped publishing
// stays in Omega's bundle, so SVIDs it signed before the issuer rotated
// keep verifying for peers until they could all have been reissued. The
// overlap is off unless configured, because Omega cannot tell a rotation
// from a revocation. A CA is never kept past its own expiry.
const UpstreamCAGrace = 24 * time.Hour

// upstreamRefreshBackoff is how long the external-issuer backends serve the
// last bundle after a failed refresh before trying the issuer again.
const upstreamRefreshBackoff = 30 * time.Second

// KeptCAEvent reports a change to the set of rotated-out CAs Omega keeps
// serving: Action is "kept" or "dropped", Reason for a drop is
// "grace-ended", "republished" or "distrusted".
type KeptCAEvent struct {
	Action      string
	Reason      string
	Subject     string
	Fingerprint string // hex SHA-256 of the DER certificate
	Until       time.Time
}

// UpstreamCA is one CA an external issuer published, as Omega stores
// it. Until is zero while the issuer still publishes the CA; once the
// issuer stops, Omega keeps it from KeptAt until Until.
type UpstreamCA struct {
	DER    []byte
	KeptAt time.Time
	Until  time.Time
}

// UpstreamCAStore keeps the issuer's CAs and the ones kept from a
// rotation across restarts, shared by every replica. Save replaces the
// whole set for the trust domain and backend; on a replica that may not
// write it returns an error wrapping ErrStoreNotLeader.
type UpstreamCAStore interface {
	LoadUpstreamCAs(ctx context.Context, trustDomain, backend string) ([]UpstreamCA, error)
	SaveUpstreamCAs(ctx context.Context, trustDomain, backend string, cas []UpstreamCA) error
}

// ErrStoreNotLeader is the error a store returns for a write on a
// replica that is not the leader. The leader writes; the others read.
var ErrStoreNotLeader = errors.New("store: not the leader")

// storeTimeout bounds each read or write of the stored CA state.
const storeTimeout = 5 * time.Second

// caOverlap turns an external issuer's current CA bundle into the one
// Omega serves: the current CAs plus any it dropped within the grace
// period. It counts changes for spiffe_sequence.
type caOverlap struct {
	grace      time.Duration
	mu         sync.Mutex
	deliverMu  sync.Mutex
	loaded     bool
	fetched    []*x509.Certificate
	current    map[[32]byte]*x509.Certificate
	retired    map[[32]byte]retiredCA
	distrusted map[[32]byte]bool
	served     []byte
	seq        atomic.Int64
	hook       func(KeptCAEvent)
	pending    []KeptCAEvent

	// store, once set, holds the state across restarts and replicas.
	store atomic.Pointer[caStore]
	// baselined is set once the stored issuer CAs were compared with
	// the issuer's bundle: only the first comparison after a start can
	// find a rotation that happened while Omega was down.
	baselined bool
	// version counts changes to the state to store; saved is the
	// version last stored.
	version int64
	saved   atomic.Int64
}

type caStore struct {
	store       UpstreamCAStore
	trustDomain string
	backend     string
}

type retiredCA struct {
	cert   *x509.Certificate
	keptAt time.Time
	until  time.Time
}

// newCAOverlap keeps dropped CAs for grace; zero keeps none.
func newCAOverlap(grace time.Duration) *caOverlap {
	o := &caOverlap{grace: grace, current: map[[32]byte]*x509.Certificate{}, retired: map[[32]byte]retiredCA{}, distrusted: map[[32]byte]bool{}}
	o.seq.Store(1)
	return o
}

// setHook installs the function told about every change to the kept set.
func (o *caOverlap) setHook(h func(KeptCAEvent)) {
	o.mu.Lock()
	o.hook = h
	o.mu.Unlock()
}

// unlock releases o.mu, then stores the state if it changed and
// reports the events queued under it, so neither runs under the lock.
// deliverMu is taken before o.mu is released, so two callers store and
// report in the order the changes were made.
func (o *caOverlap) unlock() {
	events, hook := o.pending, o.hook
	o.pending = nil
	st := o.store.Load()
	var (
		save     bool
		snapshot []UpstreamCA
		version  int64
	)
	if st != nil && o.version != o.saved.Load() {
		save, snapshot, version = true, o.snapshotLocked(), o.version
	}
	o.deliverMu.Lock()
	o.mu.Unlock()
	defer o.deliverMu.Unlock()
	if save {
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		err := st.store.SaveUpstreamCAs(ctx, st.trustDomain, st.backend, snapshot)
		cancel()
		switch {
		case err == nil:
			o.saved.Store(version)
		case errors.Is(err, ErrStoreNotLeader):
			// The leader stores the set; this replica reads it.
		default:
			// Not marked saved, so the next change or refresh tries again.
			slog.Warn("identity: could not store the upstream CAs; a restart before the next save loses the latest change", "err", err)
		}
	}
	if hook != nil {
		for _, e := range events {
			hook(e)
		}
	}
}

// snapshotLocked returns the state to store: the issuer's CAs and the
// kept ones.
func (o *caOverlap) snapshotLocked() []UpstreamCA {
	out := make([]UpstreamCA, 0, len(o.current)+len(o.retired))
	for _, c := range o.current {
		out = append(out, UpstreamCA{DER: c.Raw})
	}
	for _, r := range o.retired {
		out = append(out, UpstreamCA{DER: r.cert.Raw, KeptAt: r.keptAt, Until: r.until})
	}
	return out
}

func (o *caOverlap) drop(fp [32]byte, reason string) {
	r := o.retired[fp]
	delete(o.retired, fp)
	o.version++
	o.pending = append(o.pending, KeptCAEvent{Action: "dropped", Reason: reason, Subject: r.cert.Subject.String(), Fingerprint: hex.EncodeToString(fp[:]), Until: r.until})
}

// attachStore loads the stored state and keeps it in step from now on:
// the CAs kept before a restart are kept again until their own time is
// up, and a CA the issuer stopped publishing while Omega was down is
// kept as if Omega had seen it go. An error leaves the overlap as it was.
func (o *caOverlap) attachStore(store UpstreamCAStore, trustDomain, backend string, now time.Time) error {
	st := &caStore{store: store, trustDomain: trustDomain, backend: backend}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	stored, err := store.LoadUpstreamCAs(ctx, trustDomain, backend)
	cancel()
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.unlock()
	o.store.Store(st)
	prev := o.mergeStoredLocked(stored, o.current, now)
	o.retireLocked(prev, o.current, now)
	// Store the state as this process sees it, even when nothing changed.
	o.version++
	if o.loaded {
		o.serveLocked(now)
	}
	return nil
}

// loadStored reads the shared state, or returns false when there is no
// store or it cannot be read; the overlap then goes on with its own.
func (o *caOverlap) loadStored() ([]UpstreamCA, bool) {
	st := o.store.Load()
	if st == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	stored, err := st.store.LoadUpstreamCAs(ctx, st.trustDomain, st.backend)
	if err != nil {
		slog.Warn("identity: could not read the stored upstream CAs; serving this replica's own", "err", err)
		return nil, false
	}
	return stored, true
}

// mergeStoredLocked folds the stored state into this process's: a CA
// kept by any replica is kept here, until the time the first replica
// to keep it set, cut to the CA's keep time plus this process's grace.
// It returns the CAs the issuer published before next: this process's
// own, plus, on the first merge after a start, the stored ones.
func (o *caOverlap) mergeStoredLocked(stored []UpstreamCA, next map[[32]byte]*x509.Certificate, now time.Time) map[[32]byte]*x509.Certificate {
	prev := make(map[[32]byte]*x509.Certificate, len(o.current))
	for fp, c := range o.current {
		prev[fp] = c
	}
	first := !o.baselined
	o.baselined = true
	for _, r := range stored {
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			slog.Warn("identity: skipping a stored upstream CA that does not parse", "err", err)
			continue
		}
		fp := sha256.Sum256(c.Raw)
		if r.Until.IsZero() {
			if first {
				prev[fp] = c
			}
			continue
		}
		until := r.Until
		if limit := r.KeptAt.Add(o.grace); limit.Before(until) {
			until = limit
		}
		if _, back := next[fp]; back || o.distrusted[fp] {
			continue
		}
		if !now.Before(until) {
			// Its grace ended while no Omega was running to drop it.
			if first {
				o.pending = append(o.pending, KeptCAEvent{Action: "dropped", Reason: "grace-ended", Subject: c.Subject.String(), Fingerprint: hex.EncodeToString(fp[:]), Until: until})
				o.version++
			}
			continue
		}
		if have, ok := o.retired[fp]; ok && have.until.Equal(until) && have.keptAt.Equal(r.KeptAt) {
			continue
		}
		o.retired[fp] = retiredCA{cert: c, keptAt: r.KeptAt, until: until}
		o.version++
	}
	return prev
}

// retireLocked keeps, for the grace period, each CA in prev that next
// no longer has.
func (o *caOverlap) retireLocked(prev, next map[[32]byte]*x509.Certificate, now time.Time) {
	if o.grace <= 0 {
		return
	}
	for fp, c := range prev {
		// A CA that has already expired, or that the operator
		// distrusted, is not worth keeping.
		if _, still := next[fp]; still || !c.NotAfter.After(now) || o.distrusted[fp] {
			continue
		}
		if _, kept := o.retired[fp]; kept {
			continue
		}
		until := now.Add(o.grace)
		if c.NotAfter.Before(until) {
			until = c.NotAfter
		}
		o.retired[fp] = retiredCA{cert: c, keptAt: now, until: until}
		o.version++
		o.pending = append(o.pending, KeptCAEvent{Action: "kept", Subject: c.Subject.String(), Fingerprint: hex.EncodeToString(fp[:]), Until: until})
		// Omega cannot tell a routine rotation from a revocation.
		slog.Warn("identity: the issuer stopped publishing a CA; Omega keeps trusting it until --upstream-ca-grace ends (--upstream-ca-distrust drops it without a restart)",
			"subject", c.Subject.String(), "fingerprint", hex.EncodeToString(fp[:]), "until", until)
	}
}

// update installs fetched, the issuer's bundle now, and returns the
// bundle to serve. The first update sets the baseline without counting
// as a change.
func (o *caOverlap) update(fetched []byte, now time.Time) ([]byte, error) {
	certs, err := parsePEMCerts(fetched)
	if err != nil {
		return nil, err
	}
	// Read what the other replicas kept before taking the lock: the
	// store is shared, so every replica serves the same kept CAs.
	stored, haveStored := o.loadStored()
	o.mu.Lock()
	defer o.unlock()
	next := map[[32]byte]*x509.Certificate{}
	for _, c := range certs {
		next[sha256.Sum256(c.Raw)] = c
	}
	prev := o.current
	if haveStored {
		prev = o.mergeStoredLocked(stored, next, now)
	}
	o.retireLocked(prev, next, now)
	for fp := range o.retired {
		if _, back := next[fp]; back {
			o.drop(fp, "republished")
		}
	}
	if !sameKeys(o.current, next) {
		o.version++
	}
	o.loaded, o.fetched, o.current = true, certs, next
	return o.serveLocked(now), nil
}

func sameKeys(a, b map[[32]byte]*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// serve returns the bundle to serve now, dropping retired CAs whose time
// is up even when the issuer cannot be reached for a refresh.
func (o *caOverlap) serve(now time.Time) []byte {
	o.mu.Lock()
	defer o.unlock()
	if !o.loaded {
		return nil
	}
	return o.serveLocked(now)
}

// distrust replaces the set of CAs the operator has distrusted: any of
// them kept from a rotation is dropped at once and never kept again. A
// CA the issuer still publishes is the issuer's to withdraw, so it stays.
// It returns how many kept CAs it dropped.
func (o *caOverlap) distrust(fps [][32]byte, now time.Time) int {
	o.mu.Lock()
	defer o.unlock()
	o.distrusted = make(map[[32]byte]bool, len(fps))
	n := 0
	for _, fp := range fps {
		o.distrusted[fp] = true
		if _, kept := o.retired[fp]; kept {
			slog.Warn("identity: dropped a kept CA the operator distrusted", "subject", o.retired[fp].cert.Subject.String(), "fingerprint", hex.EncodeToString(fp[:]))
			o.drop(fp, "distrusted")
			n++
		}
	}
	if n > 0 && o.loaded {
		o.serveLocked(now)
	}
	return n
}

func (o *caOverlap) serveLocked(now time.Time) []byte {
	for fp, r := range o.retired {
		if !now.Before(r.until) {
			slog.Info("identity: stopped trusting a CA the issuer rotated out", "subject", r.cert.Subject.String())
			o.drop(fp, "grace-ended")
		}
	}
	// The issuer's own order first (step-ca pins its first root), then
	// the kept CAs in a stable order, so an unchanged set serves the same
	// bytes and does not move spiffe_sequence. Only certificates that
	// parsed are served: one Omega cannot read is not a trust anchor it
	// can vouch for.
	var served []byte
	for _, c := range o.fetched {
		served = append(served, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	fps := make([][32]byte, 0, len(o.retired))
	for fp := range o.retired {
		fps = append(fps, fp)
	}
	sort.Slice(fps, func(i, j int) bool { return bytes.Compare(fps[i][:], fps[j][:]) < 0 })
	for _, fp := range fps {
		served = append(served, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: o.retired[fp].cert.Raw})...)
	}
	if o.served != nil && !bytes.Equal(served, o.served) {
		o.seq.Add(1)
	}
	o.served = served
	return append([]byte(nil), served...)
}

func (o *caOverlap) sequence() int64 { return o.seq.Load() }

// parsePEMCerts returns the certificates in an issuer's bundle. A block
// Go cannot parse is skipped with a warning, and not served, as long as
// one parses.
func parsePEMCerts(raw []byte) ([]*x509.Certificate, error) {
	var (
		out     []*x509.Certificate
		lastErr error
	)
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Warn("identity: skipping a certificate in the issuer's bundle that does not parse", "err", err)
			lastErr = err
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		if lastErr != nil {
			return nil, fmt.Errorf("no parseable certificates in the issuer's bundle: %w", lastErr)
		}
		return nil, errors.New("no certificates in the issuer's bundle")
	}
	return out, nil
}

// upstreamGrace resolves Config.UpstreamCAGrace: zero or negative is off.
func upstreamGrace(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d
}

// ParseCAFingerprints reads SHA-256 fingerprints of DER certificates, one
// per line in hex (colons allowed), with '#' comments and blank lines.
func ParseCAFingerprints(raw []byte) ([][32]byte, error) {
	var out [][32]byte
	for i, line := range strings.Split(string(raw), "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		line = strings.ReplaceAll(strings.TrimSpace(line), ":", "")
		if line == "" {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("line %d: not a hex SHA-256 fingerprint", i+1)
		}
		out = append(out, [32]byte(b))
	}
	return out, nil
}
