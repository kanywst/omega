package identity

import (
	"bytes"
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
// a CA that an external issuer (Vault PKI, step-ca) stopped publishing
// stays in Omega's bundle, so SVIDs it signed before the issuer rotated
// keep verifying for peers until they could all have been reissued. The
// overlap is off unless configured, because Omega cannot tell a rotation
// from a revocation. A CA is never kept past its own expiry.
const UpstreamCAGrace = 24 * time.Hour

// upstreamRefreshBackoff is how long Vault PKI and step-ca serve the
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
}

type retiredCA struct {
	cert  *x509.Certificate
	until time.Time
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

// unlock releases o.mu and then reports the events queued under it, so
// the hook never runs under the lock. deliverMu is taken before o.mu is
// released, so two callers report their events in the order the changes
// were made.
func (o *caOverlap) unlock() {
	events, hook := o.pending, o.hook
	o.pending = nil
	o.deliverMu.Lock()
	o.mu.Unlock()
	defer o.deliverMu.Unlock()
	if hook != nil {
		for _, e := range events {
			hook(e)
		}
	}
}

func (o *caOverlap) drop(fp [32]byte, reason string) {
	r := o.retired[fp]
	delete(o.retired, fp)
	o.pending = append(o.pending, KeptCAEvent{Action: "dropped", Reason: reason, Subject: r.cert.Subject.String(), Fingerprint: hex.EncodeToString(fp[:]), Until: r.until})
}

// update installs fetched, the issuer's bundle now, and returns the
// bundle to serve. The first update sets the baseline without counting
// as a change.
func (o *caOverlap) update(fetched []byte, now time.Time) ([]byte, error) {
	certs, err := parsePEMCerts(fetched)
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.unlock()
	next := map[[32]byte]*x509.Certificate{}
	for _, c := range certs {
		next[sha256.Sum256(c.Raw)] = c
	}
	if o.grace > 0 {
		for fp, c := range o.current {
			// A CA that has already expired, or that the operator
			// distrusted, is not worth keeping.
			if _, still := next[fp]; !still && c.NotAfter.After(now) && !o.distrusted[fp] {
				until := now.Add(o.grace)
				if c.NotAfter.Before(until) {
					until = c.NotAfter
				}
				o.retired[fp] = retiredCA{cert: c, until: until}
				o.pending = append(o.pending, KeptCAEvent{Action: "kept", Subject: c.Subject.String(), Fingerprint: hex.EncodeToString(fp[:]), Until: until})
				// Omega cannot tell a routine rotation from a revocation.
				slog.Warn("identity: the issuer stopped publishing a CA; Omega keeps trusting it until --upstream-ca-grace ends (--upstream-ca-distrust drops it without a restart)",
					"subject", c.Subject.String(), "fingerprint", hex.EncodeToString(fp[:]), "until", until)
			}
		}
	}
	for fp := range o.retired {
		if _, back := next[fp]; back {
			o.drop(fp, "republished")
		}
	}
	o.loaded, o.fetched, o.current = true, certs, next
	return o.serveLocked(now), nil
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
