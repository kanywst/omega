package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamCAGrace is the default for how long a CA that an external issuer (Vault PKI,
// step-ca) stopped publishing stays in Omega's bundle: SVIDs it signed
// before the issuer rotated keep verifying for peers that refresh from
// Omega, until they could all have been reissued. A CA is never kept past
// its own expiry.
const UpstreamCAGrace = 24 * time.Hour

// caOverlap turns an external issuer's current CA bundle into the one
// Omega serves: the current CAs plus any it dropped within the grace
// period. It counts changes for spiffe_sequence.
type caOverlap struct {
	grace   time.Duration
	mu      sync.Mutex
	fetched []byte
	current map[[32]byte]*x509.Certificate
	retired map[[32]byte]retiredCA
	served  []byte
	seq     atomic.Int64
}

type retiredCA struct {
	cert  *x509.Certificate
	until time.Time
}

// newCAOverlap keeps dropped CAs for grace; zero keeps none.
func newCAOverlap(grace time.Duration) *caOverlap {
	o := &caOverlap{grace: grace, current: map[[32]byte]*x509.Certificate{}, retired: map[[32]byte]retiredCA{}}
	o.seq.Store(1)
	return o
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
	defer o.mu.Unlock()
	next := map[[32]byte]*x509.Certificate{}
	for _, c := range certs {
		next[sha256.Sum256(c.Raw)] = c
	}
	if o.grace > 0 {
		for fp, c := range o.current {
			if _, still := next[fp]; !still {
				until := now.Add(o.grace)
				if c.NotAfter.Before(until) {
					until = c.NotAfter
				}
				o.retired[fp] = retiredCA{cert: c, until: until}
			}
		}
	}
	for fp := range o.retired {
		if _, back := next[fp]; back {
			delete(o.retired, fp)
		}
	}
	o.fetched, o.current = append([]byte(nil), fetched...), next
	return o.serveLocked(now), nil
}

// serve returns the bundle to serve now, dropping retired CAs whose time
// is up even when the issuer cannot be reached for a refresh.
func (o *caOverlap) serve(now time.Time) []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.fetched == nil {
		return nil
	}
	return o.serveLocked(now)
}

func (o *caOverlap) serveLocked(now time.Time) []byte {
	for fp, r := range o.retired {
		if !now.Before(r.until) {
			delete(o.retired, fp)
		}
	}
	// The issuer's own order first (step-ca pins its first root), then
	// the kept CAs in a stable order, so an unchanged set serves the same
	// bytes and does not move spiffe_sequence.
	served := append([]byte(nil), o.fetched...)
	if len(served) > 0 && served[len(served)-1] != '\n' {
		served = append(served, '\n')
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

func parsePEMCerts(raw []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
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
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates in the issuer's bundle")
	}
	return out, nil
}

// upstreamGrace resolves Config.UpstreamCAGrace: zero is the default,
// negative is off.
func upstreamGrace(d time.Duration) time.Duration {
	switch {
	case d == 0:
		return UpstreamCAGrace
	case d < 0:
		return 0
	}
	return d
}
