package identity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// UpstreamCAGrace is how long a CA that an external issuer (Vault PKI,
// step-ca) stopped publishing stays in Omega's bundle: SVIDs it signed
// before the issuer rotated keep verifying for peers that refresh from
// Omega, until they could all have been reissued. A CA is never kept past
// its own expiry.
const UpstreamCAGrace = 24 * time.Hour

// caOverlap turns an external issuer's current CA bundle into the one
// Omega serves: the current CAs plus any it dropped within
// UpstreamCAGrace. It counts changes for spiffe_sequence.
type caOverlap struct {
	mu      sync.Mutex
	current map[[32]byte]*x509.Certificate
	retired map[[32]byte]retiredCA
	served  []byte
	seq     atomic.Int64
}

type retiredCA struct {
	cert  *x509.Certificate
	until time.Time
}

func newCAOverlap() *caOverlap {
	o := &caOverlap{current: map[[32]byte]*x509.Certificate{}, retired: map[[32]byte]retiredCA{}}
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
	for fp, c := range o.current {
		if _, still := next[fp]; !still {
			until := now.Add(UpstreamCAGrace)
			if c.NotAfter.Before(until) {
				until = c.NotAfter
			}
			o.retired[fp] = retiredCA{cert: c, until: until}
		}
	}
	for fp, r := range o.retired {
		if _, back := next[fp]; back || !now.Before(r.until) {
			delete(o.retired, fp)
		}
	}
	// The issuer's own order first (step-ca pins its first root), then
	// what is kept from before.
	served := append([]byte(nil), fetched...)
	if len(served) > 0 && served[len(served)-1] != '\n' {
		served = append(served, '\n')
	}
	for _, r := range o.retired {
		served = append(served, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.cert.Raw})...)
	}
	first := o.served == nil
	if !first && string(served) != string(o.served) {
		o.seq.Add(1)
	}
	o.current, o.served = next, served
	return append([]byte(nil), served...), nil
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
