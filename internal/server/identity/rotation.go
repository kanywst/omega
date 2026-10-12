package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The disk authority keeps up to three CAs in its directory:
//
//	ca.key, ca.crt            the active CA, which signs everything
//	ca.next.key, ca.next.crt  a prepared CA, trusted but not yet signing
//	ca.prev.crt               the CA it replaced, trusted until retired
//
// Rotation is prepare (generate next), activate (next becomes active, the
// old active becomes prev) and retire (drop prev), each followed by
// SIGHUP so the running server reloads the directory. Trusting next
// before it signs, and prev after it stops, lets every peer and workload
// pick up the change before it matters.
const (
	caKeyFile     = "ca.key"
	caCertFile    = "ca.crt"
	caNextKeyFile = "ca.next.key"
	caNextCrtFile = "ca.next.crt"
	caPrevCrtFile = "ca.prev.crt"
)

// RetireAfter is how long the previous CA must stay trusted after an
// activation: the longest an SVID or a JWT-SVID it signed can live.
const RetireAfter = maxJWTTTL

// caState is one generation of the disk authority's material.
type caState struct {
	cert *x509.Certificate
	key  crypto.Signer
	// trusted is every CA in the bundle: active first, then next, then
	// prev. JWT-SVIDs signed by any of them validate.
	trusted   []*x509.Certificate
	bundlePEM []byte
}

func newCAState(active *x509.Certificate, key crypto.Signer, extra ...*x509.Certificate) *caState {
	st := &caState{cert: active, key: key, trusted: []*x509.Certificate{active}}
	st.bundlePEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: active.Raw})
	for _, c := range extra {
		if c == nil {
			continue
		}
		st.trusted = append(st.trusted, c)
		st.bundlePEM = append(st.bundlePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return st
}

// readDiskState loads the directory's active, next and prev CAs without
// changing anything. If a crash interrupted an activation between its two
// renames (the new key in place, its certificate still under next), it
// uses the next certificate as the active one; the next mutating command
// moves the file (repairActivation).
func readDiskState(dir string) (*caState, error) {
	keyPath, crtPath := filepath.Join(dir, caKeyFile), filepath.Join(dir, caCertFile)
	key, err := readKey(keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := readCert(crtPath)
	if err != nil {
		return nil, err
	}
	names := []string{caNextCrtFile, caPrevCrtFile}
	if !keyMatches(key, cert) {
		next, nerr := readCert(filepath.Join(dir, caNextCrtFile))
		if nerr != nil || !keyMatches(key, next) {
			return nil, errors.New("ca.key does not match ca.crt")
		}
		cert, names = next, []string{caPrevCrtFile}
	}
	var extra []*x509.Certificate
	for _, name := range names {
		c, err := readCert(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		extra = append(extra, c)
	}
	return newCAState(cert, key, extra...), nil
}

func readKey(path string) (crypto.Signer, error) {
	// #nosec G304 -- the operator-supplied CA directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid CA key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca key is not a crypto.Signer")
	}
	return s, nil
}

func readCert(path string) (*x509.Certificate, error) {
	// #nosec G304 -- the operator-supplied CA directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid CA cert PEM in %s", filepath.Base(path))
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	return c, nil
}

func keyMatches(key crypto.Signer, cert *x509.Certificate) bool {
	a, ok1 := key.Public().(*ecdsa.PublicKey)
	b, ok2 := cert.PublicKey.(*ecdsa.PublicKey)
	return ok1 && ok2 && a.Equal(b)
}

// ReloadCA re-reads the authority's directory and installs what it finds,
// reporting whether the trust material changed. On error the previous
// material stays in use.
func (a *localAuthority) ReloadCA() (bool, error) {
	if a.dir == "" {
		return false, errors.New("authority has no directory to reload")
	}
	st, err := readDiskState(a.dir)
	if err != nil {
		return false, err
	}
	old := a.state.Load()
	if string(old.bundlePEM) == string(st.bundlePEM) && old.cert.Equal(st.cert) {
		return false, nil
	}
	a.state.Store(st)
	a.seq.Add(1)
	return true, nil
}

// BundleSequence backs spiffe_sequence: it starts at 1 and advances with
// every reload that changed the trust material.
func (a *localAuthority) BundleSequence() int64 { return a.seq.Load() }

// CAStatus describes the CAs in a disk authority's directory.
type CAStatus struct {
	Active    CAInfo    `json:"active"`
	Next      *CAInfo   `json:"next,omitempty"`
	Prev      *CAInfo   `json:"prev,omitempty"`
	PrevSince time.Time `json:"prev_since,omitzero"`
}

// CAInfo is one CA certificate.
type CAInfo struct {
	KeyID    string    `json:"kid"`
	NotAfter time.Time `json:"not_after"`
}

func caInfo(c *x509.Certificate) CAInfo {
	kid, _ := keyIDOf(c)
	return CAInfo{KeyID: kid, NotAfter: c.NotAfter}
}

// ReadCAStatus reports the directory's CAs without changing anything.
func ReadCAStatus(dir string) (CAStatus, error) {
	st, err := readDiskState(dir)
	if err != nil {
		return CAStatus{}, err
	}
	s := CAStatus{Active: caInfo(st.cert)}
	if c, err := readCert(filepath.Join(dir, caNextCrtFile)); err == nil {
		i := caInfo(c)
		s.Next = &i
	}
	if c, err := readCert(filepath.Join(dir, caPrevCrtFile)); err == nil {
		i := caInfo(c)
		s.Prev = &i
		if fi, err := os.Stat(filepath.Join(dir, caPrevCrtFile)); err == nil {
			s.PrevSince = fi.ModTime()
		}
	}
	return s, nil
}

// repairActivation finishes an activation a crash interrupted between
// moving the key and moving the certificate.
func repairActivation(dir string) error {
	key, err := readKey(filepath.Join(dir, caKeyFile))
	if err != nil {
		return err
	}
	cert, err := readCert(filepath.Join(dir, caCertFile))
	if err != nil {
		return err
	}
	if keyMatches(key, cert) {
		return nil
	}
	next, err := readCert(filepath.Join(dir, caNextCrtFile))
	if err != nil || !keyMatches(key, next) {
		return errors.New("ca.key does not match ca.crt")
	}
	if err := os.Rename(filepath.Join(dir, caNextCrtFile), filepath.Join(dir, caCertFile)); err != nil {
		return fmt.Errorf("finish an interrupted activation: %w", err)
	}
	return nil
}

// PrepareCA generates the next CA in dir. It refuses if one is already
// prepared.
func PrepareCA(dir string) (CAInfo, error) {
	if err := repairActivation(dir); err != nil {
		return CAInfo{}, err
	}
	if _, err := os.Stat(filepath.Join(dir, caNextKeyFile)); err == nil {
		return CAInfo{}, errors.New("a next CA is already prepared; activate it first")
	}
	if _, err := readDiskState(dir); err != nil {
		return CAInfo{}, err
	}
	cert, err := generateCA(filepath.Join(dir, caNextKeyFile), filepath.Join(dir, caNextCrtFile))
	if err != nil {
		return CAInfo{}, err
	}
	return caInfo(cert), nil
}

// ActivateCA makes the prepared CA the active one and keeps the old
// active certificate as prev. It refuses while a previous CA is still
// retained, so there are never more than three trusted CAs.
func ActivateCA(dir string) (CAInfo, error) {
	if err := repairActivation(dir); err != nil {
		return CAInfo{}, err
	}
	if _, err := os.Stat(filepath.Join(dir, caNextKeyFile)); err != nil {
		return CAInfo{}, errors.New("no next CA is prepared; run prepare first")
	}
	nextKey, err := readKey(filepath.Join(dir, caNextKeyFile))
	if err != nil {
		return CAInfo{}, err
	}
	next, err := readCert(filepath.Join(dir, caNextCrtFile))
	if err != nil {
		return CAInfo{}, err
	}
	if !keyMatches(nextKey, next) {
		return CAInfo{}, errors.New("ca.next.key does not match ca.next.crt; prepare again")
	}
	active, err := readCert(filepath.Join(dir, caCertFile))
	if err != nil {
		return CAInfo{}, err
	}
	// A previous CA that is the current active one is what a crash right
	// after the first write below leaves: resume. Any other is still in
	// use and must be retired first.
	prevPath := filepath.Join(dir, caPrevCrtFile)
	if prev, err := readCert(prevPath); err == nil {
		if !prev.Equal(active) {
			return CAInfo{}, errors.New("a previous CA is still trusted; retire it first")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return CAInfo{}, err
	} else if err := writeFileSync(prevPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: active.Raw}), 0o644); err != nil {
		// The old certificate is kept first, so a crash at any later
		// point leaves it trusted. The key moves before the certificate;
		// a crash between the two is finished by repairActivation.
		return CAInfo{}, err
	}
	if err := os.Rename(filepath.Join(dir, caNextKeyFile), filepath.Join(dir, caKeyFile)); err != nil {
		return CAInfo{}, err
	}
	if err := os.Rename(filepath.Join(dir, caNextCrtFile), filepath.Join(dir, caCertFile)); err != nil {
		return CAInfo{}, err
	}
	return caInfo(next), nil
}

// RetireCA stops trusting the previous CA. Unless force is set it refuses
// before RetireAfter has passed since the activation, while SVIDs and
// JWT-SVIDs that CA signed may still be in use.
func RetireCA(dir string, force bool) error {
	if err := repairActivation(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, caPrevCrtFile)
	fi, err := os.Stat(path)
	if err != nil {
		return errors.New("no previous CA to retire")
	}
	if wait := RetireAfter - time.Since(fi.ModTime()); wait > 0 && !force {
		return fmt.Errorf("the previous CA was replaced %s ago; tokens it signed may live %s longer (use --force to retire now)", time.Since(fi.ModTime()).Round(time.Minute), wait.Round(time.Minute))
	}
	return os.Remove(path)
}

func keyIDOf(c *x509.Certificate) (string, error) {
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("ca key is not ECDSA (only ES256 is supported)")
	}
	der, err := marshalECPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:8]), nil
}

func writeFileSync(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	// #nosec G304 -- the operator-supplied CA directory.
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
