package cli

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// controlPlaneTransport builds the transport a component uses to call the
// control plane. --server-ca pins the server's CA, and --client-cert /
// --client-key present an identity, which a --require-auth server needs.
// The client pair is re-read when either file changes, so a short-lived
// SVID rotated on disk is picked up without a restart.
func controlPlaneTransport(serverURL, caFile, certFile, keyFile string) (http.RoundTripper, error) {
	if caFile == "" && certFile == "" && keyFile == "" {
		return http.DefaultTransport, nil
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("--client-cert and --client-key must be set together")
	}
	if u, err := url.Parse(serverURL); err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("TLS flags need an https control-plane URL, got %q", serverURL)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		// #nosec G304 -- operator-supplied --server-ca path.
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read --server-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--server-ca %q contains no PEM certificates", caFile)
		}
		cfg.RootCAs = pool
	}
	if certFile != "" {
		kp := &reloadingKeyPair{certFile: certFile, keyFile: keyFile}
		if _, err := kp.get(); err != nil {
			return nil, err
		}
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return kp.get() }
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = cfg
	return t, nil
}

// reloadingKeyPair serves a client key pair from disk, reloading it when
// either file's modification time changes.
type reloadingKeyPair struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	certMod time.Time
	keyMod  time.Time
}

func (k *reloadingKeyPair) get() (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cs, cerr := os.Stat(k.certFile)
	ks, kerr := os.Stat(k.keyFile)
	if k.cert != nil && cerr == nil && kerr == nil && cs.ModTime().Equal(k.certMod) && ks.ModTime().Equal(k.keyMod) {
		return k.cert, nil
	}
	cert, err := tls.LoadX509KeyPair(k.certFile, k.keyFile)
	if err != nil {
		if k.cert != nil {
			// Mid-rotation (one file written, not the other): keep the
			// pair that last loaded until both match again.
			return k.cert, nil
		}
		return nil, fmt.Errorf("load --client-cert/--client-key: %w", err)
	}
	k.cert = &cert
	if cerr == nil {
		k.certMod = cs.ModTime()
	}
	if kerr == nil {
		k.keyMod = ks.ModTime()
	}
	return k.cert, nil
}
