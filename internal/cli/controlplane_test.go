package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePair(t *testing.T, dir, cn string, mod time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(cf, mod, mod)
	_ = os.Chtimes(kf, mod, mod)
	return cf, kf
}

func leafCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x.Subject.CommonName
}

func TestControlPlaneTransportReloadsClientPair(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writePair(t, dir, "first", time.Now().Add(-time.Hour))
	rt, err := controlPlaneTransport("https://cp:8443", "", cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	get := rt.(*http.Transport).TLSClientConfig.GetClientCertificate
	c, err := get(nil)
	if err != nil || leafCN(t, c) != "first" {
		t.Fatalf("initial pair: %v", err)
	}
	writePair(t, dir, "second", time.Now())
	if c, _ = get(nil); leafCN(t, c) != "second" {
		t.Error("a rotated pair must be picked up")
	}
	// A half-written rotation keeps serving the last good pair.
	if err := os.WriteFile(kf, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = get(nil); err != nil || leafCN(t, c) != "second" {
		t.Errorf("mid-rotation: %v", err)
	}
}

func TestControlPlaneTransportRejectsMisuse(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writePair(t, dir, "x", time.Now())
	if rt, err := controlPlaneTransport("http://cp", "", "", ""); err != nil || rt != http.DefaultTransport {
		t.Errorf("no TLS flags: %v", err)
	}
	for name, args := range map[string][4]string{
		"cert without key": {"https://cp", "", cf, ""},
		"TLS over http":    {"http://cp", "", cf, kf},
		"missing CA file":  {"https://cp", filepath.Join(dir, "nope"), "", ""},
		"CA without PEM":   {"https://cp", kf, "", ""},
		"unreadable pair":  {"https://cp", "", filepath.Join(dir, "nope"), kf},
	} {
		if _, err := controlPlaneTransport(args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
