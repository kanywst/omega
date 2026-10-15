package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func TestCheckUpstreamLeaf(t *testing.T) {
	newCA := func() (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
		c, _ := x509.ParseCertificate(der)
		return c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	ca, caKey, bundle := newCA()
	_, _, otherBundle := newCA()
	id := spiffeid.RequireFromString("spiffe://omega.local/w")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	issue := func(mutate func(*x509.Certificate)) *x509.Certificate {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(30 * time.Minute),
			URIs: []*url.URL{id.URL()}, KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
		if mutate != nil {
			mutate(tpl)
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	if err := checkUpstreamLeaf("test", issue(nil), id, csr, bundle); err != nil {
		t.Fatalf("a good leaf: %v", err)
	}
	extra, _ := url.Parse("spiffe://omega.local/admin")
	for name, tc := range map[string]struct {
		cert   *x509.Certificate
		bundle []byte
		want   string
	}{
		"extra URI SAN":  {issue(func(c *x509.Certificate) { c.URIs = append(c.URIs, extra) }), bundle, "not exactly"},
		"DNS SAN":        {issue(func(c *x509.Certificate) { c.DNSNames = []string{"db.internal"} }), bundle, "DNS, IP or email"},
		"CA leaf":        {issue(func(c *x509.Certificate) { c.IsCA = true }), bundle, "CA certificate"},
		"cert sign":      {issue(func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign }), bundle, "key usage"},
		"no digital sig": {issue(func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }), bundle, "key usage"},
		"other chain":    {issue(nil), otherBundle, "does not chain"},
	} {
		if err := checkUpstreamLeaf("test", tc.cert, id, csr, tc.bundle); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q, got %v", name, tc.want, err)
		}
	}
}
