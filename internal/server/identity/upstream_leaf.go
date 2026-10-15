package identity

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// checkUpstreamLeaf is defence in depth for a certificate an external
// issuer (Vault PKI, step-ca) returned: a misconfigured role or
// provisioner, or a hostile upstream, must not hand a workload anything
// but an X.509-SVID leaf for exactly the requested ID, on the CSR's key,
// that chains to the bundle Omega serves.
func checkUpstreamLeaf(backend string, cert *x509.Certificate, id spiffeid.ID, csr *x509.CertificateRequest, bundlePEM []byte) error {
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("%s: issued certificate public key does not match CSR", backend)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != id.URL().String() {
		return fmt.Errorf("%s: issued certificate URI SANs %v are not exactly the requested SPIFFE ID %q", backend, cert.URIs, id)
	}
	if len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 {
		return fmt.Errorf("%s: issued certificate carries DNS, IP or email SANs omega did not request", backend)
	}
	// X.509-SVID: a leaf is not a CA, asserts digitalSignature and does
	// not assert keyCertSign or cRLSign.
	if cert.IsCA {
		return fmt.Errorf("%s: issued certificate is a CA certificate", backend)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return fmt.Errorf("%s: issued certificate key usage %#x is not an X.509-SVID leaf's", backend, cert.KeyUsage)
	}
	roots := x509.NewCertPool()
	for rest := bundlePEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			roots.AddCert(c)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("%s: issued certificate does not chain to the served bundle: %w", backend, err)
	}
	return nil
}
