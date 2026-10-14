// mock-pca is a tiny stand-in for AWS Private CA (ACM PCA) for the
// examples/ca-aws-pca demo. It speaks the awsJson1_1 protocol the AWS
// SDK uses (POST / with an X-Amz-Target header) for the three
// operations omega calls:
//
//	ACMPrivateCA.GetCertificateAuthorityCertificate
//	ACMPrivateCA.IssueCertificate
//	ACMPrivateCA.GetCertificate
//
// It holds a root CA and an issuing CA under it, signs leaves with the
// URI SAN from ApiPassthrough as EndEntityCertificate_APIPassthrough/V1
// would, and answers the first GetCertificate for each certificate with
// RequestInProgressException so the demo exercises omega's polling.
// Requests must carry a SigV4 Authorization header; the signature
// itself is not verified.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type mock struct {
	caARN   string
	subCert *x509.Certificate
	subKey  *ecdsa.PrivateKey
	subPEM  string
	rootPEM string

	mu     sync.Mutex
	seq    int
	issued map[string]string // certificate ARN -> leaf PEM
	polled map[string]bool   // certificate ARN -> answered "in progress" once
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18392", "listen address")
	caARN := flag.String("ca-arn", "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/demo", "certificate-authority ARN to serve")
	flag.Parse()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	root := mustCA("Mock PCA Root CA", rootKey, nil, nil)
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	sub := mustCA("Mock PCA Issuing CA", subKey, root, rootKey)

	m := &mock{
		caARN:   *caARN,
		subCert: sub,
		subKey:  subKey,
		subPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sub.Raw})),
		rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})),
		issued:  map[string]string{},
		polled:  map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("POST /", m.serve)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("mock-pca listening on http://%s for %s", *addr, *caARN)
	log.Fatal(srv.ListenAndServe())
}

func mustCA(cn string, key *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent, parentKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func awsError(w http.ResponseWriter, code, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-ErrorType", code)
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": msg})
}

func (m *mock) serve(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		awsError(w, "MissingAuthenticationTokenException", "request is not SigV4-signed")
		return
	}
	var body map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		awsError(w, "SerializationException", err.Error())
		return
	}
	if body["CertificateAuthorityArn"] != m.caARN {
		awsError(w, "ResourceNotFoundException", "unknown certificate authority")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	op := r.Header.Get("X-Amz-Target")
	log.Printf("%s", op)
	switch op {
	case "ACMPrivateCA.GetCertificateAuthorityCertificate":
		_ = json.NewEncoder(w).Encode(map[string]string{"Certificate": m.subPEM, "CertificateChain": m.rootPEM})
	case "ACMPrivateCA.IssueCertificate":
		leaf, err := m.sign(body)
		if err != nil {
			awsError(w, "MalformedCSRException", err.Error())
			return
		}
		m.mu.Lock()
		m.seq++
		arn := fmt.Sprintf("%s/certificate/%d", m.caARN, m.seq)
		m.issued[arn] = leaf
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"CertificateArn": arn})
	case "ACMPrivateCA.GetCertificate":
		arn, _ := body["CertificateArn"].(string)
		m.mu.Lock()
		leaf, ok := m.issued[arn]
		first := ok && !m.polled[arn]
		m.polled[arn] = true
		m.mu.Unlock()
		switch {
		case !ok:
			awsError(w, "ResourceNotFoundException", "unknown certificate")
		case first:
			awsError(w, "RequestInProgressException", "certificate is being issued")
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"Certificate": leaf, "CertificateChain": m.subPEM + m.rootPEM})
		}
	default:
		awsError(w, "UnknownOperationException", op)
	}
}

// sign issues a leaf the way EndEntityCertificate_APIPassthrough/V1
// does: key from the CSR (a base64 blob of PEM), SAN and subject from
// ApiPassthrough, server + client auth EKUs, validity from the request.
func (m *mock) sign(body map[string]any) (string, error) {
	raw, _ := body["Csr"].(string)
	csrPEM, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return "", fmt.Errorf("csr is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", err
	}
	pt, _ := body["ApiPassthrough"].(map[string]any)
	ext, _ := pt["Extensions"].(map[string]any)
	sans, _ := ext["SubjectAlternativeNames"].([]any)
	var uris []*url.URL
	for _, s := range sans {
		gn, _ := s.(map[string]any)
		if v, ok := gn["UniformResourceIdentifier"].(string); ok {
			u, err := url.Parse(v)
			if err != nil {
				return "", err
			}
			uris = append(uris, u)
		}
	}
	var subject pkix.Name
	if subj, ok := pt["Subject"].(map[string]any); ok {
		subject.CommonName, _ = subj["CommonName"].(string)
	}
	notAfter := time.Now().Add(30 * time.Minute)
	if v, ok := body["Validity"].(map[string]any); ok {
		if secs, ok := v["Value"].(float64); ok {
			notAfter = time.Unix(int64(secs), 0)
		}
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, m.subCert, csr.PublicKey, m.subKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
