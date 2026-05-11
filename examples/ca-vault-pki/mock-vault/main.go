// mock-vault is a tiny stand-in for HashiCorp Vault's PKI engine
// for the examples/ca-vault-pki demo. It generates its own ECDSA
// CA at startup and serves the two endpoints omega calls:
//
//   GET  /v1/<mount>/ca_chain
//   POST /v1/<mount>/sign/<role>
//
// All requests must carry the configured X-Vault-Token header; any
// other path returns 404. The point of a custom mock here (vs.
// running real Vault dev mode in docker) is that the demo's
// assertions can stay shell-only and the CI matrix gets a 5-second
// example instead of a 30-second one.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18290", "listen address")
	mount := flag.String("mount", "pki", "PKI mount path")
	role := flag.String("role", "omega", "PKI role")
	token := flag.String("token", "demo-token", "expected X-Vault-Token header value")
	flag.Parse()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("mock-vault: gen ca key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mock Vault Root CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("mock-vault: sign ca: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	authed := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Vault-Token") != *token {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/"+*mount+"/ca_chain", authed(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(caPEM)
	}))
	mux.HandleFunc("POST /v1/"+*mount+"/sign/"+*role, authed(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CSR        string `json:"csr"`
			CommonName string `json:"common_name"`
			URISans    string `json:"uri_sans"`
			TTL        string `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		csrBlock, _ := pem.Decode([]byte(req.CSR))
		if csrBlock == nil {
			http.Error(w, "csr is not PEM", http.StatusBadRequest)
			return
		}
		parsed, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			http.Error(w, "parse csr: "+err.Error(), http.StatusBadRequest)
			return
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			http.Error(w, "serial: "+err.Error(), http.StatusInternalServerError)
			return
		}
		leafTpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: req.CommonName},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(30 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		if req.URISans != "" {
			for raw := range strings.SplitSeq(req.URISans, ",") {
				u, err := url.Parse(strings.TrimSpace(raw))
				if err != nil {
					http.Error(w, "parse uri san "+raw+": "+err.Error(), http.StatusBadRequest)
					return
				}
				leafTpl.URIs = append(leafTpl.URIs, u)
			}
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, parsed.PublicKey, caKey)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": string(leafPEM),
				"ca_chain":    []string{string(caPEM)},
			},
		})
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	// Token is intentionally absent from the log line - even in a
	// demo it is the kind of value that should not show up in CI
	// logs or terminal scrollback.
	log.Printf("mock-vault: mount=%s role=%s listening on http://%s",
		*mount, *role, *addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("mock-vault: listen: %v", err)
	}
}
