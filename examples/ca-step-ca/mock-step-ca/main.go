// mock-step-ca is a tiny stand-in for Smallstep step-ca for the
// examples/ca-step-ca demo. It generates its own ECDSA Root CA at
// startup and serves the two endpoints omega calls:
//
//	GET  /roots.pem
//	POST /1.0/sign
//
// /1.0/sign verifies the OTT against a known provisioner public JWK
// the demo writes to disk at boot; a bad signature / wrong iss /
// stale exp / wrong sha gets a 401. That keeps the demo honest: a
// regression that breaks omega's OTT signing trips it.
//
// The point of a custom mock (vs. running real step-ca) is the same
// as for mock-vault: the demo stays shell-only, CI gets a fast
// example, and the assertions can stay focused on the omega side of
// the wire.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18590", "listen address")
	provisionerName := flag.String("provisioner", "omega", "expected JWK provisioner name (OTT `iss` claim)")
	pubJWKFile := flag.String("provisioner-pub-jwk", "", "path to the provisioner public JWK (JSON or PEM)")
	flag.Parse()

	if *pubJWKFile == "" {
		log.Fatalf("mock-step-ca: --provisioner-pub-jwk is required")
	}
	// #nosec G304 -- demo binary, path comes from the wrapper script.
	pubJWKBytes, err := os.ReadFile(*pubJWKFile)
	if err != nil {
		log.Fatalf("mock-step-ca: read pub jwk: %v", err)
	}
	if block, _ := pem.Decode(pubJWKBytes); block != nil {
		pubJWKBytes = block.Bytes
	}
	var pubJWK jose.JSONWebKey
	if err := pubJWK.UnmarshalJSON(pubJWKBytes); err != nil {
		log.Fatalf("mock-step-ca: parse pub jwk: %v", err)
	}
	if !pubJWK.IsPublic() {
		log.Fatalf("mock-step-ca: --provisioner-pub-jwk must be a public JWK")
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("mock-step-ca: gen ca key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mock step-ca Root CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatalf("mock-step-ca: sign ca: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	rootSum := sha256.Sum256(caDER)
	rootSHA := hex.EncodeToString(rootSum[:])

	mux := http.NewServeMux()
	mux.HandleFunc("GET /roots.pem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(caPEM)
	})
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CSR string `json:"csr"`
			OTT string `json:"ott"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		// OTT verification: signature against the configured provisioner
		// public JWK, then claim-level checks for the fields omega
		// promises to bind.
		sig, err := jose.ParseSigned(req.OTT, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			http.Error(w, "parse ott: "+err.Error(), http.StatusUnauthorized)
			return
		}
		raw, err := sig.Verify(&pubJWK)
		if err != nil {
			http.Error(w, "verify ott signature: "+err.Error(), http.StatusUnauthorized)
			return
		}
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err != nil {
			http.Error(w, "ott claims: "+err.Error(), http.StatusBadRequest)
			return
		}
		if iss, _ := claims["iss"].(string); iss != *provisionerName {
			http.Error(w, "ott iss mismatch", http.StatusUnauthorized)
			return
		}
		if sha, _ := claims["sha"].(string); sha != rootSHA {
			http.Error(w, "ott sha pin does not match served root", http.StatusUnauthorized)
			return
		}
		if exp, ok := claims["exp"].(float64); !ok || int64(exp) < time.Now().Unix() {
			http.Error(w, "ott expired or missing exp", http.StatusUnauthorized)
			return
		}
		sans, _ := claims["sans"].([]any)
		if len(sans) == 0 {
			http.Error(w, "ott has no sans", http.StatusUnauthorized)
			return
		}
		first, _ := sans[0].(string)
		uri, err := url.Parse(first)
		if err != nil {
			http.Error(w, "ott san[0] is not a URL: "+err.Error(), http.StatusBadRequest)
			return
		}

		csrBlock, _ := pem.Decode([]byte(req.CSR))
		if csrBlock == nil {
			http.Error(w, "csr is not PEM", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
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
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(30 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			URIs:         []*url.URL{uri},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"crt": string(leafPEM),
			"ca":  string(caPEM),
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("mock-step-ca: provisioner=%s listening on http://%s", *provisionerName, *addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("mock-step-ca: listen: %v", err)
	}
}
