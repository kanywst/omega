// keygen emits a fresh ECDSA P-256 JWK pair for the
// examples/ca-step-ca demo. omega loads the private side via
// --ca-step-ca-provisioner-key-file; mock-step-ca loads the public
// side via --provisioner-pub-jwk and uses it to verify the OTT
// signatures omega mints per /1.0/sign request.
//
// Kept inline (one tiny Go file under the example dir) so the demo
// is hermetic: nothing persists past `make down`, and there is no
// long-lived key on disk between demo runs.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"log"
	"os"

	"github.com/go-jose/go-jose/v4"
)

func main() {
	outPriv := flag.String("out-priv", "", "output path for the private JWK")
	outPub := flag.String("out-pub", "", "output path for the public JWK")
	flag.Parse()
	if *outPriv == "" || *outPub == "" {
		log.Fatal("keygen: --out-priv and --out-pub are required")
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("keygen: gen ecdsa: %v", err)
	}
	// kid derives from the SubjectPublicKeyInfo encoding so omega
	// and mock-step-ca see the same id without any extra
	// coordination, and we stay clear of the deprecated direct
	// access to (*PublicKey).X / .Y.
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		log.Fatalf("keygen: marshal spki: %v", err)
	}
	sum := sha256.Sum256(spki)
	kid := base64.RawURLEncoding.EncodeToString(sum[:8])

	privJWK := jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	pubJWK := privJWK.Public()

	privBytes, err := privJWK.MarshalJSON()
	if err != nil {
		log.Fatalf("keygen: marshal priv: %v", err)
	}
	pubBytes, err := pubJWK.MarshalJSON()
	if err != nil {
		log.Fatalf("keygen: marshal pub: %v", err)
	}
	if err := os.WriteFile(*outPriv, privBytes, 0o600); err != nil {
		log.Fatalf("keygen: write priv: %v", err)
	}
	if err := os.WriteFile(*outPub, pubBytes, 0o600); err != nil {
		log.Fatalf("keygen: write pub: %v", err)
	}
}
