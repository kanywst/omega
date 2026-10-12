package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// loadBundleSigningKey reads an ECDSA P-256 private key (SEC 1 or PKCS #8
// PEM) used to sign policy bundles.
func loadBundleSigningKey(path string) (*ecdsa.PrivateKey, error) {
	// #nosec G304 -- operator-supplied --policy-bundle-signing-key path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --policy-bundle-signing-key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("--policy-bundle-signing-key holds no PEM block")
	}
	var key any
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("--policy-bundle-signing-key: unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse --policy-bundle-signing-key: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("--policy-bundle-signing-key must be an ECDSA P-256 key")
	}
	return ec, nil
}

// loadBundleVerifyKey reads the public half of the bundle signing key, as
// a PUBLIC KEY PEM block or a certificate.
func loadBundleVerifyKey(path string) (*ecdsa.PublicKey, error) {
	// #nosec G304 -- operator-supplied --policy-bundle-key path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read --policy-bundle-key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("--policy-bundle-key holds no PEM block")
	}
	var pub any
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(block.Bytes); err == nil {
			pub = cert.PublicKey
		}
	default:
		return nil, fmt.Errorf("--policy-bundle-key: unsupported PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse --policy-bundle-key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("--policy-bundle-key must be an ECDSA P-256 public key")
	}
	return ec, nil
}
