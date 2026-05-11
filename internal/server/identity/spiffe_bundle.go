// SPIFFE Trust Domain Format (TDF) bundle assembly.
//
// SPIFFE Trust Domain and Bundle 1.0 §4 defines the native bundle
// format: a single JSON document with `spiffe_sequence`,
// `spiffe_refresh_hint`, and a `keys` array of JWKs. Each key carries a
// `use` parameter of either `x509-svid` (a trust anchor) or `jwt-svid`
// (a JWT signing key).
//
// BuildSPIFFEBundle assembles that document from any Authority by
// reading the X.509 trust anchors out of BundlePEM() and the JWT
// signing keys out of JWTBundle(), without requiring backend-specific
// changes. Adding a new CA backend (Vault, step-ca, AWS PCA, ...) does
// not require touching this code as long as the new backend keeps the
// two existing accessors working.
package identity

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// SPIFFEBundleOptions parameterises the static fields of the assembled
// document. Backends that one day implement a real key-rotation
// counter pass their stored sequence here; the refresh hint is the
// recommended minimum time a peer should wait before re-fetching.
type SPIFFEBundleOptions struct {
	Sequence    int64
	RefreshHint time.Duration
}

// BuildSPIFFEBundle returns a SPIFFE TDF JSON document for the given
// Authority. The function is a free function rather than an Authority
// method on purpose: every backend already exposes BundlePEM() and
// JWTBundle(), so the assembly is identical across backends and
// belongs in one place. Returns an error if the bundle PEM or JWKS is
// malformed, or if a trust anchor uses an unsupported key type.
func BuildSPIFFEBundle(a Authority, opts SPIFFEBundleOptions) ([]byte, error) {
	x509Keys, err := x509AnchorsAsJWKs(a.BundlePEM())
	if err != nil {
		return nil, fmt.Errorf("x509 anchors: %w", err)
	}
	jwksRaw, err := a.JWTBundle()
	if err != nil {
		return nil, fmt.Errorf("jwt bundle: %w", err)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwksRaw, &jwks); err != nil {
		return nil, fmt.Errorf("parse jwt bundle: %w", err)
	}
	// JWT-SVID JWKs in omega today carry `use: sig`; SPIFFE TDF
	// requires `use: jwt-svid` so peers can tell the JWT signers
	// apart from the X.509 anchors in the same array.
	for i := range jwks.Keys {
		jwks.Keys[i]["use"] = "jwt-svid"
	}

	refreshSeconds := max(int(opts.RefreshHint/time.Second), 0)
	out := map[string]any{
		"spiffe_sequence":     opts.Sequence,
		"spiffe_refresh_hint": refreshSeconds,
		"keys":                append(x509Keys, jwks.Keys...),
	}
	return json.Marshal(out)
}

func x509AnchorsAsJWKs(bundlePEM []byte) ([]map[string]any, error) {
	var out []map[string]any
	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse trust anchor: %w", err)
		}
		jwk, err := certToJWK(cert, block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, jwk)
	}
	return out, nil
}

func certToJWK(cert *x509.Certificate, der []byte) (map[string]any, error) {
	jwk := map[string]any{
		"use": "x509-svid",
		"x5c": []string{base64.StdEncoding.EncodeToString(der)},
	}
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		crv, err := ecCurveName(pub)
		if err != nil {
			return nil, err
		}
		point, err := ecPointBytes(pub)
		if err != nil {
			return nil, err
		}
		coordLen := (pub.Curve.Params().BitSize + 7) / 8
		// SEC1 uncompressed point: first byte is 0x04, then X || Y of
		// equal length.
		if len(point) != 1+2*coordLen {
			return nil, fmt.Errorf("unexpected EC point length %d for curve %s", len(point), crv)
		}
		jwk["kty"] = "EC"
		jwk["crv"] = crv
		jwk["x"] = base64.RawURLEncoding.EncodeToString(point[1 : 1+coordLen])
		jwk["y"] = base64.RawURLEncoding.EncodeToString(point[1+coordLen:])
	case *rsa.PublicKey:
		jwk["kty"] = "RSA"
		jwk["n"] = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk["e"] = base64.RawURLEncoding.EncodeToString(bigIntFromInt(pub.E).Bytes())
	default:
		return nil, fmt.Errorf("unsupported trust anchor key type %T", cert.PublicKey)
	}
	return jwk, nil
}

func ecCurveName(pub *ecdsa.PublicKey) (string, error) {
	switch pub.Curve.Params().Name {
	case "P-256":
		return "P-256", nil
	case "P-384":
		return "P-384", nil
	case "P-521":
		return "P-521", nil
	default:
		return "", errors.New("unsupported EC curve " + pub.Curve.Params().Name)
	}
}

func bigIntFromInt(v int) *big.Int { return big.NewInt(int64(v)) }
