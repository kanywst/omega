package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/go-jose/go-jose/v4"
)

// JWTSVIDAlgs are the JWS algorithms a JWT-SVID may be signed with: the
// ones SPIRE uses for each of its jwt_key_type values (ec-p256 -> ES256,
// ec-p384 -> ES384, rsa-2048 / rsa-4096 -> RS256).
var JWTSVIDAlgs = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256}

// minRSAKeyBits is the smallest RSA modulus accepted as a JWT-SVID
// signing key. SPIRE's smallest RSA key type is rsa-2048.
const minRSAKeyBits = 2048

// JWTVerificationKey is one JWT-SVID signing key and the single algorithm
// it verifies. Pinning the algorithm to the key, rather than accepting any
// algorithm the key type could verify, is what keeps a token's alg header
// from choosing how its own signature is checked.
type JWTVerificationKey struct {
	Key crypto.PublicKey
	Alg jose.SignatureAlgorithm
}

// JWK is the subset of RFC 7517 / 7518 members omega reads from a JWT
// bundle.
type JWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	N      string   `json:"n"`
	E      string   `json:"e"`
}

// signingAlg reports the JWT-SVID algorithm k would verify, or false when
// k is structurally not a JWT-SVID signing key omega consumes: another key
// type or curve, a non-signing use, key_ops without "verify", or an alg
// other than the one its key type is pinned to. Such keys are skipped
// (RFC 7517 §5), so a heterogeneous JWKS stays usable.
func (k JWK) signingAlg() (jose.SignatureAlgorithm, bool) {
	var alg jose.SignatureAlgorithm
	switch {
	case k.Kty == "EC" && k.Crv == "P-256":
		alg = jose.ES256
	case k.Kty == "EC" && k.Crv == "P-384":
		alg = jose.ES384
	case k.Kty == "RSA":
		alg = jose.RS256
	default:
		return "", false
	}
	if k.Use != "" && k.Use != "sig" {
		return "", false
	}
	// An RSA key advertising RS512 or PS256, or an EC key advertising a
	// key-agreement alg such as ECDH-ES, is not the signer this key type is
	// pinned to; treating it as one would verify with an algorithm the
	// issuer never declared.
	if k.Alg != "" && k.Alg != string(alg) {
		return "", false
	}
	if len(k.KeyOps) > 0 && !slices.Contains(k.KeyOps, "verify") {
		return "", false
	}
	return alg, true
}

// ParseJWTSigningKey decodes k as a JWT-SVID verification key. ok is false
// when k is not a key omega consumes (see signingAlg), in which case the
// caller skips it. A key that is recognised but cannot be decoded (a bad
// coordinate, an off-curve point, a short RSA modulus) is an error, not a
// skip: it is a corrupt trust anchor, not a foreign one.
func ParseJWTSigningKey(k JWK) (key JWTVerificationKey, ok bool, err error) {
	alg, ok := k.signingAlg()
	if !ok {
		return JWTVerificationKey{}, false, nil
	}
	var pub crypto.PublicKey
	switch alg {
	case jose.ES256:
		pub, err = ecPublicKeyFromJWK(elliptic.P256(), 32, k.X, k.Y)
	case jose.ES384:
		pub, err = ecPublicKeyFromJWK(elliptic.P384(), 48, k.X, k.Y)
	case jose.RS256:
		pub, err = rsaPublicKeyFromJWK(k.N, k.E)
	}
	if err != nil {
		return JWTVerificationKey{}, true, err
	}
	return JWTVerificationKey{Key: pub, Alg: alg}, true, nil
}

// canonicalJWK is the public-only re-encoding of key served at
// /v1/jwt/bundle. Members are rebuilt from the decoded key rather than
// copied, so a reformatted upstream file is not mistaken for a rotation.
func canonicalJWK(kid string, key JWTVerificationKey) (map[string]string, error) {
	enc := base64.RawURLEncoding
	out := map[string]string{"alg": string(key.Alg), "use": "sig", "kid": kid}
	switch pub := key.Key.(type) {
	case *ecdsa.PublicKey:
		point, err := pub.Bytes()
		if err != nil {
			return nil, err
		}
		size := (len(point) - 1) / 2
		out["kty"] = "EC"
		out["crv"] = pub.Curve.Params().Name
		out["x"] = enc.EncodeToString(point[1 : 1+size])
		out["y"] = enc.EncodeToString(point[1+size:])
	case *rsa.PublicKey:
		out["kty"] = "RSA"
		out["n"] = enc.EncodeToString(pub.N.Bytes())
		out["e"] = enc.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	default:
		return nil, fmt.Errorf("unsupported key type %T", key.Key)
	}
	return out, nil
}

// ecPublicKeyFromJWK decodes a base64url EC point (x, y) of the given
// coordinate size. ParseUncompressedPublicKey performs the on-curve and
// point-at-infinity checks itself, so the SEC 1 uncompressed encoding is
// the whole validation step.
func ecPublicKeyFromJWK(curve elliptic.Curve, size int, x, y string) (*ecdsa.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("jwk x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("jwk y: %w", err)
	}
	name := curve.Params().Name
	if len(xb) != size || len(yb) != size {
		return nil, fmt.Errorf("jwk %s coordinates must be %d bytes each (got x=%d, y=%d)", name, size, len(xb), len(yb))
	}
	point := make([]byte, 0, 1+2*size)
	point = append(point, 0x04)
	point = append(point, xb...)
	point = append(point, yb...)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("jwk point is not on the %s curve: %w", name, err)
	}
	return pub, nil
}

func rsaPublicKeyFromJWK(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("jwk n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("jwk e: %w", err)
	}
	if len(nb) == 0 || nb[0] == 0 {
		return nil, errors.New("jwk n must be a non-empty big-endian integer without leading zeros")
	}
	modulus := new(big.Int).SetBytes(nb)
	if bits := modulus.BitLen(); bits < minRSAKeyBits {
		return nil, fmt.Errorf("jwk RSA modulus is %d bits, want at least %d", bits, minRSAKeyBits)
	}
	if len(eb) == 0 || len(eb) > 4 || eb[0] == 0 {
		return nil, errors.New("jwk e must be a big-endian integer of 1 to 4 bytes without leading zeros")
	}
	exp := new(big.Int).SetBytes(eb).Int64()
	if exp < 3 || exp%2 == 0 {
		return nil, fmt.Errorf("jwk RSA exponent %d is not an odd integer of at least 3", exp)
	}
	return &rsa.PublicKey{N: modulus, E: int(exp)}, nil
}
