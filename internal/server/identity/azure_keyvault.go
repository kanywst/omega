// azure_keyvault.go implements Authority with the CA private key held
// in Azure Key Vault (or Azure Managed HSM). Unlike the Vault PKI and
// step-ca backends, Key Vault is a key store, not a CA: Omega builds
// every certificate and JWT itself and sends only the SHA-256 digest
// to Key Vault's `keys/{name}/{version}/sign` operation. The private
// key never leaves Key Vault, and X.509-SVIDs and JWT-SVIDs are both
// signed by it. ADR 0021 records why this is a remote signer and not a
// hosted CA.
//
// Each issued X.509-SVID and JWT-SVID costs one Key Vault round trip.
// Validation stays local: it needs only the public key, fetched once
// at startup.

package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	azureKeyVaultAPIVersion = "7.4"
	defaultAzureKVTimeout   = 10 * time.Second
	maxAzureKVResponse      = 1 << 20
	// AzureKeyVaultCACertFile is where the self-signed CA certificate
	// is kept under the CA directory when no certificate is supplied.
	AzureKeyVaultCACertFile = "azure-keyvault-ca.crt"
)

// azureKeyVaultAuthority is a localAuthority whose CA key is a Key
// Vault signer. The localAuthority is held in a named field rather
// than embedded so the backend does not pick up ReloadCA: its CA
// material comes from Key Vault and a certificate file, not from a
// rotatable CA directory, and a SIGHUP must not report a failed reload.
type azureKeyVaultAuthority struct {
	local *localAuthority
}

var _ Authority = (*azureKeyVaultAuthority)(nil)

func (a *azureKeyVaultAuthority) TrustDomain() spiffeid.TrustDomain { return a.local.TrustDomain() }
func (a *azureKeyVaultAuthority) BundlePEM() []byte                 { return a.local.BundlePEM() }
func (a *azureKeyVaultAuthority) IssuerURL() string                 { return a.local.IssuerURL() }
func (a *azureKeyVaultAuthority) JWTKeyID() (string, error)         { return a.local.JWTKeyID() }
func (a *azureKeyVaultAuthority) JWTBundle() ([]byte, error)        { return a.local.JWTBundle() }

func (a *azureKeyVaultAuthority) IssueSVID(id spiffeid.ID, csr *x509.CertificateRequest) (*SVID, error) {
	return a.local.IssueSVID(id, csr)
}

func (a *azureKeyVaultAuthority) IssueJWTSVID(id spiffeid.ID, audience []string, ttl time.Duration, extraClaims map[string]any) (*JWTSVID, error) {
	return a.local.IssueJWTSVID(id, audience, ttl, extraClaims)
}

func (a *azureKeyVaultAuthority) ValidateJWTSVID(token, audience string) (spiffeid.ID, error) {
	return a.local.ValidateJWTSVID(token, audience)
}

func (a *azureKeyVaultAuthority) ValidatePresentedCertBinding(token, audience string, presented *x509.Certificate) (spiffeid.ID, error) {
	return a.local.ValidatePresentedCertBinding(token, audience, presented)
}

func (a *azureKeyVaultAuthority) ParseJWTSVIDClaims(token string) (spiffeid.ID, map[string]any, error) {
	return a.local.ParseJWTSVIDClaims(token)
}

// newAzureKeyVaultAuthority resolves the Key Vault key, loads or mints
// the CA certificate for it and returns the authority. Every failure
// is a startup failure: a missing permission or a wrong key surfaces
// here, not at the first issuance.
func newAzureKeyVaultAuthority(td spiffeid.TrustDomain, issuer string, cfg Config) (*azureKeyVaultAuthority, error) {
	vaultURL, err := url.Parse(strings.TrimRight(strings.TrimSpace(cfg.AzureKeyVaultURL), "/"))
	if err != nil {
		return nil, fmt.Errorf("identity: azure-keyvault: vault url: %w", err)
	}
	if err := requireHTTPSOrLoopback(vaultURL); err != nil {
		return nil, fmt.Errorf("identity: azure-keyvault: vault url: %w", err)
	}
	if vaultURL.Host == "" || vaultURL.RawQuery != "" || vaultURL.Fragment != "" || (vaultURL.Path != "" && vaultURL.Path != "/") {
		return nil, fmt.Errorf("identity: azure-keyvault: vault url must be a bare https://<name>.vault.azure.net, got %q", cfg.AzureKeyVaultURL)
	}
	vaultURL.Path = ""
	if strings.ContainsAny(cfg.AzureKeyVaultKeyName, "/?#") || strings.ContainsAny(cfg.AzureKeyVaultKeyVersion, "/?#") {
		return nil, errors.New("identity: azure-keyvault: key name and version must not contain '/', '?' or '#'")
	}

	httpClient := &http.Client{Timeout: defaultAzureKVTimeout}
	getenv := cfg.AzureKeyVaultGetenv
	if getenv == nil {
		getenv = os.Getenv
	}
	cred, err := newAzureCredential(getenv, httpClient, azureKeyVaultScope(vaultURL))
	if err != nil {
		return nil, fmt.Errorf("identity: azure-keyvault: %w", err)
	}
	kv := &azureKeyVaultClient{
		vault:  vaultURL.String(),
		client: httpClient,
		tokens: &azureTokenCache{cred: cred},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*defaultAzureKVTimeout)
	defer cancel()
	signer, err := kv.resolveSigner(ctx, cfg.AzureKeyVaultKeyName, cfg.AzureKeyVaultKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("identity: azure-keyvault: %w", err)
	}

	active, extra, err := loadOrMintAzureCA(cfg, signer)
	if err != nil {
		return nil, fmt.Errorf("identity: azure-keyvault: %w", err)
	}

	local := &localAuthority{trustDomain: td, issuerURL: issuer}
	local.state.Store(newCAState(active, signer, extra...))
	local.seq.Store(1)
	return &azureKeyVaultAuthority{local: local}, nil
}

// azureKeyVaultScope derives the OAuth scope from the vault host: the
// host from its "vault" or "managedhsm" label on. That maps
// myvault.vault.azure.net (and its privatelink name) to
// https://vault.azure.net/.default, and covers Managed HSM and the
// sovereign clouds (vault.usgovcloudapi.net, vault.azure.cn). Any
// other host, such as a loopback test server, gets the public cloud
// scope.
func azureKeyVaultScope(u *url.URL) string {
	labels := strings.Split(u.Hostname(), ".")
	for i, l := range labels {
		if (l == "vault" || l == "managedhsm") && i > 0 && i < len(labels)-1 {
			return "https://" + strings.Join(labels[i:], ".") + "/.default"
		}
	}
	return "https://vault.azure.net/.default"
}

// loadOrMintAzureCA returns the CA certificate for signer's key and
// any other certificates to trust beside it. A supplied certificate
// file is used as given. Without one, the certificate is read from the
// CA directory, and minted there (self-signed through Key Vault) on
// first start.
func loadOrMintAzureCA(cfg Config, signer *azureKeyVaultSigner) (*x509.Certificate, []*x509.Certificate, error) {
	path := strings.TrimSpace(cfg.AzureKeyVaultCACertFile)
	supplied := path != ""
	if !supplied {
		if cfg.Dir == "" {
			return nil, nil, errors.New("no CA certificate file and no CA directory to keep a self-signed one in")
		}
		if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("ca dir: %w", err)
		}
		path = filepath.Join(cfg.Dir, AzureKeyVaultCACertFile)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			cert, err := mintAzureCA(signer)
			if err != nil {
				return nil, nil, err
			}
			if err := writeFileSync(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
				return nil, nil, fmt.Errorf("write %s: %w", path, err)
			}
			return cert, nil, nil
		}
	}
	certs, err := readCertBundle(path)
	if err != nil {
		return nil, nil, err
	}
	active, extra, err := pickAzureCA(certs, signer)
	if err != nil {
		if supplied {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		return nil, nil, fmt.Errorf("%s: %w (the key changed since this certificate was minted: pin the old key version, or move the file aside to mint a new CA, which workloads must then trust)", path, err)
	}
	return active, extra, nil
}

// pickAzureCA splits certs into the one whose public key is signer's
// key, which signs, and the rest, which are trusted only. Extra
// certificates let an operator keep a previous or next CA trusted
// across a key rotation.
func pickAzureCA(certs []*x509.Certificate, signer *azureKeyVaultSigner) (*x509.Certificate, []*x509.Certificate, error) {
	var active *x509.Certificate
	var extra []*x509.Certificate
	now := time.Now()
	for _, c := range certs {
		if active == nil && keyMatches(signer, c) {
			active = c
			continue
		}
		extra = append(extra, c)
	}
	if active == nil {
		return nil, nil, fmt.Errorf("no certificate matches Key Vault key %s", signer.keyID)
	}
	if !active.IsCA || !active.BasicConstraintsValid || active.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("the certificate for the Key Vault key is not a CA certificate (needs basicConstraints CA:TRUE and keyCertSign)")
	}
	if err := active.CheckSignatureFrom(active); err != nil {
		return nil, nil, fmt.Errorf("the certificate for the Key Vault key is not a self-signed root (certificate chains are not supported): %w", err)
	}
	if now.Before(active.NotBefore) || now.After(active.NotAfter) {
		return nil, nil, fmt.Errorf("the certificate for the Key Vault key is not valid now (valid %s to %s)", active.NotBefore.Format(time.RFC3339), active.NotAfter.Format(time.RFC3339))
	}
	// The other certificates are published as trust anchors in the
	// bundle and the JWKS, so they get the same checks bar the key.
	for _, c := range extra {
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, nil, fmt.Errorf("trusted CA certificate %q must carry an ECDSA P-256 key", c.Subject.CommonName)
		}
		if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, nil, fmt.Errorf("trusted certificate %q is not a CA certificate (needs basicConstraints CA:TRUE and keyCertSign)", c.Subject.CommonName)
		}
		if now.After(c.NotAfter) {
			return nil, nil, fmt.Errorf("trusted CA certificate %q expired at %s; remove it", c.Subject.CommonName, c.NotAfter.Format(time.RFC3339))
		}
	}
	return active, extra, nil
}

// mintAzureCA self-signs a CA certificate through Key Vault.
func mintAzureCA(signer crypto.Signer) (*x509.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Omega Key Vault CA"},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca through key vault: %w", err)
	}
	return x509.ParseCertificate(der)
}

func readCertBundle(path string) ([]*x509.Certificate, error) {
	// #nosec G304 -- operator-supplied via --ca-azure-keyvault-ca-cert or the CA directory.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ca cert in %s: %w", filepath.Base(path), err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s has no PEM certificates", filepath.Base(path))
	}
	return certs, nil
}

// requireHTTPSOrLoopback refuses to send a bearer token over plain
// http, except to a loopback address (tests, a local proxy).
func requireHTTPSOrLoopback(u *url.URL) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("must use https (got http for non-loopback host %q)", host)
	default:
		return fmt.Errorf("must use https (got %q)", u.Scheme)
	}
}

// azureKeyVaultClient calls the two Key Vault key operations Omega
// needs: get key and sign.
type azureKeyVaultClient struct {
	vault  string
	client *http.Client
	tokens *azureTokenCache
}

type azureKVError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// do sends one authenticated request and decodes a 200 response into
// out. A 401 drops the cached token so the next call fetches a fresh
// one; the call itself is not retried.
func (c *azureKeyVaultClient) do(ctx context.Context, method, path string, in, out any) error {
	tok, err := c.tokens.token(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.vault+path+"?api-version="+azureKeyVaultAPIVersion, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("key vault %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAzureKVResponse))
	if err != nil {
		return fmt.Errorf("key vault %s %s: read: %w", method, path, err)
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			c.tokens.invalidate()
		}
		var kvErr azureKVError
		if json.Unmarshal(raw, &kvErr) == nil && kvErr.Error.Code != "" {
			return fmt.Errorf("key vault %s %s returned %d: %s: %s", method, path, resp.StatusCode, kvErr.Error.Code, firstLine(kvErr.Error.Message))
		}
		return fmt.Errorf("key vault %s %s returned %d", method, path, resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("key vault %s %s: decode: %w", method, path, err)
	}
	return nil
}

// resolveSigner fetches the key (the current version when version is
// empty) and returns a signer pinned to that exact version, so every
// signature of this process comes from one key even if a new version
// is created meanwhile.
func (c *azureKeyVaultClient) resolveSigner(ctx context.Context, name, version string) (*azureKeyVaultSigner, error) {
	path := "/keys/" + url.PathEscape(name)
	if version != "" {
		path += "/" + url.PathEscape(version)
	}
	var out struct {
		Key struct {
			KID    string   `json:"kid"`
			KTY    string   `json:"kty"`
			CRV    string   `json:"crv"`
			X      string   `json:"x"`
			Y      string   `json:"y"`
			KeyOps []string `json:"key_ops"`
		} `json:"key"`
		Attributes struct {
			Enabled *bool `json:"enabled"`
		} `json:"attributes"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	k := out.Key
	if k.KTY != "EC" && k.KTY != "EC-HSM" {
		return nil, fmt.Errorf("key %q has type %q; only EC P-256 keys are supported", name, k.KTY)
	}
	if k.CRV != "P-256" {
		return nil, fmt.Errorf("key %q is on curve %q; only P-256 is supported", name, k.CRV)
	}
	if out.Attributes.Enabled != nil && !*out.Attributes.Enabled {
		return nil, fmt.Errorf("key %q is disabled", name)
	}
	if len(k.KeyOps) > 0 && !containsString(k.KeyOps, "sign") {
		return nil, fmt.Errorf("key %q does not permit the sign operation (key_ops %v)", name, k.KeyOps)
	}
	pub, err := azureECPublicKey(k.X, k.Y)
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", name, err)
	}
	kidURL, err := url.Parse(k.KID)
	if err != nil {
		return nil, fmt.Errorf("key %q: kid: %w", name, err)
	}
	parts := strings.Split(strings.Trim(kidURL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "keys" || parts[1] != name || parts[2] == "" {
		return nil, fmt.Errorf("key %q: unexpected kid %q", name, k.KID)
	}
	if version != "" && parts[2] != version {
		return nil, fmt.Errorf("key %q: asked for version %q, Key Vault returned %q", name, version, parts[2])
	}
	return &azureKeyVaultSigner{
		kv:      c,
		path:    "/keys/" + url.PathEscape(name) + "/" + url.PathEscape(parts[2]),
		keyID:   name + "/" + parts[2],
		pub:     pub,
		timeout: defaultAzureKVTimeout,
	}, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func azureECPublicKey(x, y string) (*ecdsa.PublicKey, error) {
	xb, err := decodeAzureB64(x)
	if err != nil {
		return nil, fmt.Errorf("x: %w", err)
	}
	yb, err := decodeAzureB64(y)
	if err != nil {
		return nil, fmt.Errorf("y: %w", err)
	}
	if len(xb) > 32 || len(yb) > 32 {
		return nil, errors.New("P-256 coordinates longer than 32 bytes")
	}
	point := make([]byte, 65)
	point[0] = 4
	copy(point[1+32-len(xb):33], xb)
	copy(point[33+32-len(yb):], yb)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("not a P-256 point: %w", err)
	}
	return pub, nil
}

// decodeAzureB64 decodes Key Vault's base64url, which may or may not
// carry padding.
func decodeAzureB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// azureKeyVaultSigner is a crypto.Signer whose private key is a Key
// Vault key version. Sign sends the digest to Key Vault and verifies
// the returned signature against the public key fetched at startup
// before using it, so a signature from any other key is refused.
type azureKeyVaultSigner struct {
	kv      *azureKeyVaultClient
	path    string
	keyID   string // name/version, for messages
	pub     *ecdsa.PublicKey
	timeout time.Duration
}

var _ crypto.Signer = (*azureKeyVaultSigner)(nil)

func (s *azureKeyVaultSigner) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer for ECDSA with SHA-256 and returns an
// ASN.1 DER signature, which is what crypto/x509 expects.
func (s *azureKeyVaultSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("azure key vault signer supports only ES256 (SHA-256)")
	}
	r, sig, err := s.signDigest(digest)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, sig})
}

// signRaw returns the JWS form of an ES256 signature over payload: the
// 64-byte R || S concatenation Key Vault itself returns.
func (s *azureKeyVaultSigner) signRaw(payload []byte) ([]byte, error) {
	sum := sha256.Sum256(payload)
	r, sig, err := s.signDigest(sum[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	sig.FillBytes(out[32:])
	return out, nil
}

func (s *azureKeyVaultSigner) signDigest(digest []byte) (*big.Int, *big.Int, error) {
	if len(digest) != sha256.Size {
		return nil, nil, fmt.Errorf("digest is %d bytes, want %d", len(digest), sha256.Size)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	var out struct {
		Value string `json:"value"`
	}
	in := map[string]string{"alg": "ES256", "value": base64.RawURLEncoding.EncodeToString(digest)}
	if err := s.kv.do(ctx, http.MethodPost, s.path+"/sign", in, &out); err != nil {
		return nil, nil, err
	}
	raw, err := decodeAzureB64(out.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("key vault sign: signature is not base64url: %w", err)
	}
	if len(raw) != 64 {
		return nil, nil, fmt.Errorf("key vault sign: ES256 signature is %d bytes, want 64", len(raw))
	}
	r := new(big.Int).SetBytes(raw[:32])
	sig := new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(s.pub, digest, r, sig) {
		return nil, nil, fmt.Errorf("key vault sign: signature does not verify under key %s", s.keyID)
	}
	return r, sig, nil
}

// joseSigner adapts the signer for go-jose, which takes a remote key
// as an OpaqueSigner rather than a crypto.Signer.
func (s *azureKeyVaultSigner) joseSigner() jose.OpaqueSigner { return azureJOSESigner{s} }

type azureJOSESigner struct{ s *azureKeyVaultSigner }

func (j azureJOSESigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: j.s.pub, Algorithm: string(jose.ES256), Use: "sig"}
}

func (j azureJOSESigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

func (j azureJOSESigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.ES256 {
		return nil, fmt.Errorf("azure key vault signer supports only ES256, not %s", alg)
	}
	return j.s.signRaw(payload)
}
