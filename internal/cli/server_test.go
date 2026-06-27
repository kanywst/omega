package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/federation"
)

func TestHasNonEmpty(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{"nil", nil, false},
		{"empty slice", []string{}, false},
		{"single blank", []string{"  "}, false},
		{"empty string", []string{""}, false},
		{"one real value", []string{"https://omega.example.com"}, true},
		{"blank then real", []string{"", "omega"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasNonEmpty(tc.in); got != tc.want {
				t.Errorf("hasNonEmpty(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseFederatePeersRejectsHTTP(t *testing.T) {
	// http:// must be rejected by default: an unauthenticated fetch
	// lets a MITM inject a rogue CA as a trusted federated anchor.
	_, err := parseFederatePeers([]string{"name=omega.beta,url=http://127.0.0.1:18089"}, false)
	if err == nil {
		t.Fatal("expected http:// federation peer to be rejected without --federation-allow-insecure")
	}
	if !strings.Contains(err.Error(), "http://") {
		t.Fatalf("error should call out the http scheme, got: %v", err)
	}
}

func TestParseFederatePeersAllowsHTTPWithInsecureFlag(t *testing.T) {
	peers, err := parseFederatePeers([]string{"name=omega.beta,url=http://127.0.0.1:18089"}, true)
	if err != nil {
		t.Fatalf("http peer should be allowed with the insecure flag: %v", err)
	}
	if len(peers) != 1 || peers[0].URL != "http://127.0.0.1:18089" {
		t.Fatalf("unexpected peers: %+v", peers)
	}
}

func TestParseFederatePeersDefaultsToHTTPSWeb(t *testing.T) {
	peers, err := parseFederatePeers([]string{"name=omega.beta,url=https://omega.beta:8443"}, false)
	if err != nil {
		t.Fatalf("https web peer should parse: %v", err)
	}
	if len(peers) != 1 {
		t.Fatalf("want 1 peer, got %d", len(peers))
	}
	if peers[0].Profile != federation.ProfileHTTPSWeb {
		t.Fatalf("default profile should be https_web, got %q", peers[0].Profile)
	}
}

func TestParseFederatePeersHTTPSSPIFFE(t *testing.T) {
	spec := "name=omega.beta,url=https://omega.beta:8443,profile=https_spiffe," +
		"endpoint_spiffe_id=spiffe://omega.beta/control-plane,endpoint_bundle=/etc/omega/beta.pem"
	peers, err := parseFederatePeers([]string{spec}, false)
	if err != nil {
		t.Fatalf("https_spiffe peer should parse: %v", err)
	}
	p := peers[0]
	if p.Profile != federation.ProfileHTTPSSPIFFE ||
		p.EndpointSPIFFEID != "spiffe://omega.beta/control-plane" ||
		p.EndpointBundleFile != "/etc/omega/beta.pem" {
		t.Fatalf("unexpected parsed peer: %+v", p)
	}
}

func TestParseFederatePeersHTTPSSPIFFERequiresPins(t *testing.T) {
	cases := map[string]string{
		"missing endpoint_spiffe_id": "name=omega.beta,url=https://omega.beta:8443,profile=https_spiffe,endpoint_bundle=/etc/omega/beta.pem",
		"missing endpoint_bundle":    "name=omega.beta,url=https://omega.beta:8443,profile=https_spiffe,endpoint_spiffe_id=spiffe://omega.beta/cp",
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFederatePeers([]string{spec}, false); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

// endpoint_ca is a web-PKI knob; under https_spiffe verification uses the
// SPIFFE bundle, so endpoint_ca would be silently ignored and must error.
func TestParseFederatePeersRejectsEndpointCAUnderHTTPSSPIFFE(t *testing.T) {
	spec := "name=omega.beta,url=https://omega.beta:8443,profile=https_spiffe," +
		"endpoint_spiffe_id=spiffe://omega.beta/cp,endpoint_bundle=/etc/omega/beta.pem,endpoint_ca=/etc/omega/web.pem"
	if _, err := parseFederatePeers([]string{spec}, false); err == nil {
		t.Fatal("expected endpoint_ca under https_spiffe to be rejected")
	}
}

func TestParseFederatePeersUnknownProfile(t *testing.T) {
	if _, err := parseFederatePeers([]string{"name=omega.beta,url=https://omega.beta:8443,profile=mtls_web"}, false); err == nil {
		t.Fatal("expected unknown profile to be rejected")
	}
}

// Pins under the web-PKI profile are silently ineffective, so supplying
// them with profile=https_web (or default) is a footgun and must error
// rather than quietly verify by web-PKI only.
func TestParseFederatePeersRejectsPinsUnderHTTPSWeb(t *testing.T) {
	cases := map[string]string{
		"spiffe_id under web": "name=omega.beta,url=https://omega.beta:8443,endpoint_spiffe_id=spiffe://omega.beta/cp",
		"bundle under web":    "name=omega.beta,url=https://omega.beta:8443,profile=https_web,endpoint_bundle=/etc/omega/beta.pem",
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFederatePeers([]string{spec}, false); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

// Peer clients are keyed by trust domain; a duplicate name would
// overwrite the earlier peer's verifying client, so it must be rejected.
func TestParseFederatePeersRejectsDuplicateName(t *testing.T) {
	specs := []string{
		"name=omega.beta,url=https://omega.beta:8443",
		"name=omega.beta,url=https://other.beta:8443",
	}
	if _, err := parseFederatePeers(specs, false); err == nil {
		t.Fatal("expected duplicate peer name to be rejected")
	}
}

// Enabling --k8s-attest without an audience leaves TokenReview's
// audience check disabled, which lets any pod's default ServiceAccount
// token be replayed. The server must refuse to start in that state.
func TestServerCommandRequiresK8sTokenAudience(t *testing.T) {
	cmd := newServerCommand()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--k8s-attest",
		"--data-dir", t.TempDir(),
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected startup to fail when --k8s-attest is on but no --k8s-token-audience is set")
	}
	if !strings.Contains(err.Error(), "k8s-token-audience") {
		t.Fatalf("error should mention the missing audience flag, got: %v", err)
	}
}

// writeTestKeypair writes a self-signed cert+key PEM pair to dir and
// returns their paths, for exercising buildServerTLS.
func writeTestKeypair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "omega-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// No TLS flags => nil config => plaintext listener (backward-compatible
// default).
func TestBuildServerTLS_PlaintextDefault(t *testing.T) {
	cfg, err := buildServerTLS("", "", "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg != nil {
		t.Fatal("expected nil config (plaintext) when no TLS flags are set")
	}
}

// --client-ca without server TLS is a misconfiguration.
func TestBuildServerTLS_ClientCANeedsServerCert(t *testing.T) {
	dir := t.TempDir()
	caPath, _ := writeTestKeypair(t, dir)
	if _, err := buildServerTLS("", "", caPath); err == nil {
		t.Fatal("expected error: --client-ca without --tls-cert/--tls-key")
	}
}

// Server cert + key without --client-ca => TLS, no client-cert
// requirement.
func TestBuildServerTLS_ServerOnly(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestKeypair(t, dir)
	cfg, err := buildServerTLS(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg == nil || cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected server-only TLS with NoClientCert, got %+v", cfg)
	}
}

// Server cert + key + --client-ca => mutual TLS with
// RequireAndVerifyClientCert.
func TestBuildServerTLS_MutualTLS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestKeypair(t, dir)
	caPath := certPath // any PEM with a cert works as a client CA bundle
	cfg, err := buildServerTLS(certPath, keyPath, caPath)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil {
		t.Fatalf("expected mutual TLS, got ClientAuth=%v", cfg.ClientAuth)
	}
}

// --require-auth without --client-ca must fail fast at startup: auth has
// nothing to verify client certs against.
func TestServerCommandRequireAuthNeedsClientCA(t *testing.T) {
	cmd := newServerCommand()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--require-auth", "--data-dir", t.TempDir()})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected startup to fail when --require-auth is set without --client-ca")
	}
	if !strings.Contains(err.Error(), "client-ca") {
		t.Fatalf("error should mention --client-ca, got: %v", err)
	}
}
