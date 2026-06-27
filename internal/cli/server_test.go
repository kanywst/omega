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
