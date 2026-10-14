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
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	k8sattestor "github.com/kanywst/omega/internal/agent/attestor/k8s"
)

func writePair(t *testing.T, dir, cn string, mod time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(cf, mod, mod)
	_ = os.Chtimes(kf, mod, mod)
	return cf, kf
}

func leafCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	x, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x.Subject.CommonName
}

func TestControlPlaneTransportReloadsClientPair(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writePair(t, dir, "first", time.Now().Add(-time.Hour))
	rt, err := controlPlaneTransport("https://cp:8443", "", cf, kf)
	if err != nil {
		t.Fatal(err)
	}
	get := rt.(*http.Transport).TLSClientConfig.GetClientCertificate
	c, err := get(nil)
	if err != nil || leafCN(t, c) != "first" {
		t.Fatalf("initial pair: %v", err)
	}
	writePair(t, dir, "second", time.Now())
	if c, _ = get(nil); leafCN(t, c) != "second" {
		t.Error("a rotated pair must be picked up")
	}
	// A half-written rotation keeps serving the last good pair.
	if err := os.WriteFile(kf, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = get(nil); err != nil || leafCN(t, c) != "second" {
		t.Errorf("mid-rotation: %v", err)
	}
}

func TestControlPlaneTransportRejectsMisuse(t *testing.T) {
	dir := t.TempDir()
	cf, kf := writePair(t, dir, "x", time.Now())
	if rt, err := controlPlaneTransport("http://cp", "", "", ""); err != nil || rt != http.DefaultTransport {
		t.Errorf("no TLS flags: %v", err)
	}
	for name, args := range map[string][4]string{
		"cert without key": {"https://cp", "", cf, ""},
		"TLS over http":    {"http://cp", "", cf, kf},
		"missing CA file":  {"https://cp", filepath.Join(dir, "nope"), "", ""},
		"CA without PEM":   {"https://cp", kf, "", ""},
		"unreadable pair":  {"https://cp", "", filepath.Join(dir, "nope"), kf},
	} {
		if _, err := controlPlaneTransport(args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestCheckLocalPDP(t *testing.T) {
	for _, tc := range []struct {
		addr, server, cert string
		remote             bool
		ok                 bool
	}{
		{"127.0.0.1:8181", "https://cp", "c.pem", false, true},
		{"localhost:8181", "https://cp", "c.pem", false, true},
		{"[::1]:8181", "https://cp", "c.pem", false, true},
		{"0.0.0.0:8181", "https://cp", "c.pem", false, false},
		{":8181", "https://cp", "c.pem", false, false},
		{"0.0.0.0:8181", "https://cp", "c.pem", true, true},
		{"127.0.0.1:8181", "http://cp", "c.pem", false, false},
		{"127.0.0.1:8181", "https://cp", "", false, false},
		{"nonsense", "https://cp", "c.pem", false, false},
	} {
		if err := checkLocalPDP(tc.addr, tc.remote, tc.server, "ca.pem", tc.cert); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	if err := checkLocalPDP("127.0.0.1:8181", false, "https://cp", "", "c.pem"); err == nil {
		t.Error("a local PDP without --server-ca must be refused")
	}
}

func TestTrustDomainOfCert(t *testing.T) {
	dir := t.TempDir()
	cf, _ := writePair(t, dir, "plain", time.Now())
	if _, err := trustDomainOfCert(cf); err == nil {
		t.Error("a certificate without a SPIFFE ID must be refused")
	}
	if _, err := trustDomainOfCert(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file must be refused")
	}
	if err := os.WriteFile(filepath.Join(dir, "junk"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := trustDomainOfCert(filepath.Join(dir, "junk")); err == nil {
		t.Error("a file without PEM must be refused")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse("spiffe://omega.local/nodes/n1")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	svid := filepath.Join(dir, "svid.pem")
	if err := os.WriteFile(svid, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if td, err := trustDomainOfCert(svid); err != nil || td != "omega.local" {
		t.Errorf("svid: %q %v", td, err)
	}
}

func TestAgentNeedsAMapOrALocalPDP(t *testing.T) {
	cmd := newAgentCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{"--socket", filepath.Join(t.TempDir(), "a.sock")})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--local-pdp-addr") {
		t.Fatalf("an agent with neither --map nor a local PDP has nothing to do: %v", err)
	}
	cmd = newAgentCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{"--policy-bundle-key", "k.pem", "--map", "uid=0,id=spiffe://omega.local/x"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--local-pdp-addr") {
		t.Fatalf("--policy-bundle-key without a local PDP would be silently ignored: %v", err)
	}
	// With a local PDP and no --map, the flags are checked as for any
	// local PDP rather than refused for the missing --map.
	cmd = newAgentCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{"--local-pdp-addr", "127.0.0.1:0", "--server", "http://cp"})
	if err := cmd.Execute(); err == nil || strings.Contains(err.Error(), "--map") {
		t.Fatalf("want the local PDP's own checks, got: %v", err)
	}
}

func TestLocalPDPOnlyAgentExitsWhenItCannotListen(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse("spiffe://omega.local/nodes/n1")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	cert, keyFile := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	base := []string{"--server", "https://127.0.0.1:1", "--server-ca", cert, "--client-cert", cert, "--client-key", keyFile, "--local-pdp-addr", busy.Addr().String()}
	for name, extra := range map[string][]string{
		"local PDP only":        nil,
		"with the Workload API": {"--socket", shortSocketPath(t), "--map", "uid=0,id=spiffe://omega.local/x"},
	} {
		cmd := newAgentCommand()
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(append(slices.Clone(base), extra...))
		done := make(chan error, 1)
		go func() { done <- cmd.Execute() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "local PDP") {
				t.Fatalf("%s: want the listener error, got %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: an agent whose local PDP cannot listen must exit", name)
		}
	}
}

func TestBundleKeyLoaders(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(key)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalECPrivateKey(p384)
	write := func(name, typ string, der []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for _, p := range []string{write("sec1.pem", "EC PRIVATE KEY", sec1), write("pkcs8.pem", "PRIVATE KEY", pkcs8)} {
		if _, err := loadBundleSigningKey(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := loadBundleVerifyKey(write("pub.pem", "PUBLIC KEY", pub)); err != nil {
		t.Errorf("public key: %v", err)
	}
	for name, err := range map[string]error{
		"P-384 signing key":   func() error { _, e := loadBundleSigningKey(write("p384.pem", "EC PRIVATE KEY", p384der)); return e }(),
		"wrong signing type":  func() error { _, e := loadBundleSigningKey(write("x.pem", "CERTIFICATE", []byte("x"))); return e }(),
		"missing signing key": func() error { _, e := loadBundleSigningKey(filepath.Join(dir, "nope")); return e }(),
		"private as public":   func() error { _, e := loadBundleVerifyKey(write("sec1b.pem", "EC PRIVATE KEY", sec1)); return e }(),
		"no PEM":              func() error { _, e := loadBundleVerifyKey(write("junk", "", nil)); return e }(),
	} {
		if err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// shortSocketPath returns a unix socket path short enough for macOS's
// 104-byte limit, which t.TempDir under a long test name can exceed.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "oa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

func TestAgentK8sWorkloadAttestorFlags(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters: [{name: c, cluster: {server: "http://127.0.0.1:1"}}]
contexts: [{name: c, context: {cluster: c, user: u}}]
users: [{name: u, user: {}}]
current-context: c
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NODE_NAME", "")
	run := func(args ...string) error {
		cmd := newAgentCommand()
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(append([]string{"--k8s-workload-attestor", "--kubeconfig", kubeconfig}, args...))
		return cmd.Execute()
	}
	// The attestor alone is enough to serve the Workload API, so the
	// error is about the attestor, not the missing --map.
	want := "node name is required"
	if !k8sattestor.Supported {
		want = "only supported on Linux"
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v, want %q", err, want)
	}
	if !k8sattestor.Supported {
		return
	}
	if err := run("--k8s-node-name", "n", "--k8s-workload-svid-template", "not-a-spiffe-id"); err == nil || !strings.Contains(err.Error(), "template") {
		t.Fatalf("bad template: %v", err)
	}
	if err := run("--kubeconfig", filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "kubeconfig") {
		t.Fatalf("missing kubeconfig: %v", err)
	}
}
