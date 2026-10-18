package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

func TestPolicyCommands(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	pdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pdir, "base.cedar"), []byte(`forbid (principal == User::"mallory", action, resource);`), 0o600); err != nil {
		t.Fatal(err)
	}
	pdp := policy.New()
	if err := pdp.LoadDir(pdir); err != nil {
		t.Fatal(err)
	}
	const root = "spiffe://omega.local/platform/root"
	srv := httptest.NewUnstartedServer(api.NewServer(store, ca, pdp).WithRequireAuth(true).WithDomainRootAdmins([]string{root}).Handler())
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.BundlePEM())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: clientCAs, ClientAuth: tls.VerifyClientCertIfGiven}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// The server's own certificate verifies it; the client presents an
	// SVID the Omega CA issued to the root admin.
	serverCA := filepath.Join(dir, "server-ca.pem")
	if err := os.WriteFile(serverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)
	svid, err := ca.IssueSVID(spiffeid.RequireFromString(root), csr)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile := filepath.Join(dir, "svid.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, svid.CertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	policyFile := filepath.Join(dir, "alice-read.cedar")
	write := func(text string) {
		if err := os.WriteFile(policyFile, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	flags := []string{"--server=" + srv.URL, "--server-ca=" + serverCA, "--client-cert=" + certFile, "--client-key=" + keyFile}
	run := func(args ...string) (string, error) {
		return runCmd(t, newPolicyCommand(), append(args, flags...)...)
	}
	write(`permit (principal == User::"alice", action == Action::"read", resource);`)
	if out, err := run("apply", "-f", policyFile); err != nil || !strings.Contains(out, `"version": 1`) {
		t.Fatalf("apply (create): %v %s", err, out)
	}
	write(`permit (principal == User::"alice", action, resource);`)
	if out, err := run("apply", "-f", policyFile); err != nil || !strings.Contains(out, `"version": 2`) {
		t.Fatalf("apply (update): %v %s", err, out)
	}
	if out, err := run("list"); err != nil || !strings.Contains(out, `"base.cedar"`) || !strings.Contains(out, `"alice-read"`) {
		t.Fatalf("list: %v %s", err, out)
	}
	if out, err := run("get", "alice-read"); err != nil || !strings.Contains(out, "action, resource") {
		t.Fatalf("get: %v %s", err, out)
	}
	if _, err := run("apply", "-f", policyFile, "--id", "base.cedar"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("apply over a file: %v", err)
	}
	write("permit (")
	if _, err := run("apply", "-f", policyFile); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("apply invalid: %v", err)
	}
	if _, err := run("apply"); err == nil {
		t.Fatal("apply without --file must fail")
	}
	if _, err := run("delete", "alice-read", "--if-match", `"1-stale"`); err == nil || !strings.Contains(err.Error(), "412") {
		t.Fatalf("stale delete: %v", err)
	}
	if _, err := run("delete", "alice-read"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("delete without --if-match or --force must be refused: %v", err)
	}
	if _, err := run("delete", "alice-read", "--if-match", "*"); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("--if-match '*' must point to --force: %v", err)
	}
	if _, err := run("delete", "alice-read", "--force", "--if-match", `"1"`); err == nil {
		t.Fatal("--force with --if-match must be refused")
	}
	if out, err := run("delete", "alice-read", "--force"); err != nil {
		t.Fatalf("delete: %v %s", err, out)
	}
	if _, err := run("get", "alice-read"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("get after delete: %v", err)
	}
	if _, err := runCmd(t, newPolicyCommand(), "list", "--server=http://127.0.0.1:1", "--client-cert="+certFile); err == nil {
		t.Fatal("--client-cert without --client-key must fail")
	}
}
