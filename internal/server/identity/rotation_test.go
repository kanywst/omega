package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func countCerts(b []byte) int { return strings.Count(string(b), "BEGIN CERTIFICATE") }

func jwksKids(t *testing.T, a *localAuthority) []string {
	t.Helper()
	raw, err := a.JWTBundle()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range doc.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func issueX509(t *testing.T, a *localAuthority, id spiffeid.ID) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	svid, err := a.IssueSVID(id, csr)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(svid.CertPEM)
	c, _ := x509.ParseCertificate(block.Bytes)
	return c
}

func verifiesAgainstBundle(c *x509.Certificate, bundle []byte) bool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(bundle)
	_, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

func TestCARotationCycle(t *testing.T) {
	dir := t.TempDir()
	a, err := loadOrCreateDisk(dir, "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	id := spiffeid.RequireFromString("spiffe://omega.local/web")
	oldKid, _ := a.JWTKeyID()
	oldJWT, err := a.IssueJWTSVID(id, []string{"aud"}, time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	oldSVID := issueX509(t, a, id)

	// prepare: trusted, not signing.
	if _, err := PrepareCA(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareCA(dir); err == nil {
		t.Fatal("a second prepare must be refused")
	}
	if changed, err := a.ReloadCA(); err != nil || !changed {
		t.Fatalf("reload after prepare: %v %v", changed, err)
	}
	if countCerts(a.BundlePEM()) != 2 || len(jwksKids(t, a)) != 2 || a.BundleSequence() != 2 {
		t.Fatalf("after prepare: %d certs, kids %v, seq %d", countCerts(a.BundlePEM()), jwksKids(t, a), a.BundleSequence())
	}
	if kid, _ := a.JWTKeyID(); kid != oldKid {
		t.Fatal("a prepared CA must not sign yet")
	}
	if changed, _ := a.ReloadCA(); changed {
		t.Fatal("a reload with nothing new must report no change")
	}

	// activate: the new CA signs, the old stays trusted.
	if _, err := ActivateCA(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReloadCA(); err != nil {
		t.Fatal(err)
	}
	newKid, _ := a.JWTKeyID()
	if newKid == oldKid || a.BundleSequence() != 3 {
		t.Fatalf("after activate: kid %s (old %s), seq %d", newKid, oldKid, a.BundleSequence())
	}
	if _, err := a.ValidateJWTSVID(oldJWT.Token, "aud"); err != nil {
		t.Fatalf("a token the previous CA signed must still validate: %v", err)
	}
	newJWT, _ := a.IssueJWTSVID(id, []string{"aud"}, time.Hour, nil)
	if newJWT.KeyID != newKid {
		t.Fatal("new tokens must be signed by the new CA")
	}
	newSVID := issueX509(t, a, id)
	if !verifiesAgainstBundle(newSVID, a.BundlePEM()) || !verifiesAgainstBundle(oldSVID, a.BundlePEM()) {
		t.Fatal("both old and new SVIDs must verify against the bundle")
	}
	if _, err := PrepareCA(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateCA(dir); err == nil {
		t.Fatal("activation while a previous CA is still trusted must be refused")
	}
	_ = os.Remove(filepath.Join(dir, caNextKeyFile))
	_ = os.Remove(filepath.Join(dir, caNextCrtFile))

	// retire: the old CA is no longer trusted.
	if err := RetireCA(dir, false); err == nil {
		t.Fatal("retiring before RetireAfter must need --force")
	}
	if err := RetireCA(dir, true); err != nil {
		t.Fatal(err)
	}
	if err := RetireCA(dir, true); err == nil {
		t.Fatal("nothing left to retire")
	}
	if _, err := a.ReloadCA(); err != nil {
		t.Fatal(err)
	}
	if countCerts(a.BundlePEM()) != 1 || verifiesAgainstBundle(oldSVID, a.BundlePEM()) {
		t.Fatal("after retire only the new CA is trusted")
	}
	if _, err := a.ValidateJWTSVID(oldJWT.Token, "aud"); err == nil {
		t.Fatal("a token from the retired CA must not validate")
	}
	if _, err := a.ValidateJWTSVID(newJWT.Token, "aud"); err != nil {
		t.Fatal(err)
	}
	st, err := ReadCAStatus(dir)
	if err != nil || st.Active.KeyID != newKid || st.Next != nil || st.Prev != nil {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestCAActivationInterruptedBetweenRenamesIsFinishedOnLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateDisk(dir, "omega.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareCA(dir); err != nil {
		t.Fatal(err)
	}
	// What ActivateCA does, stopped after moving the key.
	cur, _ := os.ReadFile(filepath.Join(dir, caCertFile))
	_ = os.WriteFile(filepath.Join(dir, caPrevCrtFile), cur, 0o644)
	if err := os.Rename(filepath.Join(dir, caNextKeyFile), filepath.Join(dir, caKeyFile)); err != nil {
		t.Fatal(err)
	}
	a, err := loadOrCreateDisk(dir, "omega.local")
	if err != nil {
		t.Fatalf("a half-done activation must load, not fail: %v", err)
	}
	if countCerts(a.BundlePEM()) != 2 {
		t.Fatalf("active and previous must both be trusted: %d", countCerts(a.BundlePEM()))
	}
	if _, err := ReadCAStatus(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, caNextCrtFile)); err != nil {
		t.Fatal("reading must not change the directory")
	}
	// The next mutating command finishes it.
	if err := RetireCA(dir, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, caNextCrtFile)); !os.IsNotExist(err) {
		t.Fatal("the next certificate must have been moved into place")
	}
}

func TestCAReloadKeepsTheOldStateOnBadFiles(t *testing.T) {
	dir := t.TempDir()
	a, err := loadOrCreateDisk(dir, "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	before := a.BundlePEM()
	if err := os.WriteFile(filepath.Join(dir, caPrevCrtFile), []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReloadCA(); err == nil {
		t.Fatal("a corrupt file must fail the reload")
	}
	if string(a.BundlePEM()) != string(before) {
		t.Fatal("a failed reload must keep the previous material")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kd, _ := x509.MarshalPKCS8PrivateKey(other)
	_ = os.Remove(filepath.Join(dir, caPrevCrtFile))
	_ = os.WriteFile(filepath.Join(dir, caKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	if _, err := a.ReloadCA(); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("a key that does not match the certificate: %v", err)
	}
	if _, err := ActivateCA(dir); err == nil {
		t.Fatal("activate without a prepared CA must be refused")
	}
	if err := RetireCA(dir, false); err == nil {
		t.Fatal("retire without a previous CA must be refused")
	}
}

func TestCAActivationResumesAfterACrashThatOnlyWroteThePrevious(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateDisk(dir, "omega.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareCA(dir); err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile(filepath.Join(dir, caCertFile))
	_ = os.WriteFile(filepath.Join(dir, caPrevCrtFile), cur, 0o644)
	if _, err := ActivateCA(dir); err != nil {
		t.Fatalf("activate must resume, not refuse: %v", err)
	}
	st, err := ReadCAStatus(dir)
	if err != nil || st.Next != nil || st.Prev == nil {
		t.Fatalf("after resume: %+v %v", st, err)
	}
}

func TestCAActivationRefusesAMismatchedNextPair(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateDisk(dir, "omega.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareCA(dir); err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kd, _ := x509.MarshalPKCS8PrivateKey(other)
	_ = os.WriteFile(filepath.Join(dir, caNextKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	before, _ := os.ReadFile(filepath.Join(dir, caKeyFile))
	if _, err := ActivateCA(dir); err == nil {
		t.Fatal("a next key that does not match its certificate must be refused")
	}
	after, _ := os.ReadFile(filepath.Join(dir, caKeyFile))
	if string(before) != string(after) {
		t.Fatal("a refused activation must not move anything")
	}
	if _, err := os.Stat(filepath.Join(dir, caPrevCrtFile)); !os.IsNotExist(err) {
		t.Fatal("a refused activation must not write the previous CA")
	}
}

func TestCARetireGuardUsesTheRecordedActivationTime(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateDisk(dir, "omega.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareCA(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateCA(dir); err != nil {
		t.Fatal(err)
	}
	// A copy or restore resets file times; the recorded time still holds.
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir, caPrevCrtFile), old, old)
	if err := RetireCA(dir, false); err == nil {
		t.Fatal("the guard must use the recorded activation time, not the file's mtime")
	}
	st, _ := ReadCAStatus(dir)
	if time.Since(st.PrevSince) > time.Minute {
		t.Fatalf("status must report the recorded time: %s", st.PrevSince)
	}
	if err := RetireCA(dir, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, caPrevSince)); !os.IsNotExist(err) {
		t.Fatal("retire must remove the recorded time")
	}
}

func TestCARetireRefusesAnUnreadableActivationTime(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateDisk(dir, "omega.local"); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareCA(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateCA(dir); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, caPrevSince), []byte("garbage"), 0o644)
	if err := RetireCA(dir, false); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("a corrupt activation time must stop retire: %v", err)
	}
}
