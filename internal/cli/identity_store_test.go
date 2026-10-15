package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/storage"
)

func TestIdentityStoreRoundTripsAndMarksFollowers(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	s := identityStore{store}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keptAt := time.Now().UTC().Truncate(time.Second)
	want := identity.UpstreamCA{DER: der, KeptAt: keptAt, Until: keptAt.Add(time.Hour)}
	if err := s.SaveUpstreamCAs(ctx, "omega.local", "vault-pki", []identity.UpstreamCA{want}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadUpstreamCAs(ctx, "omega.local", "vault-pki")
	if err != nil || len(got) != 1 || !got[0].Until.Equal(want.Until) || !got[0].KeptAt.Equal(want.KeptAt) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if err := s.SaveBundleSequence(ctx, "omega.local", 4, "d"); err != nil {
		t.Fatal(err)
	}
	if seq, digest, err := s.LoadBundleSequence(ctx, "omega.local"); err != nil || seq != 4 || digest != "d" {
		t.Fatalf("sequence: %d %q %v", seq, digest, err)
	}

	// A disk CA's spiffe_sequence survives a restart of the server.
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	first := identity.NewDurableSequence(ca, s, "omega.local").BundleSequence()
	if first != 5 {
		t.Fatalf("first sequence after a stored 4: %d", first)
	}
	if again := identity.NewDurableSequence(ca, s, "omega.local").BundleSequence(); again != first {
		t.Fatalf("after a restart: %d, want %d", again, first)
	}

	store.SetLeaderForTest(true, false)
	if err := s.SaveUpstreamCAs(ctx, "omega.local", "vault-pki", nil); !errors.Is(err, identity.ErrStoreNotLeader) {
		t.Fatalf("follower save: %v", err)
	}
	if err := s.SaveBundleSequence(ctx, "omega.local", 9, "d"); !errors.Is(err, identity.ErrStoreNotLeader) {
		t.Fatalf("follower sequence save: %v", err)
	}
	if notLeader(nil) != nil {
		t.Fatal("nil error changed")
	}
	store.SetLeaderForTest(false, false)
	_ = store.Close()
	if _, err := s.LoadUpstreamCAs(ctx, "omega.local", "vault-pki"); err == nil {
		t.Fatal("a closed store read without error")
	}
}
