package cli

import (
	"bytes"
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
	kr, err := storage.NewAuditKeyring("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	store.UseAuditKeyring(kr)
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
	for i := 0; i < 2; i++ {
		seq, err := identity.NewDurableSequence(ca, s, "omega.local")
		if err != nil {
			t.Fatal(err)
		}
		// The first start numbers the CA after the stored 4; a restart
		// with the same CA keeps it.
		if got := seq.BundleSequence(); got != 5 {
			t.Fatalf("start %d: spiffe_sequence %d, want 5", i+1, got)
		}
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
