package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/identity"
)

// TestUpstreamBackendsRestoreTheStoredKeptSet checks that each external
// issuer backend serves the CAs kept before a restart once the store is
// attached.
func TestUpstreamBackendsRestoreTheStoredKeptSet(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	old := mustCA(t, "Rotated Out CA", key, nil, nil)
	backends := map[string]func(t *testing.T) identity.Authority{
		string(identity.KindVaultPKI): func(t *testing.T) identity.Authority {
			v := newVaultFixture(t, "pki", "omega", "tok")
			a, err := identity.New(identity.Config{
				Kind: identity.KindVaultPKI, TrustDomain: "omega.local", Dir: filepath.Join(t.TempDir(), "ca"),
				VaultPKIAddr: v.server.URL, VaultPKIToken: v.token, VaultPKIMount: v.mount, VaultPKIRole: v.role,
				UpstreamCAGrace: identity.UpstreamCAGrace,
			})
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
		string(identity.KindStepCA): func(t *testing.T) identity.Authority {
			f := newStepCAFixture(t, "omega")
			a, err := identity.New(identity.Config{
				Kind: identity.KindStepCA, TrustDomain: "omega.local", Dir: filepath.Join(t.TempDir(), "ca"),
				StepCAURL: f.server.URL, StepCAProvisionerName: f.provisionerName, StepCAProvisionerKeyPEM: f.provisionerKeyPriv,
				UpstreamCAGrace: identity.UpstreamCAGrace,
			})
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
		string(identity.KindAWSPCA): func(t *testing.T) identity.Authority {
			cfg := pcaConfig(t, newPCAFixture(t, nil))
			cfg.UpstreamCAGrace = identity.UpstreamCAGrace
			a, err := identity.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			return a
		},
	}
	for backend, mk := range backends {
		t.Run(backend, func(t *testing.T) {
			a := mk(t)
			keeper := a.(identity.UpstreamCAKeeper)
			before := strings.Count(string(a.BundlePEM()), "BEGIN CERTIFICATE")
			store := identity.NewMemCAStore()
			store.Put("omega.local", backend, []identity.UpstreamCA{{DER: old.Raw, KeptAt: time.Now(), Until: time.Now().Add(time.Hour)}})

			store.Fail(errors.New("db down"), nil)
			if err := keeper.UseCAStore(store); err == nil {
				t.Fatal("a store that cannot be read was attached")
			}
			store.Fail(nil, nil)
			if err := keeper.UseCAStore(store); err != nil {
				t.Fatal(err)
			}
			bundle := string(a.BundlePEM())
			if n := strings.Count(bundle, "BEGIN CERTIFICATE"); n != before+1 || !strings.Contains(bundle, string(certPEM(old))) {
				t.Fatalf("the stored kept CA is not served: %d certs, want %d", n, before+1)
			}
			if rows := store.Rows("omega.local", backend); len(rows) != before+1 {
				t.Fatalf("the issuer's CAs were not stored with the kept one: %d rows", len(rows))
			}
		})
	}
}
