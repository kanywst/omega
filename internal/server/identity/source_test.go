package identity_test

import (
	"testing"

	"github.com/kanywst/omega/internal/server/identity"
)

func TestAsSourceWrapsBareAuthority(t *testing.T) {
	auth, err := identity.LoadOrCreate(t.TempDir(), "example.org")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	src := identity.AsSource(auth)
	if got := src.SourceKind(); got != identity.SourceBuiltIn {
		t.Fatalf("SourceKind() = %q, want %q", got, identity.SourceBuiltIn)
	}
	// The embedded Authority must remain reachable through the Source.
	if src.TrustDomain() != auth.TrustDomain() {
		t.Fatalf("trust domain not preserved through Source: %s vs %s", src.TrustDomain(), auth.TrustDomain())
	}
}

func TestAsSourceIsIdempotent(t *testing.T) {
	auth, err := identity.LoadOrCreate(t.TempDir(), "example.org")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	once := identity.NewBuiltInSource(auth)
	twice := identity.AsSource(once)
	if twice != once {
		t.Fatal("AsSource re-wrapped an existing Source instead of returning it unchanged")
	}
}

func TestAsSourceNilStaysNil(t *testing.T) {
	if identity.AsSource(nil) != nil {
		t.Fatal("AsSource(nil) must return a nil Source interface, not a non-nil wrapper around a nil Authority")
	}
}
