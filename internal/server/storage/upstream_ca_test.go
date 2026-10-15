package storage_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/storage"
)

func TestUpstreamCAs(t *testing.T) { exerciseUpstreamCAs(t, newStore(t)) }

func TestPostgresUpstreamCAs(t *testing.T) { exerciseUpstreamCAs(t, openPostgresStore(t)) }

func TestBundleSequence(t *testing.T) { exerciseBundleSequence(t, newStore(t)) }

func TestPostgresBundleSequence(t *testing.T) { exerciseBundleSequence(t, openPostgresStore(t)) }

func exerciseUpstreamCAs(t *testing.T, s *storage.Store) {
	t.Helper()
	ctx := context.Background()
	got, err := s.UpstreamCAs(ctx, "example.org", "vault-pki")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty store: %v %v", got, err)
	}
	keptAt := time.Unix(1700000000, 123).UTC()
	until := keptAt.Add(24 * time.Hour)
	current := storage.UpstreamCA{DER: []byte("current-ca")}
	kept := storage.UpstreamCA{DER: []byte("kept-ca"), KeptAt: keptAt, KeptUntil: until}
	if err := s.ReplaceUpstreamCAs(ctx, "example.org", "vault-pki", []storage.UpstreamCA{current, kept}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	// Another backend and trust domain are separate sets.
	if err := s.ReplaceUpstreamCAs(ctx, "example.org", "step-ca", []storage.UpstreamCA{{DER: []byte("other")}}); err != nil {
		t.Fatalf("replace other backend: %v", err)
	}
	if err := s.ReplaceUpstreamCAs(ctx, "other.org", "vault-pki", []storage.UpstreamCA{{DER: []byte("other")}}); err != nil {
		t.Fatalf("replace other trust domain: %v", err)
	}
	got, err = s.UpstreamCAs(ctx, "example.org", "vault-pki")
	if err != nil || len(got) != 2 {
		t.Fatalf("read back: %v %v", got, err)
	}
	for _, c := range got {
		switch {
		case bytes.Equal(c.DER, current.DER):
			if !c.KeptAt.IsZero() || !c.KeptUntil.IsZero() {
				t.Errorf("current CA came back kept: %+v", c)
			}
		case bytes.Equal(c.DER, kept.DER):
			if !c.KeptAt.Equal(keptAt) || !c.KeptUntil.Equal(until) {
				t.Errorf("kept CA times: got %v..%v, want %v..%v", c.KeptAt, c.KeptUntil, keptAt, until)
			}
		default:
			t.Errorf("unexpected CA %q", c.DER)
		}
	}
	// A replace drops what is not in the new set.
	if err := s.ReplaceUpstreamCAs(ctx, "example.org", "vault-pki", []storage.UpstreamCA{current}); err != nil {
		t.Fatalf("replace again: %v", err)
	}
	if got, _ := s.UpstreamCAs(ctx, "example.org", "vault-pki"); len(got) != 1 || !bytes.Equal(got[0].DER, current.DER) {
		t.Fatalf("after replace: %v", got)
	}
	if got, _ := s.UpstreamCAs(ctx, "example.org", "step-ca"); len(got) != 1 {
		t.Fatalf("other backend touched: %v", got)
	}
	if err := s.ReplaceUpstreamCAs(ctx, "example.org", "vault-pki", []storage.UpstreamCA{{}}); err == nil {
		t.Fatal("a CA without a certificate was stored")
	}
	if got, _ := s.UpstreamCAs(ctx, "example.org", "vault-pki"); len(got) != 1 {
		t.Fatalf("a failed replace changed the set: %v", got)
	}

	s.SetLeaderForTest(true, false)
	defer s.SetLeaderForTest(false, false)
	if err := s.ReplaceUpstreamCAs(ctx, "example.org", "vault-pki", nil); !errors.Is(err, storage.ErrNotLeader) {
		t.Fatalf("follower replace: %v", err)
	}
	if got, err := s.UpstreamCAs(ctx, "example.org", "vault-pki"); err != nil || len(got) != 1 {
		t.Fatalf("follower read: %v %v", got, err)
	}
}

func exerciseBundleSequence(t *testing.T, s *storage.Store) {
	t.Helper()
	ctx := context.Background()
	if seq, digest, err := s.LoadBundleSequence(ctx, "example.org"); err != nil || seq != 0 || digest != "" {
		t.Fatalf("empty: %d %q %v", seq, digest, err)
	}
	if err := s.SaveBundleSequence(ctx, "example.org", 3, "d3"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.SaveBundleSequence(ctx, "example.org", 5, "d5"); err != nil {
		t.Fatalf("save higher: %v", err)
	}
	// Lower and equal sequences do not move it back.
	for _, seq := range []int64{4, 5} {
		if err := s.SaveBundleSequence(ctx, "example.org", seq, "stale"); err != nil {
			t.Fatalf("save %d: %v", seq, err)
		}
	}
	if seq, digest, err := s.LoadBundleSequence(ctx, "example.org"); err != nil || seq != 5 || digest != "d5" {
		t.Fatalf("load: %d %q %v", seq, digest, err)
	}
	if seq, _, _ := s.LoadBundleSequence(ctx, "other.org"); seq != 0 {
		t.Fatalf("other trust domain: %d", seq)
	}
	s.SetLeaderForTest(true, false)
	defer s.SetLeaderForTest(false, false)
	if err := s.SaveBundleSequence(ctx, "example.org", 9, "d9"); !errors.Is(err, storage.ErrNotLeader) {
		t.Fatalf("follower save: %v", err)
	}
}
