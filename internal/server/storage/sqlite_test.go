package storage_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/kanywst/omega/internal/server/storage"
)

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCreateGetList(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	created, err := s.CreateDomain(ctx, storage.Domain{Name: "media.news", Description: "news domain"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Parent != "media" {
		t.Errorf("parent auto-derive: got %q want %q", created.Parent, "media")
	}
	if created.CreatedAt.IsZero() {
		t.Error("created_at should be set")
	}

	got, err := s.GetDomain(ctx, "media.news")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "media.news" || got.Description != "news domain" || got.Parent != "media" {
		t.Errorf("get returned wrong domain: %+v", got)
	}

	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "media.sports"}); err != nil {
		t.Fatalf("create second: %v", err)
	}
	list, err := s.ListDomains(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list len: got %d want 2", len(list))
	}
	if list[0].Name != "media.news" || list[1].Name != "media.sports" {
		t.Errorf("list order: %+v", list)
	}
}

func TestDuplicate(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	if _, err := s.CreateDomain(ctx, storage.Domain{Name: "example"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err := s.CreateDomain(ctx, storage.Domain{Name: "example"})
	if !errors.Is(err, storage.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
}

func TestNotFound(t *testing.T) {
	s := newStore(t)
	_, err := s.GetDomain(context.Background(), "nope")
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestEmptyName(t *testing.T) {
	s := newStore(t)
	if _, err := s.CreateDomain(context.Background(), storage.Domain{}); err == nil {
		t.Fatal("want error on empty name")
	}
}
