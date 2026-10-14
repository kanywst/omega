package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/storage"
)

type fakeKeeper struct{ got [][32]byte }

func (f *fakeKeeper) SetKeptCAHook(func(identity.KeptCAEvent)) {}
func (f *fakeKeeper) DistrustCAs(fps [][32]byte) int           { f.got = fps; return len(fps) }

func TestCADistrustRecordsChangesAndRejections(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	path := filepath.Join(dir, "distrust")
	k := &fakeKeeper{}
	d := &caDistrust{keeper: k, path: path, store: store}
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fp := strings.Repeat("ab", 32)

	write(fp + "\n")
	if err := d.apply(ctx); err != nil || len(k.got) != 1 {
		t.Fatalf("apply: %v %v", err, k.got)
	}
	// The same list again is not recorded twice.
	if err := d.apply(ctx); err != nil {
		t.Fatal(err)
	}
	// A typo is refused, kept out of the keeper and recorded.
	write("not-a-fingerprint\n")
	if err := d.apply(ctx); err == nil {
		t.Fatal("a bad list must be refused")
	}
	// An empty file is refused as a likely truncated write; clearing
	// takes a file with only a comment, and is recorded.
	write("")
	if err := d.apply(ctx); err == nil {
		t.Fatal("an empty file must be refused")
	}
	write("# cleared after the incident\n")
	if err := d.apply(ctx); err != nil || len(k.got) != 0 {
		t.Fatalf("clear: %v %v", err, k.got)
	}

	events, err := store.ListAudit(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		if e.Kind != "ca.upstream" {
			continue
		}
		var p map[string]any
		_ = json.Unmarshal(e.Payload, &p)
		n := 0
		if l, ok := p["fingerprints"].([]any); ok {
			n = len(l)
		}
		got = append(got, e.Decision+":"+strings.Repeat("x", n))
	}
	if strings.Join(got, ",") != "ok:x,error:,error:,ok:" {
		t.Fatalf("audit rows: %v", got)
	}
}

func TestKeptCAQueueKeepsOrderAndDrainsOnShutdown(t *testing.T) {
	q := newKeptCAQueue()
	ctx, cancel := context.WithCancel(context.Background())
	var got []string
	done := make(chan struct{})
	block := make(chan struct{})
	go func() {
		q.run(ctx, func(_ context.Context, e identity.KeptCAEvent) {
			if e.Fingerprint == "1" {
				<-block // a slow store
			}
			got = append(got, e.Fingerprint)
		})
		close(done)
	}()
	for _, fp := range []string{"1", "2", "3"} {
		q.push(identity.KeptCAEvent{Fingerprint: fp})
	}
	cancel()
	close(block)
	<-done
	if strings.Join(got, ",") != "1,2,3" {
		t.Fatalf("events recorded %v, want all three in order", got)
	}
}
