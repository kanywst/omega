package audit

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/storage"
)

// fakeForwarder records every batch handed to Forward and lets the test
// flip between success and failure mid-run.
type fakeForwarder struct {
	name string

	mu      sync.Mutex
	batches [][]storage.AuditEvent
	failN   int32 // if > 0, next Forward call returns errBoom (decrements)
}

func (f *fakeForwarder) Name() string { return f.name }

func (f *fakeForwarder) Forward(ctx context.Context, events []storage.AuditEvent) error {
	if atomic.LoadInt32(&f.failN) > 0 {
		atomic.AddInt32(&f.failN, -1)
		return errors.New("forward boom")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]storage.AuditEvent, len(events))
	copy(cp, events)
	f.batches = append(f.batches, cp)
	return nil
}

func (f *fakeForwarder) seenSeqs() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []int64
	for _, b := range f.batches {
		for _, e := range b {
			out = append(out, e.Seq)
		}
	}
	return out
}

func openPumpStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "pump.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// runPump launches pump.Run in a goroutine and registers a cleanup that
// cancels its context and waits for Run to return. Without the wait, a
// straggling goroutine can race with t.TempDir's RemoveAll on SQLite WAL
// files and trip "directory not empty" on cleanup.
func runPump(t *testing.T, p *Pump) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ctx
}

func appendN(t *testing.T, store *storage.Store, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := store.AppendAudit(ctx, storage.AuditEvent{Kind: "k", Subject: "s"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

func TestPumpDeliversAndAdvancesWatermark(t *testing.T) {
	store := openPumpStore(t)
	appendN(t, store, 3)

	fwd := &fakeForwarder{name: "test"}
	pump := NewPump(store, fwd, PumpConfig{BatchSize: 100, PollInterval: 20 * time.Millisecond})

	ctx := runPump(t, pump)

	waitFor(t, func() bool { return len(fwd.seenSeqs()) >= 3 }, "first 3 events delivered")

	// Watermark must advance to the highest delivered seq.
	got, err := store.AuditForwardSeq(ctx, "test")
	if err != nil {
		t.Fatalf("read seq: %v", err)
	}
	if got != 3 {
		t.Errorf("watermark = %d, want 3", got)
	}

	// New events should be picked up on the next tick.
	appendN(t, store, 2)
	waitFor(t, func() bool { return len(fwd.seenSeqs()) >= 5 }, "next 2 events delivered")

	got, _ = store.AuditForwardSeq(ctx, "test")
	if got != 5 {
		t.Errorf("watermark after second batch = %d, want 5", got)
	}
}

func TestPumpRetriesOnForwarderError(t *testing.T) {
	store := openPumpStore(t)
	appendN(t, store, 2)

	fwd := &fakeForwarder{name: "test", failN: 2}
	pump := NewPump(store, fwd, PumpConfig{BatchSize: 100, PollInterval: 10 * time.Millisecond})

	ctx := runPump(t, pump)

	// After the first 2 attempts fail, the 3rd should succeed and deliver
	// the same seqs (1, 2). Watermark must not have advanced during failures.
	waitFor(t, func() bool { return len(fwd.seenSeqs()) >= 2 }, "events delivered after retry")

	got, err := store.AuditForwardSeq(ctx, "test")
	if err != nil {
		t.Fatalf("read seq: %v", err)
	}
	if got != 2 {
		t.Errorf("watermark = %d, want 2", got)
	}

	// Make sure the same seqs were the ones delivered (no events skipped).
	seqs := fwd.seenSeqs()
	if seqs[0] != 1 || seqs[1] != 2 {
		t.Errorf("delivered seqs = %v, want [1 2]", seqs)
	}
}

func TestPumpResumesFromWatermark(t *testing.T) {
	store := openPumpStore(t)
	appendN(t, store, 5)

	// Pretend a previous run already delivered up to seq 3.
	if err := store.SetAuditForwardSeq(context.Background(), "test", 3); err != nil {
		t.Fatalf("seed seq: %v", err)
	}

	fwd := &fakeForwarder{name: "test"}
	pump := NewPump(store, fwd, PumpConfig{BatchSize: 100, PollInterval: 10 * time.Millisecond})

	runPump(t, pump)

	waitFor(t, func() bool { return len(fwd.seenSeqs()) >= 2 }, "events 4 and 5 delivered")

	seqs := fwd.seenSeqs()
	if seqs[0] != 4 || seqs[len(seqs)-1] != 5 {
		t.Errorf("resumed delivery seqs = %v, want starting at 4 ending at 5", seqs)
	}
}

func TestPumpHonoursBatchSize(t *testing.T) {
	store := openPumpStore(t)
	appendN(t, store, 5)

	fwd := &fakeForwarder{name: "test"}
	pump := NewPump(store, fwd, PumpConfig{BatchSize: 2, PollInterval: 10 * time.Millisecond})

	runPump(t, pump)

	waitFor(t, func() bool { return len(fwd.seenSeqs()) >= 5 }, "all 5 events delivered")

	fwd.mu.Lock()
	defer fwd.mu.Unlock()
	for _, b := range fwd.batches {
		if len(b) > 2 {
			t.Errorf("batch size %d exceeds limit", len(b))
		}
	}
}

func TestNewPumpAppliesDefaults(t *testing.T) {
	store := openPumpStore(t)
	fwd := &fakeForwarder{name: "x"}
	p := NewPump(store, fwd, PumpConfig{})
	if p.cfg.BatchSize != 100 {
		t.Errorf("default BatchSize = %d, want 100", p.cfg.BatchSize)
	}
	if p.cfg.PollInterval != time.Second {
		t.Errorf("default PollInterval = %v, want 1s", p.cfg.PollInterval)
	}
}
