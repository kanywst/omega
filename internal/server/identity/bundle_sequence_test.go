package identity

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeMaterial is trust material that changes when the test says so.
type fakeMaterial struct {
	pem    atomic.Value
	jwtErr error
	calls  atomic.Int64
	count  atomic.Int64 // the source's own count, when it keeps one
}

func newFakeMaterial(pem string) *fakeMaterial {
	m := &fakeMaterial{}
	m.pem.Store(pem)
	return m
}

func (m *fakeMaterial) BundlePEM() []byte          { return []byte(m.pem.Load().(string)) }
func (m *fakeMaterial) JWTBundle() ([]byte, error) { return []byte(`{"keys":[]}`), m.jwtErr }
func (m *fakeMaterial) BundleSequence() int64      { m.calls.Add(1); return m.count.Load() }

func newSeq(t *testing.T, src bundleMaterial, store BundleSequenceStore, td string) *DurableSequence {
	t.Helper()
	d, err := NewDurableSequence(src, store, td)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDurableSequenceNeverGoesBackAcrossARestart(t *testing.T) {
	store := NewMemCAStore()
	src := newFakeMaterial("A")
	d := newSeq(t, src, store, "omega.local")
	if got := d.BundleSequence(); got != 1 {
		t.Fatalf("first: %d", got)
	}
	if src.calls.Load() != 2 { // once to start, once for the call
		t.Fatal("the source was not asked to refresh first")
	}
	loads, _ := store.Counts()
	if got := d.BundleSequence(); got != 1 {
		t.Fatalf("unchanged: %d", got)
	}
	if after, _ := store.Counts(); after != loads {
		t.Fatal("an unchanged bundle read the store")
	}
	src.pem.Store("B")
	if got := d.BundleSequence(); got != 2 {
		t.Fatalf("after a change: %d", got)
	}

	// A restart with the same material serves the same sequence; with
	// new material, the next one.
	if got := newSeq(t, src, store, "omega.local").BundleSequence(); got != 2 {
		t.Fatalf("restart, same material: %d", got)
	}
	src.pem.Store("C")
	if got := newSeq(t, src, store, "omega.local").BundleSequence(); got != 3 {
		t.Fatalf("restart, new material: %d", got)
	}
	// Going back to earlier material still moves forward.
	src.pem.Store("A")
	if got := newSeq(t, src, store, "omega.local").BundleSequence(); got != 4 {
		t.Fatalf("restart, earlier material: %d", got)
	}
}

func TestDurableSequenceCountsEveryChangeTheSourceCounted(t *testing.T) {
	store := NewMemCAStore()
	src := newFakeMaterial("A")
	src.count.Store(1)
	d := newSeq(t, src, store, "omega.local")
	if d.BundleSequence() != 1 {
		t.Fatal("first")
	}
	// Two rotations (X.509 CA, then JWT key) before anyone reads it.
	src.pem.Store("B")
	src.count.Store(3)
	if got := d.BundleSequence(); got != 3 {
		t.Fatalf("after two rotations: %d, want 3", got)
	}
	// A restart's source counts from 1 again; the store keeps it going up.
	src2 := newFakeMaterial("C")
	src2.count.Store(1)
	if got := newSeq(t, src2, store, "omega.local").BundleSequence(); got != 4 {
		t.Fatalf("after a restart: %d, want 4", got)
	}
}

func TestDurableSequenceReplicas(t *testing.T) {
	store := NewMemCAStore()
	src := newFakeMaterial("A")
	leader := newSeq(t, src, store, "omega.local")
	follower := newSeq(t, src, store.Replica(true), "omega.local")
	if leader.BundleSequence() != 1 || follower.BundleSequence() != 1 {
		t.Fatal("replicas disagree on the first bundle")
	}
	// The leader numbers the change first; the follower takes its number.
	src.pem.Store("B")
	if leader.BundleSequence() != 2 || follower.BundleSequence() != 2 {
		t.Fatal("replicas disagree after a change")
	}
	// The follower sees a change first: it counts on its own and does
	// not write, and the leader still agrees.
	src.pem.Store("C")
	if follower.BundleSequence() != 3 || leader.BundleSequence() != 3 {
		t.Fatal("replicas disagree when the follower sees a change first")
	}
}

func TestDurableSequenceFollowerTakesUpTheLeadersNumber(t *testing.T) {
	store := NewMemCAStore()
	leaderSrc, followerSrc := newFakeMaterial("A"), newFakeMaterial("A")
	leaderSrc.count.Store(1)
	followerSrc.count.Store(1)
	clock := time.Now()
	leader := newSeq(t, leaderSrc, store, "omega.local")
	follower := newSeq(t, followerSrc, store.Replica(true), "omega.local")
	follower.now = func() time.Time { return clock }
	// Two changes: the follower's source saw them as one, the leader's
	// as two, and the follower numbered the bundle first.
	leaderSrc.pem.Store("B")
	followerSrc.pem.Store("B")
	followerSrc.count.Store(2)
	leaderSrc.count.Store(3)
	if got := follower.BundleSequence(); got != 2 {
		t.Fatalf("follower first: %d", got)
	}
	if got := leader.BundleSequence(); got != 3 {
		t.Fatalf("leader: %d", got)
	}
	if got := follower.BundleSequence(); got != 2 {
		t.Fatalf("follower before its recheck: %d", got)
	}
	clock = clock.Add(sequenceRecheck + time.Second)
	if got := follower.BundleSequence(); got != 3 {
		t.Fatalf("follower after its recheck: %d, want the leader's 3", got)
	}
}

func TestDurableSequenceStoreFailures(t *testing.T) {
	store := NewMemCAStore()
	src := newFakeMaterial("A")
	store.Fail(errors.New("db down"), nil)
	if _, err := NewDurableSequence(src, store, "omega.local"); err == nil {
		t.Fatal("started without reading the stored sequence")
	}
	store.Fail(nil, nil)
	d := newSeq(t, src, store, "omega.local")
	clock := time.Now()
	d.now = func() time.Time { return clock }
	if d.BundleSequence() != 1 {
		t.Fatal("first")
	}
	// With the store down, a change keeps the last sequence rather than
	// guess, and the store is read again after a pause, not on every
	// call.
	store.Fail(errors.New("db down"), nil)
	src.pem.Store("B")
	if got := d.BundleSequence(); got != 1 {
		t.Fatalf("with the store down: %d", got)
	}
	store.Fail(nil, nil)
	loads, _ := store.Counts()
	if got := d.BundleSequence(); got != 1 {
		t.Fatalf("during the pause: %d", got)
	}
	if after, _ := store.Counts(); after != loads {
		t.Fatal("the store was read again during the pause")
	}
	clock = clock.Add(sequenceRecheck + time.Second)
	if got := d.BundleSequence(); got != 2 {
		t.Fatalf("once the store is back: %d", got)
	}
	store.Fail(nil, errors.New("read only"))
	src.pem.Store("C")
	if got := d.BundleSequence(); got != 3 {
		t.Fatalf("with saves failing: %d", got)
	}
	// A JWT bundle that cannot be read is not a change: the last
	// sequence stays, and nothing moves once it can be read again.
	store.Fail(nil, nil)
	src.jwtErr = errors.New("no keys")
	if got := d.BundleSequence(); got != 3 {
		t.Fatalf("without JWT keys: %d", got)
	}
	src.jwtErr = nil
	if got := d.BundleSequence(); got != 3 {
		t.Fatalf("after the JWT keys are back: %d", got)
	}
	if seq, _, _ := store.LoadBundleSequence(t.Context(), "omega.local"); seq > 3 {
		t.Fatalf("stored sequence moved: %d", seq)
	}
	src.jwtErr = errors.New("no keys")
	if _, err := NewDurableSequence(src, store, "omega.local"); err == nil {
		t.Fatal("started without numbering the trust bundle")
	}
}

func TestDurableSequenceRefusesAnOutOfRangeStoredValue(t *testing.T) {
	store := NewMemCAStore()
	if err := store.SaveBundleSequence(context.Background(), "omega.local", math.MaxInt64-1, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDurableSequence(newFakeMaterial("A"), store, "omega.local"); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("continued from a stored sequence near overflow: %v", err)
	}
}
