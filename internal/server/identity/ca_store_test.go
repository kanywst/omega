package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// MemCAStore is an in-memory UpstreamCAStore and BundleSequenceStore
// shared by the tests in this package and in identity_test. Each view
// returned by Replica shares the rows but has its own leader bit.
type MemCAStore struct {
	*memRows
	Follower bool
}

type memRows struct {
	mu      sync.Mutex
	cas     map[string][]UpstreamCA
	seq     map[string]int64
	digest  map[string]string
	loadErr error
	saveErr error
	loads   int
	saves   int
}

// NewMemCAStore returns an empty store whose view is the leader.
func NewMemCAStore() *MemCAStore {
	return &MemCAStore{memRows: &memRows{cas: map[string][]UpstreamCA{}, seq: map[string]int64{}, digest: map[string]string{}}}
}

// Replica returns a view of the same rows from another replica.
func (m *MemCAStore) Replica(follower bool) *MemCAStore {
	return &MemCAStore{memRows: m.memRows, Follower: follower}
}

// Fail makes the next loads or saves fail until cleared with nil.
func (m *MemCAStore) Fail(load, save error) {
	m.mu.Lock()
	m.loadErr, m.saveErr = load, save
	m.mu.Unlock()
}

// Rows returns the stored CAs for a trust domain and backend.
func (m *MemCAStore) Rows(trustDomain, backend string) []UpstreamCA {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]UpstreamCA(nil), m.cas[trustDomain+"/"+backend]...)
}

// Put stores rows directly, as another process would have just now; a
// row with a SavedAt keeps it, as a replayed old row would.
func (m *MemCAStore) Put(trustDomain, backend string, rows []UpstreamCA) {
	m.mu.Lock()
	m.cas[trustDomain+"/"+backend] = stamp(rows)
	m.mu.Unlock()
}

func stamp(rows []UpstreamCA) []UpstreamCA {
	out := append([]UpstreamCA(nil), rows...)
	for i := range out {
		if out[i].SavedAt.IsZero() {
			out[i].SavedAt = time.Now()
		}
	}
	return out
}

// Counts returns how many loads and saves reached the store.
func (m *MemCAStore) Counts() (loads, saves int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loads, m.saves
}

func (m *MemCAStore) LoadUpstreamCAs(_ context.Context, trustDomain, backend string) ([]UpstreamCA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return append([]UpstreamCA(nil), m.cas[trustDomain+"/"+backend]...), nil
}

func (m *MemCAStore) SaveUpstreamCAs(_ context.Context, trustDomain, backend string, cas []UpstreamCA) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Follower {
		return ErrStoreNotLeader
	}
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saves++
	rows := append([]UpstreamCA(nil), cas...)
	for i := range rows {
		rows[i].SavedAt = time.Now()
	}
	m.cas[trustDomain+"/"+backend] = rows
	return nil
}

func (m *MemCAStore) LoadBundleSequence(_ context.Context, trustDomain string) (int64, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	if m.loadErr != nil {
		return 0, "", m.loadErr
	}
	return m.seq[trustDomain], m.digest[trustDomain], nil
}

func (m *MemCAStore) SaveBundleSequence(_ context.Context, trustDomain string, seq int64, digest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Follower {
		return ErrStoreNotLeader
	}
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saves++
	if seq > m.seq[trustDomain] {
		m.seq[trustDomain], m.digest[trustDomain] = seq, digest
	}
	return nil
}

func derOf(t *testing.T, p []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("not PEM")
	}
	return b.Bytes
}

func certCount(b []byte) int { return strings.Count(string(b), "BEGIN CERTIFICATE") }

// keptRow finds der among the kept rows.
func keptRow(rows []UpstreamCA, der []byte) (UpstreamCA, bool) {
	for _, r := range rows {
		if string(r.DER) == string(der) && !r.Until.IsZero() {
			return r, true
		}
	}
	return UpstreamCA{}, false
}

type eventLog struct {
	mu sync.Mutex
	ev []KeptCAEvent
}

func (l *eventLog) add(e KeptCAEvent) { l.mu.Lock(); l.ev = append(l.ev, e); l.mu.Unlock() }

func (l *eventLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.ev {
		out = append(out, strings.TrimSuffix(e.Action+":"+e.Reason, ":"))
	}
	l.ev = nil
	return out
}

func TestCAOverlapKeepsTheKeptSetAcrossARestart(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	store := NewMemCAStore()

	o1 := newCAOverlap(UpstreamCAGrace)
	_, _ = o1.update(a, now)
	if err := o1.attachStore(store, "omega.local", "vault-pki", now); err != nil {
		t.Fatal(err)
	}
	if rows := store.Rows("omega.local", "vault-pki"); len(rows) != 1 || !rows[0].Until.IsZero() {
		t.Fatalf("baseline not stored: %+v", rows)
	}
	_, _ = o1.update(b, now.Add(time.Minute))
	kept, ok := keptRow(store.Rows("omega.local", "vault-pki"), derOf(t, a))
	if !ok || !kept.Until.Equal(now.Add(time.Minute+UpstreamCAGrace)) {
		t.Fatalf("kept CA not stored: %+v", kept)
	}

	// A new process starts after the rotation: the issuer only has B.
	o2 := newCAOverlap(UpstreamCAGrace)
	var log eventLog
	o2.setHook(log.add)
	_, _ = o2.update(b, now.Add(time.Hour))
	if err := o2.attachStore(store, "omega.local", "vault-pki", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := o2.serve(now.Add(time.Hour)); certCount(got) != 2 {
		t.Fatalf("restart lost the kept CA: %d certs", certCount(got))
	}
	if ev := log.take(); len(ev) != 1 || ev[0] != "kept:restored" {
		t.Fatalf("a CA taken from the store is recorded as restored: %v", ev)
	}
	// It is dropped when the first process would have dropped it.
	if got := o2.serve(now.Add(UpstreamCAGrace + 2*time.Minute)); string(got) != string(b) {
		t.Fatal("the restored CA outlived its grace")
	}
	if ev := log.take(); len(ev) != 1 || ev[0] != "dropped:grace-ended" {
		t.Fatalf("events: %v", ev)
	}
	if _, ok := keptRow(store.Rows("omega.local", "vault-pki"), derOf(t, a)); ok {
		t.Fatal("the dropped CA is still stored")
	}
}

func TestCAOverlapIgnoresAReplayedOldIssuerRow(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	store := NewMemCAStore()
	// A valid row for A, saved two grace periods ago, replayed into the
	// database after the issuer stopped publishing A.
	store.Put("omega.local", "step-ca", []UpstreamCA{{DER: derOf(t, a), SavedAt: now.Add(-2 * UpstreamCAGrace)}})
	o := newCAOverlap(UpstreamCAGrace)
	_, _ = o.update(b, now)
	if err := o.attachStore(store, "omega.local", "step-ca", now); err != nil {
		t.Fatal(err)
	}
	if got := o.serve(now); string(got) != string(b) {
		t.Fatal("a replayed row older than the grace made A trusted again")
	}
	// Saved half a grace ago: kept, but only until save time plus grace.
	store2 := NewMemCAStore()
	savedAt := now.Add(-UpstreamCAGrace / 2)
	store2.Put("omega.local", "step-ca", []UpstreamCA{{DER: derOf(t, a), SavedAt: savedAt}})
	o2 := newCAOverlap(UpstreamCAGrace)
	_, _ = o2.update(b, now)
	if err := o2.attachStore(store2, "omega.local", "step-ca", now); err != nil {
		t.Fatal(err)
	}
	if got := o2.serve(now); certCount(got) != 2 {
		t.Fatal("a recent row lost the CA")
	}
	if got := o2.serve(savedAt.Add(UpstreamCAGrace + time.Minute)); string(got) != string(b) {
		t.Fatal("a restored CA outlived its row's save time plus the grace")
	}
}

func TestCAOverlapCatchesARotationWhileDown(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	store := NewMemCAStore()
	store.Put("omega.local", "step-ca", []UpstreamCA{{DER: derOf(t, a)}})

	o := newCAOverlap(UpstreamCAGrace)
	var log eventLog
	o.setHook(log.add)
	_, _ = o.update(b, now)
	if err := o.attachStore(store, "omega.local", "step-ca", now); err != nil {
		t.Fatal(err)
	}
	if got := o.serve(now); certCount(got) != 2 || o.sequence() != 2 {
		t.Fatalf("the CA the issuer dropped while Omega was down is not kept: %d certs, seq %d", certCount(got), o.sequence())
	}
	if ev := log.take(); len(ev) != 1 || ev[0] != "kept" {
		t.Fatalf("events: %v", ev)
	}
	// Only the first merge after a start reads the stored issuer set: a
	// stale row does not keep a CA again after its grace.
	store.Put("omega.local", "step-ca", []UpstreamCA{{DER: derOf(t, a)}})
	if got, _ := o.update(b, now.Add(UpstreamCAGrace+time.Minute)); string(got) != string(b) {
		t.Fatal("a stale stored issuer CA was kept again")
	}
}

func TestCAOverlapRestoresWithinTheCurrentGrace(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	c := testCAPEM(t, "C", now.Add(365*24*time.Hour))
	store := NewMemCAStore()
	store.Put("omega.local", "aws-pca", []UpstreamCA{
		{DER: derOf(t, b)},
		{DER: derOf(t, a), KeptAt: now.Add(-2 * time.Hour), Until: now.Add(22 * time.Hour)},
		{DER: derOf(t, c), KeptAt: now.Add(-48 * time.Hour), Until: now.Add(-24 * time.Hour)},
	})

	// The grace is now one hour shorter than it was: A's time is cut.
	o := newCAOverlap(3 * time.Hour)
	var log eventLog
	o.setHook(log.add)
	_, _ = o.update(b, now)
	if err := o.attachStore(store, "omega.local", "aws-pca", now); err != nil {
		t.Fatal(err)
	}
	if ev := log.take(); len(ev) != 2 || ev[0] != "kept:restored" || ev[1] != "dropped:grace-ended" {
		t.Fatalf("a CA whose grace ended while Omega was down is reported dropped: %v", ev)
	}
	kept, ok := keptRow(store.Rows("omega.local", "aws-pca"), derOf(t, a))
	if !ok || !kept.Until.Equal(now.Add(time.Hour)) {
		t.Fatalf("restored CA's time: %+v", kept)
	}
	if _, ok := keptRow(store.Rows("omega.local", "aws-pca"), derOf(t, c)); ok {
		t.Fatal("the expired CA is still stored")
	}

	// With the overlap turned off, nothing stored is kept.
	off := newCAOverlap(upstreamGrace(0))
	_, _ = off.update(b, now)
	if err := off.attachStore(store, "omega.local", "aws-pca", now); err != nil {
		t.Fatal(err)
	}
	if got := off.serve(now); string(got) != string(b) {
		t.Fatal("a stored CA was kept with the overlap off")
	}
}

func TestCAOverlapReplicasShareTheKeptSet(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	store := NewMemCAStore()

	leader, follower := newCAOverlap(UpstreamCAGrace), newCAOverlap(UpstreamCAGrace)
	var log eventLog
	follower.setHook(log.add)
	for _, o := range []*caOverlap{leader, follower} {
		_, _ = o.update(a, now)
	}
	if err := leader.attachStore(store, "omega.local", "vault-pki", now); err != nil {
		t.Fatal(err)
	}
	if err := follower.attachStore(store.Replica(true), "omega.local", "vault-pki", now); err != nil {
		t.Fatal(err)
	}
	// The leader sees the rotation first; the follower ten minutes later
	// keeps A until the time the leader stored.
	_, _ = leader.update(b, now.Add(time.Minute))
	_, _ = follower.update(b, now.Add(10*time.Minute))
	if ev := log.take(); len(ev) != 1 || ev[0] != "kept:restored" {
		t.Fatalf("the follower takes the leader's CA as restored, not as its own rotation: %v", ev)
	}
	until := now.Add(time.Minute + UpstreamCAGrace)
	if got := follower.serve(until.Add(-time.Second)); certCount(got) != 2 {
		t.Fatal("the follower dropped A early")
	}
	if got := follower.serve(until); string(got) != string(b) {
		t.Fatal("the follower kept A past the leader's time")
	}

	// A CA the follower keeps before the leader stores it is its own
	// until the leader's row arrives, and is not stored by it.
	c := testCAPEM(t, "C", now.Add(365*24*time.Hour))
	both := append(append([]byte(nil), b...), c...)
	for _, o := range []*caOverlap{leader, follower} {
		_, _ = o.update(both, now.Add(2*time.Hour))
	}
	_, _ = follower.update(b, now.Add(3*time.Hour))
	if _, ok := keptRow(store.Rows("omega.local", "vault-pki"), derOf(t, c)); ok {
		t.Fatal("a follower wrote to the store")
	}
	if got := follower.serve(now.Add(3 * time.Hour)); !strings.Contains(string(got), string(c)) {
		t.Fatal("the follower did not keep C on its own")
	}
}

func TestCAOverlapStoreFailures(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	store := NewMemCAStore()
	o := newCAOverlap(UpstreamCAGrace)
	_, _ = o.update(a, now)

	store.Fail(errors.New("db down"), nil)
	if err := o.attachStore(store, "omega.local", "vault-pki", now); err == nil {
		t.Fatal("a store that cannot be read was attached")
	}
	store.Fail(nil, nil)
	if err := o.attachStore(store, "omega.local", "vault-pki", now); err != nil {
		t.Fatal(err)
	}

	// A refresh goes on without the store, and a failed save is tried
	// again on the next refresh.
	store.Fail(errors.New("db down"), errors.New("db down"))
	if got, err := o.update(b, now.Add(time.Minute)); err != nil || certCount(got) != 2 {
		t.Fatalf("refresh with the store down: %v %d", err, certCount(got))
	}
	store.Fail(nil, nil)
	if _, ok := keptRow(store.Rows("omega.local", "vault-pki"), derOf(t, a)); ok {
		t.Fatal("stored while the store was down")
	}
	_, _ = o.update(b, now.Add(2*time.Minute))
	if _, ok := keptRow(store.Rows("omega.local", "vault-pki"), derOf(t, a)); !ok {
		t.Fatal("the failed save was not tried again")
	}
	// Nothing changed since: no further save.
	_, saves := store.Counts()
	_, _ = o.update(b, now.Add(3*time.Minute))
	if _, after := store.Counts(); after != saves {
		t.Fatalf("an unchanged state was stored again: %d -> %d saves", saves, after)
	}

	// A stored row that does not parse is skipped.
	rows := store.Rows("omega.local", "vault-pki")
	store.Put("omega.local", "vault-pki", append(rows, UpstreamCA{DER: []byte("junk"), KeptAt: now, Until: now.Add(time.Hour)}))
	if got, err := o.update(b, now.Add(4*time.Minute)); err != nil || certCount(got) != 2 {
		t.Fatalf("junk row: %v %d", err, certCount(got))
	}
}

func TestCAOverlapStoredRowsTheOperatorOrIssuerOverrode(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	store := NewMemCAStore()
	row := UpstreamCA{DER: derOf(t, a), KeptAt: now, Until: now.Add(time.Hour)}
	store.Put("omega.local", "vault-pki", []UpstreamCA{{DER: derOf(t, b)}, row})
	c, _ := x509.ParseCertificate(derOf(t, a))

	// Distrusted on this replica: the stored row is not taken up.
	o := newCAOverlap(UpstreamCAGrace)
	_, _ = o.update(b, now)
	o.distrust([][32]byte{sha256.Sum256(c.Raw)}, now)
	if err := o.attachStore(store.Replica(true), "omega.local", "vault-pki", now); err != nil {
		t.Fatal(err)
	}
	if got := o.serve(now); string(got) != string(b) {
		t.Fatal("a distrusted CA was restored")
	}

	// Not a CA, or kept past its own expiry: only the CA is taken, and
	// only until it expires.
	leaf := mustLeafDER(t)
	short := testCAPEM(t, "short", now.Add(time.Hour))
	store.Put("omega.local", "vault-pki", []UpstreamCA{{DER: derOf(t, b)},
		{DER: leaf, KeptAt: now, Until: now.Add(time.Hour)},
		{DER: derOf(t, short), KeptAt: now, Until: now.Add(10 * time.Hour)}})
	o = newCAOverlap(UpstreamCAGrace)
	_, _ = o.update(b, now)
	if err := o.attachStore(store.Replica(true), "omega.local", "vault-pki", now); err != nil {
		t.Fatal(err)
	}
	if len(o.retired) != 1 {
		t.Fatalf("kept %d stored certificates, want only the CA", len(o.retired))
	}
	for _, r := range o.retired {
		if !r.until.Equal(r.cert.NotAfter) {
			t.Fatalf("restored past its expiry: until %v, NotAfter %v", r.until, r.cert.NotAfter)
		}
	}
	store.Put("omega.local", "vault-pki", []UpstreamCA{{DER: derOf(t, b)}, row})

	// Published again by the issuer: it is current, not kept.
	o = newCAOverlap(UpstreamCAGrace)
	both := append(append([]byte(nil), b...), a...)
	_, _ = o.update(both, now)
	if err := o.attachStore(store.Replica(true), "omega.local", "vault-pki", now); err != nil {
		t.Fatal(err)
	}
	if got := o.serve(now); certCount(got) != 2 || len(o.retired) != 0 {
		t.Fatal("a republished CA was restored as kept")
	}
}

func mustLeafDER(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
