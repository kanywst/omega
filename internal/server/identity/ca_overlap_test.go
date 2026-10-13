package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCAPEM(t *testing.T, name string, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestCAOverlapKeepsADroppedCAForTheGracePeriod(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	o := newCAOverlap(UpstreamCAGrace)

	served, err := o.update(a, now)
	if err != nil || o.sequence() != 1 || string(served) != string(a) {
		t.Fatalf("baseline: %v seq %d", err, o.sequence())
	}
	if _, _ = o.update(a, now); o.sequence() != 1 {
		t.Fatal("an unchanged bundle must not advance the sequence")
	}
	// The issuer rotates from A to B: A stays, after B.
	served, _ = o.update(b, now.Add(time.Minute))
	if strings.Count(string(served), "BEGIN CERTIFICATE") != 2 || !strings.HasPrefix(string(served), string(b)) || o.sequence() != 2 {
		t.Fatalf("after rotation: %d certs, seq %d", strings.Count(string(served), "BEGIN CERTIFICATE"), o.sequence())
	}
	// Still within the grace period.
	served, _ = o.update(b, now.Add(UpstreamCAGrace-time.Minute))
	if strings.Count(string(served), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("A must be kept until the grace period ends")
	}
	// After it, only B.
	served, _ = o.update(b, now.Add(UpstreamCAGrace+2*time.Minute))
	if string(served) != string(b) || o.sequence() != 3 {
		t.Fatalf("after the grace period: seq %d", o.sequence())
	}
}

func TestCAOverlapNeverKeepsACAPastItsExpiry(t *testing.T) {
	now := time.Now()
	short := testCAPEM(t, "short", now.Add(time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	o := newCAOverlap(UpstreamCAGrace)
	_, _ = o.update(short, now)
	_, _ = o.update(b, now)
	served, _ := o.update(b, now.Add(2*time.Hour))
	if string(served) != string(b) {
		t.Fatal("an expired CA must not be served")
	}
}

func TestCAOverlapForgetsACAThatComesBack(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	o := newCAOverlap(UpstreamCAGrace)
	_, _ = o.update(a, now)
	_, _ = o.update(b, now)
	served, _ := o.update(append(append([]byte(nil), a...), b...), now)
	if strings.Count(string(served), "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("a CA the issuer publishes again must not be listed twice: %d", strings.Count(string(served), "BEGIN CERTIFICATE"))
	}
	if _, err := o.update([]byte("not pem"), now); err == nil {
		t.Fatal("a bundle without certificates must be refused")
	}
}

func TestCAOverlapOffAndOrderAndServeTimePruning(t *testing.T) {
	now := time.Now()
	a := testCAPEM(t, "A", now.Add(365*24*time.Hour))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	c := testCAPEM(t, "C", now.Add(365*24*time.Hour))

	off := newCAOverlap(upstreamGrace(-1))
	_, _ = off.update(a, now)
	if served, _ := off.update(b, now); string(served) != string(b) {
		t.Fatal("with the overlap off a dropped CA must go at once")
	}

	o := newCAOverlap(upstreamGrace(0))
	_, _ = o.update(append(append([]byte(nil), a...), b...), now)
	_, _ = o.update(c, now)
	first := o.serve(now)
	seq := o.sequence()
	for range 20 {
		if got := o.serve(now); string(got) != string(first) {
			t.Fatal("two kept CAs must be served in a stable order")
		}
	}
	if o.sequence() != seq {
		t.Fatal("re-serving an unchanged set must not move spiffe_sequence")
	}
	// Without any refresh, the kept CAs go once the grace ends.
	if got := o.serve(now.Add(UpstreamCAGrace + time.Minute)); string(got) != string(c) {
		t.Fatal("kept CAs must be dropped at serve time once their grace ends")
	}
	if newCAOverlap(time.Hour).serve(now) != nil {
		t.Fatal("nothing to serve before the first fetch")
	}
}

func TestCAOverlapDoesNotKeepAnAlreadyExpiredCA(t *testing.T) {
	now := time.Now()
	expired := testCAPEM(t, "old", now.Add(-time.Minute))
	b := testCAPEM(t, "B", now.Add(365*24*time.Hour))
	o := newCAOverlap(UpstreamCAGrace)
	_, _ = o.update(expired, now)
	if served, _ := o.update(b, now); string(served) != string(b) {
		t.Fatal("an expired CA the issuer dropped must not be kept")
	}
}
