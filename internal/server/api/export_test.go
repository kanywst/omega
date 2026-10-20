package api

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/kanywst/omega/internal/server/storage"
)

// SameTargetURIForTest exposes sameTargetURI to the external test package.
var SameTargetURIForTest = sameTargetURI

// ReplayFirstUseForTest drives a fresh replay cache with the given
// retention through a sequence of (key, time) uses.
func ReplayFirstUseForTest(retention time.Duration, uses []struct {
	Key string
	At  time.Time
}) []bool {
	c := newReplayCache(retention)
	out := make([]bool, len(uses))
	for i, u := range uses {
		out[i], _ = c.firstUse(u.Key, u.At)
	}
	return out
}

// ReplayOwnerQuotaForTest reports, for n fresh keys from one owner and
// then one key from another, which uses a cache with the given per-owner
// quota accepts.
func ReplayOwnerQuotaForTest(quota, n int) (ownerAccepted int, otherAccepted bool) {
	c := newReplayCache(time.Hour)
	c.perOwner = quota
	now := time.Unix(1_000_000, 0)
	for i := 0; i < n; i++ {
		if ok, _ := c.firstUseBy("noisy", string(rune('a'+i%26))+time.Duration(i).String(), now); ok {
			ownerAccepted++
		}
	}
	otherAccepted, _ = c.firstUseBy("quiet", "k", now)
	return ownerAccepted, otherAccepted
}

// FailAuditForTest makes every audit append of the given kind fail.
func (s *Server) FailAuditForTest(kind string) {
	s.auditFault = func(ev storage.AuditEvent) error {
		if ev.Kind == kind {
			return errors.New("injected audit failure")
		}
		return nil
	}
}

// FailRefreshForTest makes directory reloads fail while fail is true.
func (s *Server) FailRefreshForTest(fail *atomic.Bool) {
	s.refreshFault = func() error {
		if fail.Load() {
			return errors.New("injected refresh failure")
		}
		return nil
	}
}

// FailAuditAfterSyncForTest makes appends of kind fail, after reloading
// the directory as a concurrent sync would, so the failed change is
// projected before it is undone.
func (s *Server) FailAuditAfterSyncForTest(kind string) {
	s.auditFault = func(ev storage.AuditEvent) error {
		if ev.Kind != kind {
			return nil
		}
		if ev.Decision != "reverted" {
			_ = s.RefreshDirectory(context.Background())
		}
		return errors.New("injected audit failure")
	}
}

// FailSCIMForTest makes every SCIM change fail before it commits.
func (s *Server) FailSCIMForTest() {
	s.scimFault = func(storage.AuditEvent) error { return errors.New("injected audit failure") }
}

// RefusalAllowForTest drives a fresh refusal limiter with the given
// window through a sequence of (caller, time) refusals.
func RefusalAllowForTest(window time.Duration, refusals []struct {
	Caller string
	At     time.Time
}) (audited []bool, suppressed []int) {
	l := newRefusalLimiter(window)
	for _, r := range refusals {
		ok, n := l.allow(r.Caller, r.At)
		audited = append(audited, ok)
		suppressed = append(suppressed, n)
	}
	return audited, suppressed
}

// RefusalFullForTest fills a limiter that tracks max callers and
// reports whether two refusals from a new caller in one window are both
// audited.
func RefusalFullForTest(max int) (bool, bool) {
	l := newRefusalLimiter(time.Minute)
	l.max = max
	t0 := time.Unix(1_000_000, 0)
	for i := range max {
		l.allow(string(rune('a'+i)), t0)
	}
	first, _ := l.allow("new", t0.Add(time.Second))
	second, _ := l.allow("new", t0.Add(2*time.Second))
	return first, second
}

// RefusalUnrecordedForTest lets one refusal through, fails its audit
// write, and reports what the caller's next refusal a second later gets.
func RefusalUnrecordedForTest() (bool, int) {
	l := newRefusalLimiter(time.Minute)
	t0 := time.Unix(1_000_000, 0)
	_, n := l.allow("a", t0)
	l.unrecorded("a", n+1)
	return l.allow("a", t0.Add(time.Second))
}
