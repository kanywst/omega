package api

import (
	"errors"
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
