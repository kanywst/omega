package api

import "time"

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
