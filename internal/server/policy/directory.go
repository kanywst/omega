package policy

import (
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
)

// Entity types the engine derives from control-plane state.
const (
	DomainEntityType = "Domain"
	SpiffeEntityType = "Spiffe"
)

// Directory is control-plane state projected into the Cedar entity
// store, so policies can test membership with `in`.
type Directory struct {
	// Domains maps each domain name to its parent ("" at the top level).
	// Each becomes Domain::"<name>" whose parent is Domain::"<parent>",
	// and a Spiffe principal or resource is placed in the deepest domain
	// whose labels prefix its SPIFFE ID path: spiffe://td/media/news/web
	// is in Domain::"media.news", and so in Domain::"media".
	Domains map[string]string
}

// SetDirectory replaces the projected control-plane state.
func (e *Engine) SetDirectory(d Directory) {
	ents := cedar.EntityMap{}
	domains := make(map[string]bool, len(d.Domains))
	for name, parent := range d.Domains {
		uid := cedar.NewEntityUID(DomainEntityType, cedar.String(name))
		ent := cedar.Entity{UID: uid}
		if parent != "" {
			ent.Parents = cedar.NewEntityUIDSet(cedar.NewEntityUID(DomainEntityType, cedar.String(parent)))
		}
		ents[uid] = ent
		domains[name] = true
	}
	e.mu.Lock()
	e.directory = ents
	e.domains = domains
	e.rebuildLocked()
	e.mu.Unlock()
}

// rebuildLocked merges the static and directory entity maps and
// reindexes them. Callers hold e.mu for writing.
func (e *Engine) rebuildLocked() {
	merged := make(cedar.EntityMap, len(e.static)+len(e.directory))
	for uid, ent := range e.directory {
		merged[uid] = ent
	}
	for uid, ent := range e.static {
		merged[uid] = ent
	}
	e.entities = merged
	e.byType = indexByType(merged)
}

// withSPIFFEParents adds each Spiffe UID's domain to its parents,
// copying ents first if it changes anything.
func (e *Engine) withSPIFFEParents(ents cedar.EntityMap, uids ...cedar.EntityUID) cedar.EntityMap {
	e.mu.RLock()
	domains := e.domains
	e.mu.RUnlock()
	if len(domains) == 0 {
		return ents
	}
	cloned := false
	for _, uid := range uids {
		if string(uid.Type) != SpiffeEntityType {
			continue
		}
		dom := domainOfSPIFFEID(string(uid.ID), domains)
		if dom == "" {
			continue
		}
		if !cloned {
			ents = ents.Clone()
			cloned = true
		}
		ent, ok := ents[uid]
		if !ok {
			ent = cedar.Entity{UID: uid}
		}
		parents := ent.Parents.Slice()
		parents = append(parents, cedar.NewEntityUID(DomainEntityType, cedar.String(dom)))
		ent.Parents = cedar.NewEntityUIDSet(parents...)
		ents[uid] = ent
	}
	return ents
}

// domainOfSPIFFEID returns the deepest known domain whose labels are a
// prefix of the SPIFFE ID's path segments, or "".
func domainOfSPIFFEID(id string, domains map[string]bool) string {
	rest, ok := strings.CutPrefix(id, "spiffe://")
	if !ok {
		return ""
	}
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return ""
	}
	segs := strings.Split(strings.Trim(rest[i:], "/"), "/")
	// A path segment holding a dot is not a domain label, so it and
	// everything after it cannot be part of the match.
	for n, seg := range segs {
		if strings.Contains(seg, ".") {
			segs = segs[:n]
			break
		}
	}
	for n := len(segs); n > 0; n-- {
		if name := strings.Join(segs[:n], "."); domains[name] {
			return name
		}
	}
	return ""
}
