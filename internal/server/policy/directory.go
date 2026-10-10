package policy

import (
	"log/slog"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Entity types the engine derives from control-plane state.
const (
	DomainEntityType = "Domain"
	SpiffeEntityType = "Spiffe"
)

// Directory is control-plane state projected into the Cedar entity
// store, so policies can test membership with `in`.
type Directory struct {
	// TrustDomain is the local trust domain. Only SPIFFE IDs in it are
	// placed in a domain; a federated peer's IDs never are.
	TrustDomain spiffeid.TrustDomain
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
	e.trustDomain = d.TrustDomain
	e.rebuildLocked()
	e.mu.Unlock()
}

// rebuildLocked merges the static and directory entity maps and
// reindexes them. Callers hold e.mu for writing. The directory wins: a
// static entity with the same UID as a projected one would cut the
// hierarchy (and so silently narrow a forbid), so it is ignored, loudly.
func (e *Engine) rebuildLocked() {
	merged := make(cedar.EntityMap, len(e.static)+len(e.directory))
	for uid, ent := range e.static {
		merged[uid] = ent
	}
	for uid, ent := range e.directory {
		if _, clash := e.static[uid]; clash {
			slog.Warn("entities.json declares an entity the control plane projects; the control plane's wins", "entity", uid.String())
		}
		merged[uid] = ent
	}
	e.entities = merged
	e.byType = indexByType(merged)
}

// withSPIFFEParents adds each Spiffe UID's domain to its parents,
// copying ents first if it changes anything. ents, domains and td must
// come from the same snapshot so a parent always names an entity in ents.
func withSPIFFEParents(ents cedar.EntityMap, domains map[string]bool, td spiffeid.TrustDomain, uids ...cedar.EntityUID) cedar.EntityMap {
	if len(domains) == 0 || td.IsZero() {
		return ents
	}
	cloned := false
	for _, uid := range uids {
		if string(uid.Type) != SpiffeEntityType {
			continue
		}
		dom := domainOfSPIFFEID(string(uid.ID), domains, td)
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
// prefix of the SPIFFE ID's path segments, or "". The ID must be a
// canonical SPIFFE ID in the local trust domain.
func domainOfSPIFFEID(raw string, domains map[string]bool, td spiffeid.TrustDomain) string {
	id, err := spiffeid.FromString(raw)
	if err != nil || !id.MemberOf(td) || id.Path() == "" {
		return ""
	}
	segs := strings.Split(strings.TrimPrefix(id.Path(), "/"), "/")
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
