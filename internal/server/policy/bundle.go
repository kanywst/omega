package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Bundle is everything a local evaluator needs to decide exactly as the
// control plane would: the Cedar sources, the static entities and the
// projected domain and group directory. Revision is a content hash, so
// two bundles with the same revision evaluate identically.
type Bundle struct {
	Revision  string            `json:"revision"`
	Policies  map[string]string `json:"policies"`
	Entities  json.RawMessage   `json:"entities,omitempty"`
	Directory BundleDirectory   `json:"directory"`
}

// BundleDirectory is Directory in wire form.
type BundleDirectory struct {
	TrustDomain string                        `json:"trust_domain,omitempty"`
	Domains     map[string]string             `json:"domains,omitempty"`
	Groups      []string                      `json:"groups,omitempty"`
	Memberships map[string][]BundleMembership `json:"memberships,omitempty"`
}

// BundleMembership is Membership in wire form.
type BundleMembership struct {
	Group     string    `json:"group"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Bundle exports the engine's current state.
func (e *Engine) Bundle() (Bundle, error) {
	sources, raw, dir := e.Snapshot()
	b := Bundle{Policies: sources, Directory: BundleDirectory{
		Domains:     dir.Domains,
		Groups:      append([]string(nil), dir.Groups...),
		Memberships: map[string][]BundleMembership{},
	}}
	if b.Policies == nil {
		b.Policies = map[string]string{}
	}
	if len(raw) > 0 {
		b.Entities = json.RawMessage(raw)
	}
	if !dir.TrustDomain.IsZero() {
		b.Directory.TrustDomain = dir.TrustDomain.Name()
	}
	sort.Strings(b.Directory.Groups)
	for principal, ms := range dir.Memberships {
		out := make([]BundleMembership, 0, len(ms))
		for _, m := range ms {
			out = append(out, BundleMembership{Group: m.Group, ExpiresAt: m.ExpiresAt.UTC()})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
		b.Directory.Memberships[principal] = out
	}
	rev, err := bundleRevision(b)
	if err != nil {
		return Bundle{}, err
	}
	b.Revision = rev
	return b, nil
}

// LoadBundle replaces the engine's state with b, after checking that its
// revision matches its content.
func (e *Engine) LoadBundle(b Bundle) error {
	rev, err := bundleRevision(b)
	if err != nil {
		return err
	}
	if rev != b.Revision {
		return fmt.Errorf("bundle revision %q does not match its content (%q)", b.Revision, rev)
	}
	dir := Directory{Domains: b.Directory.Domains, Groups: b.Directory.Groups, Memberships: map[string][]Membership{}}
	if b.Directory.TrustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(b.Directory.TrustDomain)
		if err != nil {
			return fmt.Errorf("bundle trust domain: %w", err)
		}
		dir.TrustDomain = td
	}
	for principal, ms := range b.Directory.Memberships {
		for _, m := range ms {
			dir.Memberships[principal] = append(dir.Memberships[principal], Membership(m))
		}
	}
	ps, static, err := parseSources(b.Policies, b.Entities)
	if err != nil {
		return err
	}
	ents, snap := buildDirectory(dir)
	// One swap, so no evaluation sees new policies with an old directory
	// or reports a revision other than the one it decided with.
	e.mu.Lock()
	e.policies, e.static, e.sources, e.staticRaw = ps, static, b.Policies, b.Entities
	e.setDirectoryLocked(dir, ents, snap)
	e.revision = b.Revision
	e.rebuildLocked()
	e.mu.Unlock()
	return nil
}

// bundleRevision hashes everything but the revision. encoding/json
// writes map keys in sorted order, so equal content hashes equally.
func bundleRevision(b Bundle) (string, error) {
	b.Revision = ""
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("encode bundle: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
