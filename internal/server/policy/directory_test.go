package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/policy"
)

func engineWith(t *testing.T, cedarSrc string) *policy.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(cedarSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	e := policy.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSPIFFEPrincipalInDomainHierarchy(t *testing.T) {
	e := engineWith(t, `permit (principal in Domain::"media", action == Action::"read", resource);`)
	e.SetDirectory(policy.Directory{TrustDomain: spiffeid.RequireTrustDomainFromString("omega.local"), Domains: map[string]string{"media": "", "media.news": "media", "sports": ""}})

	cases := []struct {
		id   string
		want bool
	}{
		{"spiffe://omega.local/media/news/web", true},   // media.news -> media
		{"spiffe://omega.local/media/web", true},        // media
		{"spiffe://omega.local/sports/web", false},      // another domain
		{"spiffe://omega.local/media.news/web", false},  // a dotted segment is not a label path
		{"spiffe://omega.local/mediax/web", false},      // label prefix, not segment prefix
		{"spiffe://peer.example/media/news/web", false}, // a federated peer's ID is never local
		{"spiffe://omega.local//media/web", false},      // not a canonical SPIFFE ID
	}
	for _, tc := range cases {
		resp, err := e.Evaluate(policy.EvalRequest{
			Subject:  policy.Entity{Type: "Spiffe", ID: tc.id},
			Action:   policy.Action{Name: "read"},
			Resource: policy.Entity{Type: "Doc", ID: "d"},
		})
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		if resp.Decision != tc.want {
			t.Errorf("%s: decision %v, want %v", tc.id, resp.Decision, tc.want)
		}
	}
}

func TestResourceDomainAndDomainEntitiesSearchable(t *testing.T) {
	e := engineWith(t, `permit (principal, action == Action::"read", resource in Domain::"media");`)
	e.SetDirectory(policy.Directory{TrustDomain: spiffeid.RequireTrustDomainFromString("omega.local"), Domains: map[string]string{"media": "", "media.news": "media"}})
	resp, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "User", ID: "u"},
		Action:   policy.Action{Name: "read"},
		Resource: policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/media/news/db", Attrs: map[string]any{"tier": "gold"}},
	})
	if err != nil || !resp.Decision {
		t.Fatalf("resource in domain: %+v %v", resp, err)
	}
	if got := e.EntitiesOfType("Domain"); len(got) != 2 {
		t.Errorf("Domain entities: %v", got)
	}
	e.SetDirectory(policy.Directory{})
	if resp, _ := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "User", ID: "u"},
		Action:   policy.Action{Name: "read"},
		Resource: policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/media/news/db"},
	}); resp.Decision {
		t.Error("after the domains are gone the resource is no longer in Domain::\"media\"")
	}
}

func TestDirectoryWinsOverStaticEntities(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(`forbid (principal in Domain::"media", action, resource);
permit (principal, action, resource);`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A static Domain::"media.news" without its parent would cut the chain.
	if err := os.WriteFile(filepath.Join(dir, "entities.json"), []byte(`[{"uid":{"type":"Domain","id":"media.news"},"parents":[],"attrs":{}}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	e := policy.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	e.SetDirectory(policy.Directory{TrustDomain: spiffeid.RequireTrustDomainFromString("omega.local"), Domains: map[string]string{"media": "", "media.news": "media"}})
	resp, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/media/news/web"},
		Action:   policy.Action{Name: "read"},
		Resource: policy.Entity{Type: "Doc", ID: "d"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision {
		t.Fatal("the forbid on media must still cover media.news despite the static entity")
	}
}
