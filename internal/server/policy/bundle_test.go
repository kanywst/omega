package policy_test

import (
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/policy"
)

func TestBundleRoundTripDecidesTheSame(t *testing.T) {
	src := engineWith(t, `permit (principal in Domain::"media", action == Action::"read", resource);
permit (principal in Group::"media:oncall", action == Action::"page", resource);`)
	src.SetDirectory(policy.Directory{
		TrustDomain: spiffeid.RequireTrustDomainFromString("omega.local"),
		Domains:     map[string]string{"media": "", "media.news": "media"},
		Groups:      []string{"media:oncall"},
		Memberships: map[string][]policy.Membership{
			"spiffe://omega.local/people/alice": {{Group: "media:oncall", ExpiresAt: time.Now().Add(time.Hour)}},
		},
	})
	b, err := src.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := src.Bundle()
	if again.Revision != b.Revision {
		t.Fatal("the revision must be stable for unchanged content")
	}

	local := policy.New()
	if err := local.LoadBundle(b); err != nil {
		t.Fatal(err)
	}
	reqs := []policy.EvalRequest{
		{Subject: policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/media/news/web"}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}},
		{Subject: policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/people/alice"}, Action: policy.Action{Name: "page"}, Resource: policy.Entity{Type: "Pager", ID: "p"}},
		{Subject: policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/sports/web"}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}},
	}
	for _, r := range reqs {
		want, _ := src.Evaluate(r)
		got, _ := local.Evaluate(r)
		if want.Decision != got.Decision {
			t.Errorf("%s %s: local %v, control plane %v", r.Subject.ID, r.Action.Name, got.Decision, want.Decision)
		}
	}

	b.Policies["extra.cedar"] = `permit (principal, action, resource);`
	if err := policy.New().LoadBundle(b); err == nil {
		t.Error("a bundle whose content does not match its revision must be refused")
	}
}
