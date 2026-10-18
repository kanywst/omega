package policy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestBundleSignature(t *testing.T) {
	e := policy.New()
	b, err := e.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := policy.VerifyBundle(b, &key.PublicKey); err == nil {
		t.Error("an unsigned bundle must not verify")
	}
	if err := policy.SignBundle(&b, key); err != nil {
		t.Fatal(err)
	}
	if err := policy.CheckRevision(b); err != nil {
		t.Errorf("signing must not change the revision: %v", err)
	}
	if err := policy.VerifyBundle(b, &key.PublicKey); err != nil {
		t.Errorf("own key: %v", err)
	}
	if err := policy.VerifyBundle(b, &other.PublicKey); err == nil {
		t.Error("another key must not verify")
	}
	tampered := b
	tampered.Policies = map[string]string{"p.cedar": "permit (principal, action, resource);"}
	if err := policy.CheckRevision(tampered); err == nil {
		t.Error("changed content must fail the revision check")
	}
	tampered = b
	tampered.Revision = "0000"
	if err := policy.VerifyBundle(tampered, &key.PublicKey); err == nil {
		t.Error("a signature over another revision must not verify")
	}
	tampered.Signature = "!!"
	if err := policy.VerifyBundle(tampered, &key.PublicKey); err == nil {
		t.Error("a malformed signature must not verify")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err := policy.SignBundle(&b, p384); err == nil {
		t.Error("only P-256 keys sign bundles")
	}
}

// A bundle replaces the whole policy set, so a later stored-policy
// update on the same engine adds to the bundle's policies instead of
// falling back to whatever was loaded before it.
func TestLoadBundleReplacesTheFileAndStoredSets(t *testing.T) {
	src := engineWith(t, `@id("read") permit (principal, action == Action::"read", resource);`)
	b, err := src.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	local := engineWith(t, `@id("old") permit (principal, action == Action::"write", resource);`)
	if err := local.LoadBundle(b); err != nil {
		t.Fatal(err)
	}
	if err := local.SetStoredPolicies(map[string]string{"extra": `@id("page") permit (principal, action == Action::"page", resource);`}); err != nil {
		t.Fatal(err)
	}
	decide := func(action string) bool {
		r, _ := local.Evaluate(policy.EvalRequest{Subject: policy.Entity{Type: "U", ID: "u"}, Action: policy.Action{Name: action}, Resource: policy.Entity{Type: "D", ID: "d"}})
		return r.Decision
	}
	if !decide("read") || !decide("page") || decide("write") {
		t.Fatalf("read %v page %v write %v: want the bundle's and the stored policy, not the pre-bundle file", decide("read"), decide("page"), decide("write"))
	}
	if _, err := local.CheckStored("x", `@id("read") permit (principal, action, resource);`); err != nil {
		t.Fatalf("the bundle's ids are namespaced apart from stored ones: %v", err)
	}
}
