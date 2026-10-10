package cli

import (
	"strings"
	"testing"
)

func TestParseIDJAGIDPFlags(t *testing.T) {
	const iss = "https://omega.example.com"
	cfgs, err := parseIDJAGIDPFlags([]string{"name=corp,issuer=https://idp.example.com,template=spiffe://td/humans/{sub}"}, iss)
	if err != nil {
		t.Fatalf("valid flag: %v", err)
	}
	c := cfgs[0]
	if len(c.Audiences) != 1 || c.Audiences[0] != iss || c.RequiredTyp != "oauth-id-jag+jwt" || !c.ExactAudience {
		t.Errorf("config: %+v", c)
	}

	cases := []struct {
		name  string
		specs []string
		want  string
	}{
		{"unknown key", []string{"name=a,issuer=https://a,template=spiffe://td/{sub},audience=x"}, "unknown key"},
		{"not key=value", []string{"name=a,issuer"}, "key=value"},
		{"duplicate issuer", []string{
			"name=a,issuer=https://a,template=spiffe://td/{idp}/{sub}",
			"name=b,issuer=https://a,template=spiffe://td/{idp}/{sub}",
		}, "more than once"},
		{"two idps without {idp}", []string{
			"name=a,issuer=https://a,template=spiffe://td/{sub}",
			"name=b,issuer=https://b,template=spiffe://td/{idp}/{sub}",
		}, "{idp}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseIDJAGIDPFlags(tc.specs, iss)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}
