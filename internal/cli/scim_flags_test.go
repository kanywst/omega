package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSCIMIDPFlags(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "tok")
	if err := os.WriteFile(tok, []byte(strings.Repeat("t", 40)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgs, err := parseSCIMIDPFlags([]string{"name=corp,domain=people,token-file=" + tok}, "omega.local")
	if err != nil || len(cfgs) != 1 || cfgs[0].Template != "spiffe://omega.local/humans/{idp}/{externalId}" {
		t.Fatalf("defaults: %+v %v", cfgs, err)
	}
	for name, specs := range map[string][]string{
		"no token file":      {"name=corp,domain=people"},
		"short token":        {"name=corp,domain=people,token-file=" + short},
		"missing file":       {"name=corp,domain=people,token-file=" + filepath.Join(dir, "nope")},
		"bad name":           {"name=Corp,domain=people,token-file=" + tok},
		"bad domain":         {"name=corp,domain=People,token-file=" + tok},
		"unknown key":        {"name=corp,domain=people,token-file=" + tok + ",x=y"},
		"not key=value":      {"corp"},
		"constant template":  {"name=corp,domain=people,token-file=" + tok + ",template=spiffe://omega.local/everyone"},
		"duplicate":          {"name=corp,domain=people,token-file=" + tok, "name=corp,domain=people,token-file=" + tok},
		"other trust domain": {"name=corp,domain=people,token-file=" + tok + ",template=spiffe://evil.example/h/{externalId}"},
		"placeholder first":  {"name=corp,domain=people,token-file=" + tok + ",template=spiffe://omega.local/{userName}"},
		"idp after user":     {"name=corp,domain=people,token-file=" + tok + ",template=spiffe://omega.local/h/{externalId}/{idp}"},
		"two without {idp}":  {"name=a,domain=people,token-file=" + tok + ",template=spiffe://omega.local/h/{externalId}", "name=b,domain=people,token-file=" + tok},
	} {
		if _, err := parseSCIMIDPFlags(specs, "omega.local"); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
