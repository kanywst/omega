package cli

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

func runCmd(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestDomainAndGroupCommands(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca, policy.New()).Handler())
	t.Cleanup(srv.Close)
	server := "--server=" + srv.URL
	alice := "spiffe://omega.local/people/alice"

	steps := []struct {
		cmd      func() *cobra.Command
		args     []string
		wantErr  bool
		contains string
	}{
		{newDomainCommand, []string{"create", "media", "--admin", alice, server}, false, `"name": "media"`},
		{newDomainCommand, []string{"create", "media.news", server}, false, `"parent": "media"`},
		{newDomainCommand, []string{"create", "ghost.town", server}, true, "parent domain does not exist"},
		{newDomainCommand, []string{"get", "media", server}, false, alice},
		{newDomainCommand, []string{"list", server}, false, "media.news"},
		{newDomainCommand, []string{"admins", "add", "media", "spiffe://omega.local/people/bob", server}, false, "people/bob"},
		{newDomainCommand, []string{"admins", "remove", "media", "spiffe://omega.local/people/bob", server}, false, alice},
		{newGroupCommand, []string{"create", "media", "oncall", "--description", "rotation", server}, false, `"name": "oncall"`},
		{newGroupCommand, []string{"members", "add", "media", "oncall", alice, "--expires-in", "1h", server}, false, "expires_at"},
		{newGroupCommand, []string{"get", "media", "oncall", server}, false, alice},
		{newGroupCommand, []string{"list", "media", server}, false, "oncall"},
		{newGroupCommand, []string{"members", "remove", "media", "oncall", alice, server}, false, `"name": "oncall"`},
		{newGroupCommand, []string{"delete", "media", "oncall", server}, false, ""},
		{newDomainCommand, []string{"delete", "media.news", server}, false, ""},
	}
	for _, st := range steps {
		out, err := runCmd(t, st.cmd(), st.args...)
		if st.wantErr {
			if err == nil || !strings.Contains(err.Error(), st.contains) {
				t.Errorf("%v: want an error containing %q, got %v (%s)", st.args, st.contains, err, out)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: %v (%s)", st.args, err, out)
			continue
		}
		if !strings.Contains(out, st.contains) {
			t.Errorf("%v: output %q does not contain %q", st.args, out, st.contains)
		}
	}
}
