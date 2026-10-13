package cli

import (
	"path/filepath"
	"testing"

	"github.com/kanywst/omega/internal/server/identity"
)

func TestCACommands(t *testing.T) {
	data := t.TempDir()
	if _, err := identity.LoadOrCreate(filepath.Join(data, "ca"), "omega.local"); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) error {
		cmd := newCACommand()
		cmd.SilenceErrors, cmd.SilenceUsage = true, true
		cmd.SetArgs(append(args, "--data-dir", data))
		return cmd.Execute()
	}
	for _, step := range [][]string{{"status"}, {"prepare"}, {"activate"}, {"retire", "--force"}, {"status"}} {
		if err := run(step...); err != nil {
			t.Fatalf("%v: %v", step, err)
		}
	}
	if err := run("activate"); err == nil {
		t.Fatal("activate with nothing prepared must fail")
	}
	if err := run("retire"); err == nil {
		t.Fatal("retire with nothing to retire must fail")
	}
}
