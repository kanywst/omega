package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPrepareSocketDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run", "omega")
	cmd := newPrepareSocketDirCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{"--dir", dir, "--uid", strconv.Itoa(os.Getuid()), "--gid", strconv.Itoa(os.Getgid())})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
		t.Fatalf("dir: %v %v", fi, err)
	}
	// A later start finds the directory already owned by the target
	// user and leaves it alone (root with only CAP_CHOWN could not chmod it).
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd = newPrepareSocketDirCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{"--dir", dir, "--uid", strconv.Itoa(os.Getuid()), "--gid", strconv.Itoa(os.Getgid())})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatal("an already handed-over directory must not be touched")
	}
	cmd = newPrepareSocketDirCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("--dir is required")
	}
}
