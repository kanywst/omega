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
	// A later start finds the directory owned by the target user but with
	// a different mode, and puts the mode back.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd = newPrepareSocketDirCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{"--dir", dir, "--uid", strconv.Itoa(os.Getuid()), "--gid", strconv.Itoa(os.Getgid())})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode not restored: %v", fi.Mode())
	}
	// A symlink at the path is refused rather than followed.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	cmd = newPrepareSocketDirCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{"--dir", link, "--uid", strconv.Itoa(os.Getuid()), "--gid", strconv.Itoa(os.Getgid())})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a symlink must be refused")
	}
	cmd = newPrepareSocketDirCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("--dir is required")
	}
}
