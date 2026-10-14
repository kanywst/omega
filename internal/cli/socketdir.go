package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/cobra"
)

// newPrepareSocketDirCommand creates the agent's socket directory owned by
// the user the agent runs as. It is meant for a Kubernetes init container:
// kubelet creates a hostPath directory root-owned, and with only CAP_CHOWN
// this step lets the agent itself stay non-root.
func newPrepareSocketDirCommand() *cobra.Command {
	var (
		dir      string
		uid, gid int
	)
	cmd := &cobra.Command{
		Use:    "prepare-socket-dir",
		Short:  "Create the agent's socket directory owned by the agent's user (init container)",
		Hidden: true,
		RunE: func(*cobra.Command, []string) error {
			if dir == "" {
				return fmt.Errorf("--dir is required")
			}
			// #nosec G301 -- workloads in other users must reach the socket inside.
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			// Never follow a symlink planted at the path: chown and chmod
			// would land on whatever it points to.
			fi, err := os.Lstat(dir)
			if err != nil {
				return err
			}
			if !fi.IsDir() {
				return fmt.Errorf("%s is not a directory", dir)
			}
			// Already handed over on an earlier start: nothing to do.
			if owner, group, ok := fileOwner(fi); ok && owner == uid && group == gid && fi.Mode().Perm() == 0o755 {
				return nil
			}
			// #nosec G302 -- the Workload API directory must be traversable by
			// every workload; the socket inside carries its own permissions.
			if err := os.Chmod(dir, 0o755); err != nil {
				if !errors.Is(err, fs.ErrPermission) {
					return err
				}
				// Owned by another user and no CAP_FOWNER: with CAP_CHOWN,
				// take it back first so the mode can be fixed.
				if err := os.Lchown(dir, 0, 0); err != nil {
					return fmt.Errorf("chown %s: %w", dir, err)
				}
				// #nosec G302 -- as above.
				if err := os.Chmod(dir, 0o755); err != nil {
					return err
				}
			}
			if err := os.Lchown(dir, uid, gid); err != nil {
				return fmt.Errorf("chown %s: %w", dir, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "directory to create")
	cmd.Flags().IntVar(&uid, "uid", 65532, "owner uid")
	cmd.Flags().IntVar(&gid, "gid", 65532, "owner gid")
	return cmd
}
