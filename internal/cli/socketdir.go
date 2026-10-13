package cli

import (
	"fmt"
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
			fi, err := os.Stat(dir)
			if err != nil {
				return err
			}
			// Already handed over on an earlier start: nothing to do. With
			// only CAP_CHOWN, root could not chmod it any more anyway.
			if owner, ok := fileOwner(fi); ok && owner == uid {
				return nil
			}
			// Mode first, while root still owns it.
			// #nosec G302 -- the Workload API directory must be traversable by
			// every workload; the socket inside carries its own permissions.
			if err := os.Chmod(dir, 0o755); err != nil {
				return err
			}
			if err := os.Chown(dir, uid, gid); err != nil {
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
