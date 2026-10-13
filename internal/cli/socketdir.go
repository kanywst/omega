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
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			// Mode first, while root still owns it: with only CAP_CHOWN,
			// root cannot chmod a directory it no longer owns.
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
