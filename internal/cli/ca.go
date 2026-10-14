package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kanywst/omega/internal/server/identity"
)

// newCACommand rotates the built-in (disk) CA. Each step edits the CA
// directory; send the server SIGHUP afterwards to make it take effect.
func newCACommand() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Rotate the built-in CA (prepare, activate, retire), then SIGHUP the server",
		Long: `Rotate the built-in disk CA without a restart.

  omega ca prepare   generate the next CA; after SIGHUP it is trusted but does not sign
  omega ca activate  the next CA signs; the old one stays trusted as the previous CA
  omega ca retire    stop trusting the previous CA, once what it signed has expired
  omega ca status    show the active, next and previous CAs

Wait between steps long enough for every workload and peer to fetch the
new trust bundle, at least one SVID lifetime. Every replica reads its own
CA directory: apply each step on all of them, then SIGHUP them all.`,
	}
	cmd.PersistentFlags().StringVar(&dataDir, "data-dir", "./data", "the server's --data-dir; the CA lives in its ca/ subdirectory")
	caDir := func() string { return filepath.Join(dataDir, "ca") }
	printJSON := func(v any) error {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}
	var force bool
	retire := &cobra.Command{
		Use:   "retire",
		Short: "Stop trusting the previous CA",
		RunE: func(*cobra.Command, []string) error {
			if err := identity.RetireCA(caDir(), force); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "previous CA retired; send the server SIGHUP")
			return nil
		},
	}
	retire.Flags().BoolVar(&force, "force", false, "retire before tokens the previous CA signed can have expired")
	cmd.AddCommand(
		&cobra.Command{
			Use:   "status",
			Short: "Show the active, next and previous CAs",
			RunE: func(*cobra.Command, []string) error {
				st, err := identity.ReadCAStatus(caDir())
				if err != nil {
					return err
				}
				return printJSON(st)
			},
		},
		&cobra.Command{
			Use:   "prepare",
			Short: "Generate the next CA",
			RunE: func(*cobra.Command, []string) error {
				info, err := identity.PrepareCA(caDir())
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "next CA prepared; send the server SIGHUP, then wait for peers to trust it before activating")
				return printJSON(info)
			},
		},
		&cobra.Command{
			Use:   "activate",
			Short: "Make the next CA the active one",
			RunE: func(*cobra.Command, []string) error {
				info, err := identity.ActivateCA(caDir())
				if err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "next CA activated; send the server SIGHUP")
				return printJSON(info)
			},
		},
		retire,
	)
	return cmd
}
