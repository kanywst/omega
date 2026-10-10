package cli

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newGroupCommand() *cobra.Command {
	var serverURL string
	cmd := &cobra.Command{
		Use:   "group",
		Short: "Manage groups owned by a domain (policy identity Group::\"<domain>:<name>\")",
	}
	cmd.PersistentFlags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")
	groupsURL := func(domain string) string {
		return strings.TrimRight(serverURL, "/") + "/v1/domains/" + domain + "/groups"
	}

	var description string
	create := &cobra.Command{
		Use:   "create <domain> <name>",
		Short: "Create a group in a domain",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			body, err := json.Marshal(map[string]string{"name": args[1], "description": description})
			if err != nil {
				return err
			}
			return doRequest(c.OutOrStdout(), http.MethodPost, groupsURL(args[0]), body)
		},
	}
	create.Flags().StringVar(&description, "description", "", "group description")

	get := &cobra.Command{
		Use:   "get <domain> <name>",
		Short: "Show a group and its members",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			return doGET(c.OutOrStdout(), groupsURL(args[0])+"/"+args[1])
		},
	}
	list := &cobra.Command{
		Use:   "list <domain>",
		Short: "List a domain's groups",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return doGET(c.OutOrStdout(), groupsURL(args[0]))
		},
	}
	del := &cobra.Command{
		Use:   "delete <domain> <name>",
		Short: "Delete a group and its memberships",
		Args:  cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			return doRequest(c.OutOrStdout(), http.MethodDelete, groupsURL(args[0])+"/"+args[1], nil)
		},
	}

	var expiresIn time.Duration
	members := &cobra.Command{Use: "members", Short: "Add or remove group members"}
	add := &cobra.Command{
		Use:   "add <domain> <group> <spiffe-id>",
		Short: "Add a member, optionally for a limited time",
		Args:  cobra.ExactArgs(3),
		RunE: func(c *cobra.Command, args []string) error {
			req := map[string]any{"principal": args[2]}
			if expiresIn > 0 {
				req["expires_at"] = time.Now().Add(expiresIn).UTC()
			}
			body, err := json.Marshal(req)
			if err != nil {
				return err
			}
			return doRequest(c.OutOrStdout(), http.MethodPut, groupsURL(args[0])+"/"+args[1]+"/members", body)
		},
	}
	add.Flags().DurationVar(&expiresIn, "expires-in", 0, "end the membership after this long (e.g. 8h); 0 means no expiry")
	remove := &cobra.Command{
		Use:   "remove <domain> <group> <spiffe-id>",
		Short: "Remove a member",
		Args:  cobra.ExactArgs(3),
		RunE: func(c *cobra.Command, args []string) error {
			u := groupsURL(args[0]) + "/" + args[1] + "/members?principal=" + url.QueryEscape(args[2])
			return doRequest(c.OutOrStdout(), http.MethodDelete, u, nil)
		},
	}
	members.AddCommand(add, remove)
	cmd.AddCommand(create, get, list, del, members)
	return cmd
}
