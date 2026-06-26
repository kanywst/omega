package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kanywst/omega/internal/server/storage"
)

func newDomainCommand() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Manage Omega domains (hierarchical namespaces, e.g. media.news)",
	}
	cmd.PersistentFlags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")

	var description string
	create := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			body, err := json.Marshal(storage.Domain{Name: args[0], Description: description})
			if err != nil {
				return err
			}
			resp, err := http.Post(strings.TrimRight(serverURL, "/")+"/v1/domains", "application/json", bytes.NewReader(body))
			if err != nil {
				return fmt.Errorf("connect to %s: %w", serverURL, err)
			}
			defer resp.Body.Close()
			return printResponse(c.OutOrStdout(), resp)
		},
	}
	create.Flags().StringVar(&description, "description", "", "domain description")

	get := &cobra.Command{
		Use:   "get <name>",
		Short: "Get a domain by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return doGET(c.OutOrStdout(), strings.TrimRight(serverURL, "/")+"/v1/domains/"+args[0])
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List domains",
		RunE: func(c *cobra.Command, _ []string) error {
			return doGET(c.OutOrStdout(), strings.TrimRight(serverURL, "/")+"/v1/domains")
		},
	}

	cmd.AddCommand(create, get, list)
	return cmd
}

func doGET(w io.Writer, url string) error {
	// #nosec G107 -- url is built from operator-supplied --server flag, not untrusted input.
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()
	return printResponse(w, resp)
}

func printResponse(w io.Writer, resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, body, "", "  "); err != nil {
		_, _ = fmt.Fprintln(w, strings.TrimSpace(string(body)))
		return nil
	}
	_, err = fmt.Fprintln(w, indented.String())
	return err
}
