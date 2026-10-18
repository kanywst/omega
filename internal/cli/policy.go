package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// policyClient talks to the policy API. Writes need a --require-auth
// server, so it presents --client-cert over mTLS when one is set.
type policyClient struct {
	server, serverCA, cert, key string
}

func (p *policyClient) http() (*http.Client, error) {
	t, err := controlPlaneTransport(p.server, p.serverCA, p.cert, p.key)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: t}, nil
}

func (p *policyClient) url(id string) string {
	u := strings.TrimRight(p.server, "/") + "/v1/policies"
	if id != "" {
		u += "/" + url.PathEscape(id)
	}
	return u
}

// do sends one request and returns the response with its body read.
func (p *policyClient) do(method, target string, body any, header map[string]string) (*http.Response, []byte, error) {
	c, err := p.http()
	if err != nil {
		return nil, nil, err
	}
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, target, r)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", p.server, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	return resp, out, nil
}

// printBody writes a response body indented, or returns the server's error.
func printBody(w io.Writer, resp *http.Response, body []byte) error {
	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if len(body) == 0 {
		return nil
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, body, "", "  "); err != nil {
		_, err = fmt.Fprintln(w, strings.TrimSpace(string(body)))
		return err
	}
	_, err := fmt.Fprintln(w, indented.String())
	return err
}

func newPolicyCommand() *cobra.Command {
	pc := &policyClient{}
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Cedar policies stored in the control plane",
	}
	cmd.PersistentFlags().StringVar(&pc.server, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")
	cmd.PersistentFlags().StringVar(&pc.serverCA, "server-ca", "", "CA bundle (PEM) that verifies the control plane's certificate")
	cmd.PersistentFlags().StringVar(&pc.cert, "client-cert", "", "client certificate (PEM) with a SPIFFE ID, presented over mTLS; writes need a --domain-root-admin")
	cmd.PersistentFlags().StringVar(&pc.key, "client-key", "", "private key (PEM) of --client-cert")

	list := &cobra.Command{
		Use:   "list",
		Short: "List stored policies and the read-only --policy-dir files",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			resp, body, err := pc.do(http.MethodGet, pc.url(""), nil, nil)
			if err != nil {
				return err
			}
			return printBody(c.OutOrStdout(), resp, body)
		},
	}
	get := &cobra.Command{
		Use:   "get <id>",
		Short: "Show one policy with its Cedar text",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			resp, body, err := pc.do(http.MethodGet, pc.url(args[0]), nil, nil)
			if err != nil {
				return err
			}
			return printBody(c.OutOrStdout(), resp, body)
		},
	}

	var file, id string
	apply := &cobra.Command{
		Use:   "apply -f <file.cedar>",
		Short: "Create a stored policy from a Cedar file, or update it if it exists",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if file == "" {
				return errors.New("--file is required")
			}
			// #nosec G304 -- the path is the operator's own --file argument.
			text, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			if id == "" {
				id = strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
			}
			return applyPolicy(c.OutOrStdout(), pc, id, string(text))
		},
	}
	apply.Flags().StringVarP(&file, "file", "f", "", "path to a Cedar policy file")
	apply.Flags().StringVar(&id, "id", "", "policy id (default: the file name without its extension)")

	var (
		etag  string
		force bool
	)
	del := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a stored policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			// Deleting whatever version is stored could remove a forbid
			// someone else just tightened, so it has to be asked for.
			switch {
			case etag != "" && force:
				return errors.New("--if-match and --force contradict each other")
			case etag == "*":
				return errors.New("--if-match '*' deletes whatever version is stored; say so with --force")
			case force:
				etag = "*"
			case etag == "":
				return errors.New("pass --if-match with the ETag `omega policy get` printed, or --force to delete whatever version is stored")
			}
			resp, body, err := pc.do(http.MethodDelete, pc.url(args[0]), nil, map[string]string{"If-Match": etag})
			if err != nil {
				return err
			}
			return printBody(c.OutOrStdout(), resp, body)
		},
	}
	del.Flags().StringVar(&etag, "if-match", "", "delete only if the policy still has this ETag (from `omega policy get`)")
	del.Flags().BoolVar(&force, "force", false, "delete whatever version is stored (sends If-Match: *)")

	cmd.AddCommand(list, get, apply, del)
	return cmd
}

// applyPolicy creates the policy, or updates it conditionally on the
// ETag it read, so a concurrent change is reported rather than lost.
func applyPolicy(w io.Writer, pc *policyClient, id, text string) error {
	resp, body, err := pc.do(http.MethodGet, pc.url(id), nil, nil)
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		resp, body, err = pc.do(http.MethodPost, pc.url(""), map[string]string{"id": id, "text": text}, nil)
	case resp.StatusCode == http.StatusOK && resp.Header.Get("ETag") != "":
		resp, body, err = pc.do(http.MethodPut, pc.url(id), map[string]string{"text": text}, map[string]string{"If-Match": resp.Header.Get("ETag")})
	case resp.StatusCode == http.StatusOK:
		return fmt.Errorf("policy %q is a --policy-dir file and is read-only over the API", id)
	}
	if err != nil {
		return err
	}
	return printBody(w, resp, body)
}
