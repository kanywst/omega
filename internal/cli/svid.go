package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/kanywst/omega/internal/server/api"
)

func newSVIDCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "svid",
		Short: "Interact with SPIFFE SVIDs",
	}

	var (
		socket   string
		fetchOut string
	)
	fetch := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch an X.509-SVID via the local agent (SPIFFE Workload API)",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
			defer cancel()
			src, err := workloadapi.NewX509Source(ctx,
				workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socket)),
			)
			if err != nil {
				return fmt.Errorf("connect to %s: %w", socket, err)
			}
			defer src.Close()

			svid, err := src.GetX509SVID()
			if err != nil {
				return fmt.Errorf("get svid: %w", err)
			}
			bundle, err := src.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
			if err != nil {
				return fmt.Errorf("get bundle: %w", err)
			}

			svidPEM, keyPEM, err := svid.Marshal()
			if err != nil {
				return fmt.Errorf("marshal svid: %w", err)
			}
			bundlePEM, err := bundle.Marshal()
			if err != nil {
				return fmt.Errorf("marshal bundle: %w", err)
			}
			notAfter := svid.Certificates[0].NotAfter

			if fetchOut == "" {
				_, _ = fmt.Fprintf(c.OutOrStdout(), "# spiffe-id: %s\n", svid.ID)
				_, _ = fmt.Fprintf(c.OutOrStdout(), "# not-after: %s\n", notAfter.Format(time.RFC3339))
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# svid")
				_, _ = c.OutOrStdout().Write(svidPEM)
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# bundle")
				_, _ = c.OutOrStdout().Write(bundlePEM)
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# private key")
				_, _ = c.OutOrStdout().Write(keyPEM)
				return nil
			}

			if err := os.MkdirAll(fetchOut, 0o700); err != nil {
				return err
			}
			files := []struct {
				name string
				data []byte
				mode os.FileMode
			}{
				{"svid.pem", svidPEM, 0o644},
				{"bundle.pem", bundlePEM, 0o644},
				{"key.pem", keyPEM, 0o600},
			}
			for _, f := range files {
				if err := os.WriteFile(filepath.Join(fetchOut, f.name), f.data, f.mode); err != nil {
					return fmt.Errorf("write %s: %w", f.name, err)
				}
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "wrote %s/{svid,bundle,key}.pem (spiffe-id=%s, not-after=%s)\n",
				fetchOut, svid.ID, notAfter.Format(time.RFC3339))
			return nil
		},
	}
	fetch.Flags().StringVar(&socket, "socket", "/tmp/omega-agent.sock", "Workload API unix socket")
	fetch.Flags().StringVar(&fetchOut, "out-dir", "", "directory to write svid.pem / bundle.pem / key.pem (default: stdout)")

	var (
		serverURL string
		spiffeID  string
		outDir    string
	)
	issue := &cobra.Command{
		Use:   "issue",
		Short: "Generate a fresh ECDSA key + CSR locally and ask the control plane for an X.509-SVID",
		RunE: func(c *cobra.Command, _ []string) error {
			if spiffeID == "" {
				return fmt.Errorf("--spiffe-id is required")
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return fmt.Errorf("gen key: %w", err)
			}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				return fmt.Errorf("create csr: %w", err)
			}
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

			reqBody, err := json.Marshal(api.IssueSVIDRequest{SPIFFEID: spiffeID, CSR: string(csrPEM)})
			if err != nil {
				return err
			}
			resp, err := http.Post(strings.TrimRight(serverURL, "/")+"/v1/svid", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				return fmt.Errorf("connect to %s: %w", serverURL, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			var out api.IssueSVIDResponse
			if err := json.Unmarshal(body, &out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}

			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return err
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

			if outDir == "" {
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# SVID")
				_, _ = c.OutOrStdout().Write([]byte(out.SVID))
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# bundle")
				_, _ = c.OutOrStdout().Write([]byte(out.Bundle))
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# private key")
				_, _ = c.OutOrStdout().Write(keyPEM)
				_, _ = fmt.Fprintf(c.OutOrStdout(), "# expires_at: %s\n", out.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
				return nil
			}

			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return err
			}
			files := map[string][]byte{
				"svid.pem":   []byte(out.SVID),
				"bundle.pem": []byte(out.Bundle),
				"key.pem":    keyPEM,
			}
			for name, data := range files {
				path := filepath.Join(outDir, name)
				mode := os.FileMode(0o644)
				if name == "key.pem" {
					mode = 0o600
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					return fmt.Errorf("write %s: %w", path, err)
				}
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "wrote %s/{svid,bundle,key}.pem (expires_at=%s)\n", outDir, out.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
			return nil
		},
	}
	issue.Flags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")
	issue.Flags().StringVar(&spiffeID, "spiffe-id", "", "SPIFFE ID to issue (e.g. spiffe://omega.local/example/web)")
	issue.Flags().StringVar(&outDir, "out-dir", "", "directory to write svid.pem / bundle.pem / key.pem (default: stdout)")

	var (
		jwtSocket   string
		jwtAudience []string
	)
	jwtFetch := &cobra.Command{
		Use:   "jwt-fetch",
		Short: "Fetch a JWT-SVID via the local agent (SPIFFE Workload API)",
		RunE: func(c *cobra.Command, _ []string) error {
			if len(jwtAudience) == 0 {
				return fmt.Errorf("--audience is required (one or more)")
			}
			ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
			defer cancel()
			client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+jwtSocket))
			if err != nil {
				return fmt.Errorf("connect to %s: %w", jwtSocket, err)
			}
			defer client.Close()

			svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: jwtAudience[0], ExtraAudiences: jwtAudience[1:]})
			if err != nil {
				return fmt.Errorf("fetch jwt: %w", err)
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "# spiffe-id: %s\n", svid.ID)
			_, _ = fmt.Fprintf(c.OutOrStdout(), "# audience:  %s\n", strings.Join(svid.Audience, ","))
			_, _ = fmt.Fprintf(c.OutOrStdout(), "# expires:   %s\n", svid.Expiry.Format(time.RFC3339))
			_, _ = fmt.Fprintln(c.OutOrStdout(), svid.Marshal())
			return nil
		},
	}
	jwtFetch.Flags().StringVar(&jwtSocket, "socket", "/tmp/omega-agent.sock", "Workload API unix socket")
	jwtFetch.Flags().StringSliceVar(&jwtAudience, "audience", nil, "audience(s) the JWT-SVID is bound to (repeatable)")

	var (
		validateSocket   string
		validateAudience string
		validateAsJSON   bool
	)
	validate := &cobra.Command{
		Use:   "validate <jwt>",
		Short: "Validate a JWT-SVID via the local agent (SPIFFE Workload API ValidateJWTSVID)",
		Long: `Validate a JWT-SVID via the local agent.

The token is read from the positional argument; "-" reads from stdin
so the caller can pipe in a token without putting it on the
command line.

On success the SPIFFE ID, audience(s), expiry, and claims are
printed. --json switches to a single-line JSON object suitable for
piping into jq.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if strings.TrimSpace(validateAudience) == "" {
				return fmt.Errorf("--audience is required")
			}
			token := args[0]
			if token == "-" {
				// 1 MiB is two orders of magnitude above the largest
				// realistic JWT-SVID; bounds memory if something
				// unexpected ends up on stdin.
				raw, err := io.ReadAll(io.LimitReader(c.InOrStdin(), 1<<20))
				if err != nil {
					return fmt.Errorf("read token from stdin: %w", err)
				}
				token = strings.TrimSpace(string(raw))
			}
			if token == "" {
				return fmt.Errorf("token is empty")
			}
			ctx, cancel := context.WithTimeout(c.Context(), 30*time.Second)
			defer cancel()
			client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+validateSocket))
			if err != nil {
				return fmt.Errorf("connect to %s: %w", validateSocket, err)
			}
			defer client.Close()
			svid, err := client.ValidateJWTSVID(ctx, token, validateAudience)
			if err != nil {
				return fmt.Errorf("validate: %w", err)
			}
			out := c.OutOrStdout()
			if validateAsJSON {
				return json.NewEncoder(out).Encode(map[string]any{
					"valid":     true,
					"spiffe_id": svid.ID.String(),
					"audience":  svid.Audience,
					"expires":   svid.Expiry.Format(time.RFC3339),
					"claims":    svid.Claims,
				})
			}
			_, _ = fmt.Fprintf(out, "valid:    true\n")
			_, _ = fmt.Fprintf(out, "spiffe-id: %s\n", svid.ID)
			_, _ = fmt.Fprintf(out, "audience:  %s\n", strings.Join(svid.Audience, ","))
			_, _ = fmt.Fprintf(out, "expires:   %s\n", svid.Expiry.Format(time.RFC3339))
			// Claims are ordered for stable diffability; only show the
			// ones operators usually care about and drop standard time
			// claims already printed above.
			interestingClaims := []string{"iss", "act", "scope", "cnf", "preferred_username", "email", "name"}
			for _, k := range interestingClaims {
				if v, ok := svid.Claims[k]; ok {
					b, _ := json.Marshal(v)
					_, _ = fmt.Fprintf(out, "claim.%s: %s\n", k, string(b))
				}
			}
			return nil
		},
	}
	validate.Flags().StringVar(&validateSocket, "socket", "/tmp/omega-agent.sock", "Workload API unix socket")
	validate.Flags().StringVar(&validateAudience, "audience", "", "audience to validate the JWT-SVID against (required)")
	validate.Flags().BoolVar(&validateAsJSON, "json", false, "emit a single-line JSON object instead of human-readable lines")

	cmd.AddCommand(fetch, issue, jwtFetch, validate)
	return cmd
}
