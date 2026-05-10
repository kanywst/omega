package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"strings"

	"github.com/spf13/cobra"

	"github.com/0-draft/omega/internal/server/api"
	"github.com/0-draft/omega/internal/server/audit"
	"github.com/0-draft/omega/internal/server/federation"
	"github.com/0-draft/omega/internal/server/identity"
	"github.com/0-draft/omega/internal/server/metrics"
	"github.com/0-draft/omega/internal/server/policy"
	"github.com/0-draft/omega/internal/server/storage"
	"github.com/0-draft/omega/internal/server/tracing"
	"github.com/0-draft/omega/internal/version"
)

func newServerCommand() *cobra.Command {
	var (
		dataDir                 string
		dbDSN                   string
		httpAddr                string
		trustDomain             string
		issuerURL               string
		policyDir               string
		otlpEndpoint            string
		otlpInsecure            bool
		federateWith            []string
		webhookURL              string
		webhookSecret           string
		auditBatch              int
		auditPoll               time.Duration
		haLeaderKey             int64
		haPollEvery             time.Duration
		enforceTokenExchangePol bool
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Omega control plane (Identity + Policy + Federation Hub)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.MkdirAll(dataDir, 0o750); err != nil {
				return fmt.Errorf("create data dir: %w", err)
			}
			storeSpec := strings.TrimSpace(dbDSN)
			if storeSpec == "" {
				storeSpec = filepath.Join(dataDir, "omega.db")
			}
			store, err := storage.Open(storeSpec)
			if err != nil {
				return err
			}
			defer store.Close()

			ca, err := identity.New(identity.Config{
				Kind:        identity.KindDisk,
				TrustDomain: trustDomain,
				Issuer:      strings.TrimSpace(issuerURL),
				Dir:         filepath.Join(dataDir, "ca"),
			})
			if err != nil {
				return fmt.Errorf("ca: %w", err)
			}

			pdp := policy.New()
			if policyDir != "" {
				if err := pdp.LoadDir(policyDir); err != nil {
					return fmt.Errorf("policy: %w", err)
				}
			}

			peers, err := parseFederatePeers(federateWith)
			if err != nil {
				return fmt.Errorf("federate-with: %w", err)
			}
			fed := federation.NewRegistry(ca.TrustDomain(), ca.BundlePEM(), peers, 30*time.Second)

			metrics.SetBuildInfo(version.Version)

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// Postgres-only: opt into advisory-lock leader election so
			// only one replica accepts writes. SQLite is single-writer
			// by definition and silently skips this.
			if isPostgresDSN(storeSpec) {
				if err := store.StartLeaderElection(ctx, storage.LeaderConfig{
					Key:          haLeaderKey,
					PollInterval: haPollEvery,
				}); err != nil {
					return fmt.Errorf("leader election: %w", err)
				}
				fmt.Fprintf(os.Stderr, "omega server: leader election enabled (postgres advisory lock)\n")
			}

			go fed.Run(ctx)

			if strings.TrimSpace(webhookURL) != "" {
				fwd, err := audit.NewWebhookForwarder(audit.WebhookConfig{
					URL:    webhookURL,
					Secret: webhookSecret,
				})
				if err != nil {
					return fmt.Errorf("audit webhook: %w", err)
				}
				pump := audit.NewPump(store, fwd, audit.PumpConfig{
					BatchSize:    auditBatch,
					PollInterval: auditPoll,
				})
				go pump.Run(ctx)
				fmt.Fprintf(os.Stderr, "omega server: audit forwarder=webhook url=%s\n", webhookURL)
			}

			shutdownTracing, err := tracing.Setup(ctx, tracing.Config{
				ServiceName:    "omega-server",
				ServiceVersion: version.Version,
				Endpoint:       otlpEndpoint,
				Insecure:       otlpInsecure,
			})
			if err != nil {
				return fmt.Errorf("tracing: %w", err)
			}
			defer func() {
				flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = shutdownTracing(flushCtx)
			}()

			srv := &http.Server{
				Addr: httpAddr,
				Handler: api.NewServer(store, ca, pdp).
					WithFederation(fed).
					WithEnforceTokenExchangePolicy(enforceTokenExchangePol).
					Handler(),
				ReadHeaderTimeout: 5 * time.Second,
			}

			errCh := make(chan error, 1)
			go func() {
				fmt.Fprintf(os.Stderr, "omega server: trust-domain=%s data-dir=%s listen=http://%s\n", ca.TrustDomain(), dataDir, httpAddr)
				if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
					return
				}
				errCh <- nil
			}()

			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdownCtx)
				return nil
			case err := <-errCh:
				return err
			}
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", ".omega", "directory for SQLite db, CA key, etc.")
	cmd.Flags().StringVar(&dbDSN, "db", "",
		"database DSN. Empty = SQLite at <data-dir>/omega.db. "+
			"Use 'postgres://user:pass@host:port/dbname?sslmode=disable' to run against Postgres.")
	cmd.Flags().StringVar(&httpAddr, "http-addr", "127.0.0.1:8080", "HTTP listen address (admin API + AuthZEN endpoint)")
	cmd.Flags().StringVar(&trustDomain, "trust-domain", "omega.local", "SPIFFE trust domain")
	cmd.Flags().StringVar(&issuerURL, "issuer-url", "",
		"public OIDC issuer URL (e.g. https://omega.example.com). When set, JWT-SVIDs carry this as the `iss` claim and /.well-known/openid-configuration returns a discovery document. Required for AWS IAM OIDC trust, GCP WIF, and K8s ServiceAccount issuer trust. Omit to keep SPIFFE-only behaviour.")
	cmd.Flags().StringVar(&policyDir, "policy-dir", "", "directory of *.cedar policy files (and optional entities.json) to load at startup")
	cmd.Flags().StringVar(&otlpEndpoint, "otlp-endpoint", "", "OTLP/HTTP traces endpoint, host:port (overrides OTEL_EXPORTER_OTLP_ENDPOINT). Empty disables tracing.")
	cmd.Flags().BoolVar(&otlpInsecure, "otlp-insecure", false, "send OTLP traces over plaintext HTTP (no TLS)")
	cmd.Flags().StringArrayVar(&federateWith, "federate-with", nil,
		"federate with a peer trust domain (repeatable). Format: 'name=<peer-trust-domain>,url=<http-base-url>'. "+
			"The server will fetch the peer's /v1/bundle and serve it from /v1/federation/bundles.")
	cmd.Flags().StringVar(&webhookURL, "audit-webhook-url", "",
		"POST audit events to this URL as JSON batches. Empty disables the webhook forwarder.")
	cmd.Flags().StringVar(&webhookSecret, "audit-webhook-secret", "",
		"shared secret used to sign webhook bodies with HMAC-SHA256 (header X-Omega-Signature: sha256=<hex>).")
	cmd.Flags().IntVar(&auditBatch, "audit-batch-size", 100,
		"max audit events per webhook batch.")
	cmd.Flags().DurationVar(&auditPoll, "audit-poll-interval", time.Second,
		"how often the audit pump polls the store for new events.")
	cmd.Flags().Int64Var(&haLeaderKey, "ha-leader-key", 0,
		"Postgres advisory-lock key for leader election. Only used when --db is a postgres DSN. "+
			"0 (default) uses Omega's reserved key; override if you run multiple Omega clusters on one Postgres.")
	cmd.Flags().DurationVar(&haPollEvery, "ha-poll-interval", time.Second,
		"how often a follower retries to acquire the advisory lock.")
	cmd.Flags().BoolVar(&enforceTokenExchangePol, "enforce-token-exchange-policy", false,
		"evaluate POST /v1/token/exchange through the loaded Cedar policy set "+
			"(action=token.exchange, default-deny). When false, only the built-in "+
			"impersonation guard is enforced.")

	return cmd
}

// isPostgresDSN duplicates storage.isPostgresDSN so the CLI can decide
// whether to start leader election without exporting it from storage.
func isPostgresDSN(spec string) bool {
	return strings.HasPrefix(spec, "postgres://") || strings.HasPrefix(spec, "postgresql://")
}

// parseFederatePeers parses --federate-with values like
// "name=omega.beta,url=http://127.0.0.1:18089" into PeerConfig entries.
func parseFederatePeers(specs []string) ([]federation.PeerConfig, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	out := make([]federation.PeerConfig, 0, len(specs))
	for _, s := range specs {
		var name, url string
		for _, kv := range strings.Split(s, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("invalid entry %q (expected key=value pairs)", s)
			}
			switch strings.TrimSpace(k) {
			case "name":
				name = strings.TrimSpace(v)
			case "url":
				url = strings.TrimSpace(v)
			default:
				return nil, fmt.Errorf("unknown key %q in %q (expected name= and url=)", k, s)
			}
		}
		if name == "" || url == "" {
			return nil, fmt.Errorf("entry %q is missing name or url", s)
		}
		out = append(out, federation.PeerConfig{TrustDomain: name, URL: url})
	}
	return out, nil
}
