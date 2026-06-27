package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/attest"
	"github.com/kanywst/omega/internal/server/audit"
	"github.com/kanywst/omega/internal/server/federation"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/metrics"
	oidcpkg "github.com/kanywst/omega/internal/server/oidc"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
	"github.com/kanywst/omega/internal/server/tracing"
	"github.com/kanywst/omega/internal/version"
)

// buildK8sClient resolves a kube-apiserver client for --k8s-attest.
// Resolution order:
//   - explicit --kubeconfig path
//   - in-cluster ServiceAccount config (when running as a Pod)
//   - default kubeconfig discovery (KUBECONFIG env, ~/.kube/config)
//
// Any of those is acceptable for an operator; failing all three
// returns an error so misconfiguration surfaces at startup rather
// than at the first attest call.
func buildK8sClient(kubeconfig string) (kubernetes.Interface, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfig, err)
		}
		return kubernetes.NewForConfig(cfg)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return kubernetes.NewForConfig(cfg)
	}
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("no kubeconfig and no in-cluster config: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

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
		spiffeBundleRefreshHint time.Duration
		k8sAttestEnable         bool
		k8sSVIDTemplate         string
		k8sTokenAudiences       []string
		k8sKubeconfig           string
		auditOTLPEndpoint       string
		auditOTLPInsecure       bool
		auditOTLPHeaders        []string
		oidcIdPs                []string
		caBackend               string
		caVaultPKIAddr          string
		caVaultPKIToken         string
		caVaultPKITokenFile     string
		caVaultPKIMount         string
		caVaultPKIRole          string
		caVaultPKICACertFile    string
		caStepCAURL             string
		caStepCAProvisioner     string
		caStepCAKeyFile         string
		caStepCACACertFile      string
		tlsCertFile             string
		tlsKeyFile              string
		clientCAFile            string
		requireAuth             bool
		auditHMACKeyFile        string
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

			// H1: key the audit hash chain with HMAC so a DB-only
			// attacker cannot forge or truncate it. Opt-in: without the
			// flag the chain stays unkeyed (legacy SHA-256) so existing
			// deployments and CI examples are unaffected.
			var auditKeyring *storage.AuditKeyring
			if strings.TrimSpace(auditHMACKeyFile) != "" {
				auditKeyring, err = storage.LoadAuditKeyring(strings.TrimSpace(auditHMACKeyFile))
				if err != nil {
					return fmt.Errorf("audit-hmac-key-file: %w", err)
				}
				store.UseAuditKeyring(auditKeyring)
				fmt.Fprintf(os.Stderr, "omega server: audit chain keyed with HMAC-SHA-256 (keyring=%s)\n", auditHMACKeyFile)
			} else {
				fmt.Fprintf(os.Stderr, "omega server: WARN audit chain is UNKEYED (SHA-256); set --audit-hmac-key-file to make it tamper-resistant (H1)\n")
			}

			caCfg := identity.Config{
				Kind:        identity.Kind(strings.TrimSpace(caBackend)),
				TrustDomain: trustDomain,
				Issuer:      strings.TrimSpace(issuerURL),
				Dir:         filepath.Join(dataDir, "ca"),
			}
			if caCfg.Kind == identity.KindVaultPKI {
				token, err := resolveVaultToken(caVaultPKIToken, caVaultPKITokenFile)
				if err != nil {
					return fmt.Errorf("ca-vault-pki-token: %w", err)
				}
				caCfg.VaultPKIAddr = strings.TrimSpace(caVaultPKIAddr)
				caCfg.VaultPKIToken = token
				caCfg.VaultPKIMount = strings.TrimSpace(caVaultPKIMount)
				caCfg.VaultPKIRole = strings.TrimSpace(caVaultPKIRole)
				caCfg.VaultPKICACertFile = strings.TrimSpace(caVaultPKICACertFile)
			}
			if caCfg.Kind == identity.KindStepCA {
				if caStepCAKeyFile == "" {
					return errors.New("--ca-step-ca-provisioner-key-file is required when --ca-backend=step-ca")
				}
				// #nosec G304 -- caStepCAKeyFile is operator-supplied via --ca-step-ca-provisioner-key-file, not user input.
				keyPEM, err := os.ReadFile(caStepCAKeyFile)
				if err != nil {
					return fmt.Errorf("ca-step-ca-provisioner-key-file: %w", err)
				}
				caCfg.StepCAURL = strings.TrimSpace(caStepCAURL)
				caCfg.StepCAProvisionerName = strings.TrimSpace(caStepCAProvisioner)
				caCfg.StepCAProvisionerKeyPEM = keyPEM
				caCfg.StepCACACertFile = strings.TrimSpace(caStepCACACertFile)
			}
			ca, err := identity.New(caCfg)
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

			// SIGHUP re-reads the keyring so an operator can rotate keys
			// (append a new active key, demote the old to retired)
			// without restarting. Reload is atomic and refuses to drop
			// the previously-active key.
			if auditKeyring != nil {
				hup := make(chan os.Signal, 1)
				signal.Notify(hup, syscall.SIGHUP)
				go func() {
					defer signal.Stop(hup)
					for {
						select {
						case <-ctx.Done():
							return
						case <-hup:
							if err := auditKeyring.Reload(); err != nil {
								fmt.Fprintf(os.Stderr, "omega server: audit keyring reload failed: %v\n", err)
							} else {
								fmt.Fprintf(os.Stderr, "omega server: audit keyring reloaded\n")
							}
						}
					}
				}()
			}

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

			if strings.TrimSpace(auditOTLPEndpoint) != "" {
				headers, err := parseHeaderFlags(auditOTLPHeaders)
				if err != nil {
					return fmt.Errorf("audit otlp: %w", err)
				}
				fwd, err := audit.NewOTLPForwarder(audit.OTLPConfig{
					Endpoint:    auditOTLPEndpoint,
					Insecure:    auditOTLPInsecure,
					Headers:     headers,
					ServiceName: "omega-server",
				})
				if err != nil {
					return fmt.Errorf("audit otlp: %w", err)
				}
				pump := audit.NewPump(store, fwd, audit.PumpConfig{
					BatchSize:    auditBatch,
					PollInterval: auditPoll,
				})
				go pump.Run(ctx)
				fmt.Fprintf(os.Stderr, "omega server: audit forwarder=otlp endpoint=%s\n", auditOTLPEndpoint)
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

			apiServer := api.NewServer(store, ca, pdp).
				WithFederation(fed).
				WithEnforceTokenExchangePolicy(enforceTokenExchangePol).
				WithSPIFFEBundleRefreshHint(spiffeBundleRefreshHint).
				WithRequireAuth(requireAuth)

			if len(oidcIdPs) > 0 {
				cfgs, err := parseOIDCIdPFlags(oidcIdPs)
				if err != nil {
					return fmt.Errorf("oidc-idp: %w", err)
				}
				reg, err := oidcpkg.NewRegistry(cfgs)
				if err != nil {
					return fmt.Errorf("oidc-idp: %w", err)
				}
				apiServer = apiServer.WithOIDCRegistry(reg)
				names := reg.Names()
				fmt.Fprintf(os.Stderr, "omega server: oidc idps configured (%d): %s\n", len(names), strings.Join(names, ", "))
			}

			if k8sAttestEnable {
				// An empty audience disables TokenReview's audience check,
				// which lets any pod's default ServiceAccount token be
				// replayed against omega. Require an explicit audience so
				// the misconfiguration fails fast at startup.
				if !hasNonEmpty(k8sTokenAudiences) {
					return errors.New("k8s-attest: --k8s-token-audience is required when --k8s-attest=true (set it to the URL workloads use to reach omega so replayed default SA tokens are rejected)")
				}
				k8sClient, err := buildK8sClient(k8sKubeconfig)
				if err != nil {
					return fmt.Errorf("k8s-attest: %w", err)
				}
				attestor := attest.NewK8sAttestor(k8sClient, k8sTokenAudiences)
				apiServer = apiServer.WithK8sAttestor(attestor, k8sSVIDTemplate)
				fmt.Fprintf(os.Stderr, "omega server: k8s attestor enabled (template=%s, audiences=%v)\n",
					k8sSVIDTemplate, k8sTokenAudiences)
			}

			tlsConf, err := buildServerTLS(tlsCertFile, tlsKeyFile, clientCAFile)
			if err != nil {
				return err
			}
			if requireAuth && clientCAFile == "" {
				return errors.New("--require-auth needs --client-ca: caller authentication verifies client SVIDs against a CA bundle (mTLS); set --client-ca (and --tls-cert/--tls-key) or leave --require-auth off")
			}
			if requireAuth {
				fmt.Fprintf(os.Stderr, "omega server: require-auth=true (mTLS-authenticated callers; cross-identity SVID issuance denied)\n")
			} else {
				fmt.Fprintf(os.Stderr, "omega server: WARNING require-auth=false: POST /v1/svid trusts the caller-asserted spiffe_id, so any client that reaches the listener can mint an SVID for any identity (open CA). Set --require-auth=true with mTLS to close this (see docs/design/control-plane-trust-model.md C1).\n")
			}

			srv := &http.Server{
				Addr:              httpAddr,
				Handler:           apiServer.Handler(),
				ReadHeaderTimeout: 5 * time.Second,
				TLSConfig:         tlsConf,
			}

			errCh := make(chan error, 1)
			go func() {
				scheme := "http"
				if tlsConf != nil {
					scheme = "https"
				}
				fmt.Fprintf(os.Stderr, "omega server: trust-domain=%s data-dir=%s listen=%s://%s\n", ca.TrustDomain(), dataDir, scheme, httpAddr)
				// Cert/key are already loaded into TLSConfig.Certificates, so
				// ListenAndServeTLS takes empty path arguments.
				serve := srv.ListenAndServe
				if tlsConf != nil {
					serve = func() error { return srv.ListenAndServeTLS("", "") }
				}
				if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	cmd.Flags().StringVar(&caBackend, "ca-backend", "disk",
		"CA backend Kind. 'disk' (default) generates a self-signed root under --data-dir. 'vault-pki' delegates X.509-SVID signing to a Vault PKI engine; 'step-ca' delegates to Smallstep step-ca's /1.0/sign endpoint with a JWK provisioner OTT. For all non-disk backends the root key never sits on omega's disk while JWT-SVID signing stays local (see ADR 0005).")
	cmd.Flags().StringVar(&caVaultPKIAddr, "ca-vault-pki-addr", "",
		"Vault address, e.g. https://vault.example:8200. Required when --ca-backend=vault-pki.")
	cmd.Flags().StringVar(&caVaultPKIToken, "ca-vault-pki-token", "",
		"Vault token sent as X-Vault-Token. Visible to other users via `ps`; production deployments should prefer --ca-vault-pki-token-file or the OMEGA_VAULT_PKI_TOKEN env var. Required when --ca-backend=vault-pki unless one of those is set.")
	cmd.Flags().StringVar(&caVaultPKITokenFile, "ca-vault-pki-token-file", "",
		"path to a file whose first line is the Vault token. Preferred over the literal --ca-vault-pki-token flag because the secret never touches argv.")
	cmd.Flags().StringVar(&caVaultPKICACertFile, "ca-vault-pki-ca-cert", "",
		"path to a PEM file with the Vault server's TLS trust anchor(s). Empty falls back to the system trust store; production Vault is almost always behind a private CA and must set this.")
	cmd.Flags().StringVar(&caVaultPKIMount, "ca-vault-pki-mount", "pki",
		"Vault PKI engine mount path. Default 'pki' matches the canonical mount name.")
	cmd.Flags().StringVar(&caVaultPKIRole, "ca-vault-pki-role", "",
		"Vault PKI role used to sign incoming CSRs. Required when --ca-backend=vault-pki.")
	cmd.Flags().StringVar(&caStepCAURL, "ca-step-ca-url", "",
		"step-ca base URL, e.g. https://ca.example:9000. Required when --ca-backend=step-ca.")
	cmd.Flags().StringVar(&caStepCAProvisioner, "ca-step-ca-provisioner", "",
		"name of the JWK provisioner configured in step-ca's ca.json. Required when --ca-backend=step-ca.")
	cmd.Flags().StringVar(&caStepCAKeyFile, "ca-step-ca-provisioner-key-file", "",
		"path to the PEM- or JSON-encoded private JWK that signs the one-time-token presented to step-ca on each /1.0/sign call. Required when --ca-backend=step-ca.")
	cmd.Flags().StringVar(&caStepCACACertFile, "ca-step-ca-ca-cert", "",
		"path to a PEM file with the step-ca server's TLS trust anchor(s). Empty falls back to the system trust store; production step-ca is almost always behind a private CA and must set this.")

	cmd.Flags().StringArrayVar(&oidcIdPs, "oidc-idp", nil,
		"register an upstream OIDC IdP (repeatable). Format: 'name=corp,issuer=https://keycloak/realms/x,audience=omega-clients,template=spiffe://<td>/humans/{idp}/{preferred_username}'. The audience= key is required and takes one or more values separated by ';'; it is the set of `aud` values an incoming ID token must match, so tokens minted for other relying parties at the same issuer are rejected. Workloads call POST /v1/oidc/exchange with {idp, id_token, audience} to swap an external ID token for an omega JWT-SVID under the rendered SPIFFE ID.")

	cmd.Flags().BoolVar(&k8sAttestEnable, "k8s-attest", false,
		"enable the POST /v1/attest/k8s endpoint: workloads present a ServiceAccount projected token + CSR, omega validates the token via TokenReview, and issues an X.509-SVID derived from the (namespace, serviceaccount[, podname]) triple.")
	cmd.Flags().StringVar(&k8sSVIDTemplate, "k8s-svid-template",
		"spiffe://omega.local/k8s/{namespace}/{serviceaccount}",
		"SPIFFE ID template for k8s-attested SVIDs. Placeholders: {namespace}, {serviceaccount}, {podname}. The rendered ID must lie in --trust-domain.")
	cmd.Flags().StringSliceVar(&k8sTokenAudiences, "k8s-token-audience", nil,
		"expected audience(s) on the projected token (repeat to allow more than one). Required when --k8s-attest=true: set to the URL workloads use to reach omega (e.g. https://omega.example.com) so a replayed default ServiceAccount token, which carries no such audience, is rejected.")
	cmd.Flags().StringVar(&k8sKubeconfig, "kubeconfig", "",
		"path to a kubeconfig for out-of-cluster runs (used by --k8s-attest). Empty = use the in-cluster ServiceAccount config, falling back to the default kubeconfig discovery if that fails.")

	cmd.Flags().StringVar(&auditOTLPEndpoint, "audit-otlp-endpoint", "",
		"OTLP/HTTP-protobuf logs endpoint (e.g. otel-collector:4318 or https://otel.example.com). Empty disables OTLP audit forwarding. /v1/logs is appended automatically.")
	cmd.Flags().BoolVar(&auditOTLPInsecure, "audit-otlp-insecure", false,
		"use the http scheme when --audit-otlp-endpoint omits one. Ignored when the endpoint already specifies http:// or https://.")
	cmd.Flags().StringArrayVar(&auditOTLPHeaders, "audit-otlp-header", nil,
		"extra HTTP header on each OTLP export, format 'Key: value'. Repeatable; use to inject auth tokens (e.g. 'Authorization: Bearer ...').")

	cmd.Flags().StringVar(&auditHMACKeyFile, "audit-hmac-key-file", "",
		"path to a JSON keyring that MACs the audit hash chain with HMAC-SHA-256 (H1). "+
			"Shape: {\"active_key_id\":\"<id>\",\"keys\":[{\"id\":\"<id>\",\"secret\":\"<base64 >=16 bytes>\"}, ...]}. "+
			"The active key signs new rows; retired keys stay listed so old rows remain verifiable. "+
			"Each row records its key_id. Empty (default) keeps the legacy unkeyed chain for backward "+
			"compatibility. Keep this file outside --data-dir and out of DB backups; SIGHUP reloads it for rotation.")

	cmd.Flags().BoolVar(&enforceTokenExchangePol, "enforce-token-exchange-policy", false,
		"evaluate POST /v1/token/exchange through the loaded Cedar policy set "+
			"(action=token.exchange, default-deny). When false, only the built-in "+
			"impersonation guard is enforced.")

	cmd.Flags().DurationVar(&spiffeBundleRefreshHint, "spiffe-bundle-refresh-hint", 5*time.Minute,
		"value advertised as `spiffe_refresh_hint` in the SPIFFE Trust Domain Format "+
			"document served at GET /v1/spiffe-bundle. The recommended minimum "+
			"interval between peer re-fetches.")

	cmd.Flags().StringVar(&tlsCertFile, "tls-cert", "",
		"PEM certificate (chain) for the HTTP listener. Set together with --tls-key to serve HTTPS; leave both empty (default) to serve plaintext HTTP for backward compatibility.")
	cmd.Flags().StringVar(&tlsKeyFile, "tls-key", "",
		"PEM private key matching --tls-cert. Required when --tls-cert is set.")
	cmd.Flags().StringVar(&clientCAFile, "client-ca", "",
		"PEM CA bundle used to require and verify client certificates (mutual TLS). When set, the listener rejects any client whose certificate does not chain to this bundle. Requires --tls-cert/--tls-key. Empty (default) disables client-cert verification.")
	cmd.Flags().BoolVar(&requireAuth, "require-auth", false,
		"require an authenticated caller on every write / PDP / issuance endpoint: the request must arrive over mTLS with a verified client certificate carrying a spiffe:// URI SAN, and SVID issuance is bound to that caller (self-renewal only; minting a different identity is denied). Default false keeps today's open, unauthenticated behaviour. Requires --client-ca. Public reads (/healthz, /v1/leader, GET /v1/bundle, GET /v1/domains) and the attestation enrollment paths stay reachable. See docs/design/control-plane-trust-model.md (C1).")

	return cmd
}

// buildServerTLS assembles the listener tls.Config from the operator's
// flags. It returns (nil, nil) when no --tls-cert/--tls-key are set so
// the caller serves plaintext HTTP (the backward-compatible default).
//
// When cert+key are set it serves TLS with a 1.2 floor. When --client-ca
// is additionally set it switches to mutual TLS: client certificates are
// required and verified against that bundle, which is what lets the
// application layer trust the SPIFFE URI SAN it reads off the peer cert.
func buildServerTLS(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		if clientCAFile != "" {
			return nil, errors.New("--client-ca requires --tls-cert/--tls-key: client-cert verification only applies to a TLS listener")
		}
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("--tls-cert and --tls-key must be set together")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if clientCAFile != "" {
		// #nosec G304 -- clientCAFile is operator-supplied via --client-ca, not user input.
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read --client-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--client-ca %q contained no PEM certificates", clientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// isPostgresDSN duplicates storage.isPostgresDSN so the CLI can decide
// whether to start leader election without exporting it from storage.
func isPostgresDSN(spec string) bool {
	return strings.HasPrefix(spec, "postgres://") || strings.HasPrefix(spec, "postgresql://")
}

// hasNonEmpty reports whether vals contains at least one entry that is
// not blank after trimming. Used to reject an effectively-empty
// --k8s-token-audience (e.g. `--k8s-token-audience=` or whitespace).
func hasNonEmpty(vals []string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// resolveVaultToken assembles the Vault token from (in order of
// preference) the file path, the env var, and the literal flag.
// Returns "" when none are set so the caller surfaces a clear
// "token required" error instead of an opaque 403 from Vault.
func resolveVaultToken(literal, tokenFile string) (string, error) {
	if tokenFile != "" {
		// #nosec G304 -- tokenFile is operator-supplied via --ca-vault-pki-token-file, not user input.
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file %s: %w", tokenFile, err)
		}
		// First non-empty line is the token; allow a trailing newline.
		tok := strings.TrimSpace(string(raw))
		if line, _, ok := strings.Cut(tok, "\n"); ok {
			tok = strings.TrimSpace(line)
		}
		if tok == "" {
			return "", fmt.Errorf("token file %s is empty", tokenFile)
		}
		return tok, nil
	}
	if env := strings.TrimSpace(os.Getenv("OMEGA_VAULT_PKI_TOKEN")); env != "" {
		return env, nil
	}
	return strings.TrimSpace(literal), nil
}

// parseOIDCIdPFlags parses repeated --oidc-idp values. Each value is
// a comma-separated `key=value` list with keys `name`, `issuer`,
// `audience` (repeatable inside the same value via `audience=a;b`),
// and `template`. Missing required keys are a hard error so a
// misconfiguration surfaces at startup instead of failing the first
// /v1/oidc/exchange call.
//
// Limitation: values must not themselves contain a comma, because
// the outer split uses ',' as the key-value separator. SPIFFE ID
// templates and OIDC URLs do not contain commas in practice; pass
// the flag multiple times rather than smuggling commas inside one
// invocation. A shlex-style escape grammar is on the roadmap if a
// real use case turns up.
func parseOIDCIdPFlags(specs []string) ([]oidcpkg.IdPConfig, error) {
	out := make([]oidcpkg.IdPConfig, 0, len(specs))
	for _, s := range specs {
		var cfg oidcpkg.IdPConfig
		for _, kv := range strings.Split(s, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("invalid entry %q (expected key=value pairs)", s)
			}
			switch strings.TrimSpace(k) {
			case "name":
				cfg.Name = strings.TrimSpace(v)
			case "issuer":
				cfg.Issuer = strings.TrimSpace(v)
			case "audience":
				for _, a := range strings.Split(v, ";") {
					a = strings.TrimSpace(a)
					if a != "" {
						cfg.Audiences = append(cfg.Audiences, a)
					}
				}
			case "template":
				cfg.SPIFFEIDTemplate = strings.TrimSpace(v)
			default:
				return nil, fmt.Errorf("unknown key %q in %q (expected name= issuer= audience= template=)", k, s)
			}
		}
		out = append(out, cfg)
	}
	return out, nil
}

// parseHeaderFlags turns repeated "Key: value" flag values into a
// header map. Whitespace around the key and value is trimmed; an
// empty key or a missing colon is a hard error so misconfigured
// flags surface at startup instead of silently dropping auth.
func parseHeaderFlags(specs []string) (map[string]string, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(specs))
	for _, s := range specs {
		k, v, ok := strings.Cut(s, ":")
		if !ok {
			return nil, fmt.Errorf("invalid header %q (expected 'Key: value')", s)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			return nil, fmt.Errorf("invalid header %q (empty key)", s)
		}
		out[k] = v
	}
	return out, nil
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
