package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"time"

	"github.com/spf13/cobra"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"

	"github.com/kanywst/omega/internal/agent/attestor"
	"github.com/kanywst/omega/internal/agent/localpdp"
	"github.com/kanywst/omega/internal/agent/workloadapi"
	"github.com/kanywst/omega/internal/server/tracing"
	"github.com/kanywst/omega/internal/version"
)

func newAgentCommand() *cobra.Command {
	var (
		socket       string
		serverURL    string
		mappings     []string
		otlpEndpoint string
		otlpInsecure bool
		pdpAddr      string
		pdpSync      time.Duration
		pdpMaxAge    time.Duration
		pdpBuffer    int
		pdpRemote    bool
		bundleKey    string
		spoolPath    string
		serverCA     string
		clientCert   string
		clientKey    string
	)

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the Omega node agent (SPIFFE Workload API)",
		Long: `Run the Omega node agent: a SPIFFE Workload API gRPC server on a unix
socket that issues X.509-SVIDs to local workloads attested by their UID.

For each workload connection, the agent extracts the peer UID via
SO_PEERCRED (Linux) / LOCAL_PEERCRED (Darwin/BSD), maps it to a SPIFFE
ID via --map, and asks the control plane to sign a fresh CSR.`,
		RunE: func(c *cobra.Command, _ []string) error {
			mapping, err := parseMappings(mappings)
			if err != nil {
				return err
			}
			// Without --map the agent serves no Workload API; that is the
			// shape beside a SPIRE agent, which issues the identities while
			// this one only decides locally.
			if len(mapping) == 0 && pdpAddr == "" {
				return fmt.Errorf("at least one --map is required, or --local-pdp-addr to run only the local PDP (e.g. --map uid=%d,id=spiffe://omega.local/example/web)", os.Getuid())
			}
			ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			shutdownTracing, err := tracing.Setup(ctx, tracing.Config{
				ServiceName:    "omega-agent",
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

			var pdpFailed chan error
			transport, err := controlPlaneTransport(serverURL, serverCA, clientCert, clientKey)
			if err != nil {
				return err
			}

			if pdpAddr != "" {
				if err := checkLocalPDP(pdpAddr, pdpRemote, serverURL, serverCA, clientCert); err != nil {
					return err
				}
				td, err := trustDomainOfCert(clientCert)
				if err != nil {
					return err
				}
				var verifyKey *ecdsa.PublicKey
				if bundleKey != "" {
					if verifyKey, err = loadBundleVerifyKey(bundleKey); err != nil {
						return err
					}
				}
				pdp := localpdp.New(localpdp.Config{
					ServerURL: serverURL, SyncInterval: pdpSync, MaxAge: pdpMaxAge, BufferSize: pdpBuffer, TrustDomain: td, BundleKey: verifyKey, SpoolPath: spoolPath,
					HTTPClient: &http.Client{Transport: transport, Timeout: 10 * time.Second},
				})
				if err := pdp.RestoreSpool(); err != nil {
					return err
				}
				ran := make(chan struct{})
				go func() {
					pdp.Run(ctx)
					close(ran)
				}()
				// Deferred first so it runs last: once the listener has
				// stopped, wait for Run's final flush (itself bounded at
				// five seconds) so answered decisions reach the chain.
				defer func() {
					select {
					case <-ran:
					case <-time.After(6 * time.Second):
					}
				}()
				pdpFailed = make(chan error, 1)
				srv := &http.Server{Addr: pdpAddr, Handler: pdp.Handler(), ReadHeaderTimeout: 5 * time.Second}
				go func() {
					fmt.Fprintf(os.Stderr, "omega agent: local PDP on %s\n", pdpAddr)
					if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
						pdpFailed <- fmt.Errorf("local PDP: %w", err)
					}
				}()
				defer func() {
					shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = srv.Shutdown(shutCtx)
				}()
			}

			if len(mapping) == 0 {
				// The local PDP is all this agent does, so a listener that
				// cannot serve ends the process and the orchestrator sees it.
				fmt.Fprintln(os.Stderr, "omega agent: no --map, so no Workload API; serving the local PDP only")
				select {
				case <-ctx.Done():
					return nil
				case err := <-pdpFailed:
					stop() // end Run now rather than waiting out its flush timeout
					return err
				}
			}
			if pdpFailed == nil {
				return runAgent(ctx, socket, serverURL, mapping, transport)
			}
			// Workload API and local PDP together: either failing ends the
			// process, so a PDP that cannot listen is not silently absent.
			apiDone := make(chan error, 1)
			go func() { apiDone <- runAgent(ctx, socket, serverURL, mapping, transport) }()
			select {
			case err := <-apiDone:
				return err
			case err := <-pdpFailed:
				stop()
				return err
			}
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "/tmp/omega-agent.sock", "Workload API unix socket path")
	cmd.Flags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")
	cmd.Flags().StringArrayVar(&mappings, "map", nil, "uid->spiffe-id mapping (repeatable), e.g. --map 'uid=1000,id=spiffe://omega.local/example/web'")
	cmd.Flags().StringVar(&otlpEndpoint, "otlp-endpoint", "", "OTLP/HTTP traces endpoint, host:port (overrides OTEL_EXPORTER_OTLP_ENDPOINT). Empty disables tracing.")
	cmd.Flags().BoolVar(&otlpInsecure, "otlp-insecure", false, "send OTLP traces over plaintext HTTP (no TLS)")
	cmd.Flags().StringVar(&serverCA, "server-ca", "", "PEM bundle that verifies the control plane's TLS certificate (https --server). Empty uses the system roots.")
	cmd.Flags().StringVar(&clientCert, "client-cert", "", "PEM client certificate (an X.509-SVID) the agent presents to the control plane; needed when the server runs with --require-auth")
	cmd.Flags().StringVar(&clientKey, "client-key", "", "PEM private key for --client-cert")
	cmd.Flags().StringVar(&pdpAddr, "local-pdp-addr", "", "serve an AuthZEN evaluation endpoint on this address (e.g. 127.0.0.1:8181), deciding locally from the control plane's policy bundle and shipping every decision to its audit chain. Empty disables it.")
	cmd.Flags().DurationVar(&pdpSync, "policy-sync-interval", 10*time.Second, "how often the local PDP re-fetches the policy bundle")
	cmd.Flags().DurationVar(&pdpMaxAge, "policy-max-age", time.Minute, "the local PDP refuses to decide (503) when its last successful bundle sync is older than this")
	cmd.Flags().StringVar(&bundleKey, "policy-bundle-key", "", "the control plane's bundle signing public key (PEM public key or certificate); when set, the local PDP refuses any bundle without a valid signature from it")
	cmd.Flags().StringVar(&spoolPath, "decision-spool", "", "file the local PDP writes and syncs every decision to before answering, and requeues from at start, so decisions survive an agent crash (costs one fsync per decision)")
	cmd.Flags().BoolVar(&pdpRemote, "local-pdp-allow-remote", false, "let --local-pdp-addr bind a non-loopback address; the endpoint has no authentication, so anyone who reaches it can query policy and fill the decision buffer")
	cmd.Flags().IntVar(&pdpBuffer, "decision-buffer", 10000, "decisions the local PDP may hold before they reach the audit chain; when full it refuses to decide (503)")
	return cmd
}

func parseMappings(specs []string) (workloadapi.Mapping, error) {
	out := workloadapi.Mapping{}
	for _, s := range specs {
		var uidStr, id string
		for _, kv := range strings.Split(s, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("invalid map entry %q (expected key=value pairs)", s)
			}
			switch strings.TrimSpace(k) {
			case "uid":
				uidStr = strings.TrimSpace(v)
			case "id":
				id = strings.TrimSpace(v)
			default:
				return nil, fmt.Errorf("unknown key %q in --map %q (expected uid=, id=)", k, s)
			}
		}
		if uidStr == "" || id == "" {
			return nil, fmt.Errorf("--map %q is missing uid or id", s)
		}
		u, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("--map uid=%q: %w", uidStr, err)
		}
		out[uint32(u)] = id
	}
	return out, nil
}

// checkLocalPDP refuses local PDP settings that cannot work or would
// expose it: decisions are recorded under the agent's SVID, so the
// control plane must be reached over https with a client certificate,
// and the unauthenticated endpoint stays on loopback unless allowed.
func checkLocalPDP(addr string, allowRemote bool, serverURL, serverCA, clientCert string) error {
	if u, err := url.Parse(serverURL); err != nil || u.Scheme != "https" || clientCert == "" {
		return errors.New("--local-pdp-addr needs an https --server and --client-cert: decisions are recorded under the agent's SVID")
	}
	if serverCA == "" {
		return errors.New("--local-pdp-addr needs --server-ca: the policy bundle is trusted only as far as the TLS connection it came over")
	}
	if allowRemote {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--local-pdp-addr: %w", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("--local-pdp-addr %q is not a loopback address; pass --local-pdp-allow-remote to expose the unauthenticated endpoint", addr)
	}
	return nil
}

func runAgent(ctx context.Context, socketPath, serverURL string, mapping workloadapi.Mapping, transport http.RoundTripper) error {
	lis, err := attestor.Listen(socketPath)
	if err != nil {
		return err
	}
	defer lis.Close()

	grpcSrv := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()))
	workloadpb.RegisterSpiffeWorkloadAPIServer(grpcSrv, workloadapi.NewServer(serverURL, mapping).WithTransport(transport))

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "omega agent: socket=%s server=%s mappings=%d\n", socketPath, serverURL, len(mapping))
		errCh <- grpcSrv.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}

// trustDomainOfCert returns the trust domain of the SPIFFE ID in the
// first certificate of a PEM file: the agent's own SVID, whose trust
// domain is the only one its local PDP may load a bundle for.
func trustDomainOfCert(path string) (string, error) {
	// #nosec G304 -- operator-supplied --client-cert path.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read --client-cert: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("--client-cert holds no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse --client-cert: %w", err)
	}
	if len(cert.URIs) != 1 {
		return "", errors.New("--client-cert must be an X.509-SVID with exactly one URI SAN")
	}
	id, err := spiffeid.FromURI(cert.URIs[0])
	if err != nil {
		return "", fmt.Errorf("--client-cert: %w", err)
	}
	return id.TrustDomain().Name(), nil
}
