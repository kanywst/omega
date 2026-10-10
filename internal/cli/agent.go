package cli

import (
	"context"
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
			if len(mapping) == 0 {
				return fmt.Errorf("at least one --map is required (e.g. --map uid=%d,id=spiffe://omega.local/example/web)", os.Getuid())
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

			transport, err := controlPlaneTransport(serverURL, serverCA, clientCert, clientKey)
			if err != nil {
				return err
			}

			if pdpAddr != "" {
				if err := checkLocalPDP(pdpAddr, pdpRemote, serverURL, clientCert); err != nil {
					return err
				}
				pdp := localpdp.New(localpdp.Config{
					ServerURL: serverURL, SyncInterval: pdpSync, MaxAge: pdpMaxAge, BufferSize: pdpBuffer,
					HTTPClient: &http.Client{Transport: transport, Timeout: 10 * time.Second},
				})
				go pdp.Run(ctx)
				srv := &http.Server{Addr: pdpAddr, Handler: pdp.Handler(), ReadHeaderTimeout: 5 * time.Second}
				go func() {
					fmt.Fprintf(os.Stderr, "omega agent: local PDP on %s\n", pdpAddr)
					if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
						fmt.Fprintf(os.Stderr, "omega agent: local PDP: %v\n", err)
					}
				}()
				defer func() {
					shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					_ = srv.Shutdown(shutCtx)
				}()
			}

			return runAgent(ctx, socket, serverURL, mapping, transport)
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
func checkLocalPDP(addr string, allowRemote bool, serverURL, clientCert string) error {
	if u, err := url.Parse(serverURL); err != nil || u.Scheme != "https" || clientCert == "" {
		return errors.New("--local-pdp-addr needs an https --server and --client-cert: decisions are recorded under the agent's SVID")
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
