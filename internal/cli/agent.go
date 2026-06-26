package cli

import (
	"context"
	"fmt"
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

			return runAgent(ctx, socket, serverURL, mapping)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "/tmp/omega-agent.sock", "Workload API unix socket path")
	cmd.Flags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")
	cmd.Flags().StringArrayVar(&mappings, "map", nil, "uid->spiffe-id mapping (repeatable), e.g. --map 'uid=1000,id=spiffe://omega.local/example/web'")
	cmd.Flags().StringVar(&otlpEndpoint, "otlp-endpoint", "", "OTLP/HTTP traces endpoint, host:port (overrides OTEL_EXPORTER_OTLP_ENDPOINT). Empty disables tracing.")
	cmd.Flags().BoolVar(&otlpInsecure, "otlp-insecure", false, "send OTLP traces over plaintext HTTP (no TLS)")
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

func runAgent(ctx context.Context, socketPath, serverURL string, mapping workloadapi.Mapping) error {
	lis, err := attestor.Listen(socketPath)
	if err != nil {
		return err
	}
	defer lis.Close()

	grpcSrv := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()))
	workloadpb.RegisterSpiffeWorkloadAPIServer(grpcSrv, workloadapi.NewServer(serverURL, mapping))

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
