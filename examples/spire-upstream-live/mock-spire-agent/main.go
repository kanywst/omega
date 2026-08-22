// mock-spire-agent is a stand-in for a SPIRE agent's SPIFFE Workload API
// socket, for the examples/spire-upstream-live demo. It serves the two
// bundle RPCs omega consumes in spire-upstream mode, FetchX509Bundles and
// FetchJWTBundles, and enforces the workload.spiffe.io security header
// SPIRE requires.
//
// Both RPCs are streams. The agent watches the trust material on disk and
// pushes when it changes, which is what makes the demo a demo: the
// rotation is applied to the upstream, nothing signals omega, and omega
// has to follow anyway.
//
// A bundle file holding no certificates makes the agent drop the trust
// domain from the response, standing in for an upstream that stopped
// serving the domain omega was pointed at.
//
// A mock rather than a real spire-server/spire-agent pair for the same
// reason as mock-step-ca: the demo stays hermetic and fast in CI. The wire
// is not mocked - the service is the upstream SPIFFE proto, so a
// regression in omega's Workload API client trips this demo.
package main

import (
	"bytes"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type agent struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer

	trustDomainID string

	mu       sync.Mutex
	x509DER  []byte
	jwtJWKS  []byte
	watchers map[chan struct{}]struct{}
}

func newAgent(trustDomain string) *agent {
	return &agent{
		trustDomainID: "spiffe://" + trustDomain,
		watchers:      make(map[chan struct{}]struct{}),
	}
}

// Buffered and sent to non-blocking, so a slow stream never stalls the
// file watcher.
func (a *agent) subscribe() (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	a.mu.Lock()
	a.watchers[ch] = struct{}{}
	a.mu.Unlock()
	return ch, func() {
		a.mu.Lock()
		delete(a.watchers, ch)
		a.mu.Unlock()
	}
}

func (a *agent) set(x509DER, jwtJWKS []byte) bool {
	a.mu.Lock()
	if bytes.Equal(a.x509DER, x509DER) && bytes.Equal(a.jwtJWKS, jwtJWKS) {
		a.mu.Unlock()
		return false
	}
	a.x509DER, a.jwtJWKS = x509DER, jwtJWKS
	watchers := make([]chan struct{}, 0, len(a.watchers))
	for ch := range a.watchers {
		watchers = append(watchers, ch)
	}
	a.mu.Unlock()
	for _, ch := range watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return true
}

// An empty half is omitted rather than sent as a zero-length entry, which
// is how a real upstream expresses "nothing for this domain".
func (a *agent) bundles() (x509Map, jwtMap map[string][]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	x509Map = map[string][]byte{}
	jwtMap = map[string][]byte{}
	if len(a.x509DER) > 0 {
		x509Map[a.trustDomainID] = a.x509DER
	}
	if len(a.jwtJWKS) > 0 {
		jwtMap[a.trustDomainID] = a.jwtJWKS
	}
	return x509Map, jwtMap
}

// SPIRE refuses requests without this header, so a browser cannot be
// tricked into calling the socket.
func requireSecurityHeader(md metadata.MD) error {
	for _, v := range md.Get("workload.spiffe.io") {
		if v == "true" {
			return nil
		}
	}
	return status.Error(codes.InvalidArgument, "security header missing from request")
}

func (a *agent) FetchX509Bundles(_ *workloadpb.X509BundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	if err := requireSecurityHeader(md); err != nil {
		return err
	}
	updates, unsubscribe := a.subscribe()
	defer unsubscribe()
	for {
		x509Map, _ := a.bundles()
		if err := stream.Send(&workloadpb.X509BundlesResponse{Bundles: x509Map}); err != nil {
			return err
		}
		select {
		case <-stream.Context().Done():
			return nil
		case <-updates:
		}
	}
}

func (a *agent) FetchJWTBundles(_ *workloadpb.JWTBundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	if err := requireSecurityHeader(md); err != nil {
		return err
	}
	updates, unsubscribe := a.subscribe()
	defer unsubscribe()
	for {
		_, jwtMap := a.bundles()
		if err := stream.Send(&workloadpb.JWTBundlesResponse{Bundles: jwtMap}); err != nil {
			return err
		}
		select {
		case <-stream.Context().Done():
			return nil
		case <-updates:
		}
	}
}

// Concatenated DER is the encoding the Workload API uses for X.509 bundles.
func derFromPEM(pemBytes []byte) []byte {
	var der []byte
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = append(der, block.Bytes...)
		}
	}
	return der
}

// A missing or unparseable file yields empty material rather than an
// error: the demo rewrites these underneath a running agent, and a read
// landing mid-write should be retried on the next tick.
func load(bundlePath, jwksPath string) (der, jwks []byte) {
	if pemBytes, err := os.ReadFile(bundlePath); err == nil {
		der = derFromPEM(pemBytes)
	}
	if jwksPath != "" {
		if raw, err := os.ReadFile(jwksPath); err == nil {
			jwks = bytes.TrimSpace(raw)
		}
	}
	return der, jwks
}

func main() {
	var (
		socketPath  = flag.String("socket", "", "unix socket path to serve the Workload API on (required)")
		trustDomain = flag.String("trust-domain", "", "trust domain the served bundles belong to (required)")
		bundlePath  = flag.String("bundle", "", "path to the trust bundle PEM the upstream currently publishes (required)")
		jwksPath    = flag.String("jwks", "", "path to the JWT bundle JWKS the upstream currently publishes")
		poll        = flag.Duration("poll", 100*time.Millisecond, "how often to re-read the trust material")
	)
	flag.Parse()
	if *socketPath == "" || *trustDomain == "" || *bundlePath == "" {
		log.Fatal("mock-spire-agent: --socket, --trust-domain and --bundle are required")
	}

	a := newAgent(*trustDomain)
	if der, jwks := load(*bundlePath, *jwksPath); len(der) > 0 {
		a.set(der, jwks)
	} else {
		log.Fatalf("mock-spire-agent: %s held no certificates at startup", *bundlePath)
	}

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o750); err != nil {
		log.Fatalf("mock-spire-agent: socket dir: %v", err)
	}
	// A leftover socket fails Listen with "address already in use" even
	// though nothing is serving it.
	if err := os.Remove(*socketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("mock-spire-agent: stale socket: %v", err)
	}
	lis, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("mock-spire-agent: listen: %v", err)
	}

	srv := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(srv, a)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		srv.GracefulStop()
	}()

	go func() {
		for range time.Tick(*poll) {
			der, jwks := load(*bundlePath, *jwksPath)
			if a.set(der, jwks) {
				fmt.Fprintf(os.Stderr, "mock-spire-agent: published new trust material (x509=%dB jwks=%dB)\n", len(der), len(jwks))
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "mock-spire-agent: serving the workload API for %s on unix://%s\n", *trustDomain, *socketPath)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("mock-spire-agent: serve: %v", err)
	}
}
