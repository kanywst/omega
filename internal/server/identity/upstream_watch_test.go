package identity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"

	"github.com/kanywst/omega/internal/server/identity"
)

// fakeWorkloadAPI stands in for a SPIRE agent. The service is the upstream
// proto, so a change that breaks real SPIRE breaks this too.
type fakeWorkloadAPI struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer

	mu       sync.Mutex
	x509DER  map[string][]byte
	jwtJWKS  map[string][]byte
	watchers []chan struct{}
}

func (f *fakeWorkloadAPI) snapshot() (map[string][]byte, map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	x509Copy := make(map[string][]byte, len(f.x509DER))
	for k, v := range f.x509DER {
		x509Copy[k] = v
	}
	jwtCopy := make(map[string][]byte, len(f.jwtJWKS))
	for k, v := range f.jwtJWKS {
		jwtCopy[k] = v
	}
	return x509Copy, jwtCopy
}

// Buffered so a rotation never blocks on a stream that has not caught up.
func (f *fakeWorkloadAPI) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	f.mu.Lock()
	f.watchers = append(f.watchers, ch)
	f.mu.Unlock()
	return ch
}

func (f *fakeWorkloadAPI) rotate(x509DER, jwtJWKS map[string][]byte) {
	f.mu.Lock()
	f.x509DER, f.jwtJWKS = x509DER, jwtJWKS
	watchers := append([]chan struct{}(nil), f.watchers...)
	f.mu.Unlock()
	for _, ch := range watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (f *fakeWorkloadAPI) FetchX509Bundles(_ *workloadpb.X509BundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	updates := f.subscribe()
	for {
		bundles, _ := f.snapshot()
		if err := stream.Send(&workloadpb.X509BundlesResponse{Bundles: bundles}); err != nil {
			return err
		}
		select {
		case <-stream.Context().Done():
			return nil
		case <-updates:
		}
	}
}

func (f *fakeWorkloadAPI) FetchJWTBundles(_ *workloadpb.JWTBundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	updates := f.subscribe()
	for {
		_, bundles := f.snapshot()
		if err := stream.Send(&workloadpb.JWTBundlesResponse{Bundles: bundles}); err != nil {
			return err
		}
		select {
		case <-stream.Context().Done():
			return nil
		case <-updates:
		}
	}
}

// TCP rather than a unix socket: a temp dir can exceed the ~100 byte
// sockaddr path limit.
func startFakeWorkloadAPI(t *testing.T, fake *fakeWorkloadAPI) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "tcp://" + lis.Addr().String()
}

// upstreamGeneration mints one generation in the shapes the Workload API
// serves: DER for X.509, JWKS for JWT.
func upstreamGeneration(t *testing.T, td string) (der, jwks []byte, kid string) {
	t.Helper()
	up := upstreamAuthority(t, td)
	jwks, err := up.JWTBundle()
	if err != nil {
		t.Fatalf("upstream JWTBundle: %v", err)
	}
	kid, err = up.JWTKeyID()
	if err != nil {
		t.Fatalf("upstream JWTKeyID: %v", err)
	}
	return derFromPEM(t, up.BundlePEM()), jwks, kid
}

func derFromPEM(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
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
	if len(der) == 0 {
		t.Fatal("upstream bundle PEM held no certificates")
	}
	return der
}

// A certificate that is not a CA, so the bundle carries no trust anchor.
func leafOnlyDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "not-a-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return der
}

func dialFeed(t *testing.T, addr, td string, consumeJWT bool) *identity.UpstreamWorkloadAPI {
	t.Helper()
	// t.Context, not one cancelled on return: the watches have to outlive
	// this helper.
	feed, err := identity.DialUpstreamWorkloadAPI(t.Context(), identity.UpstreamWorkloadAPIConfig{
		Addr:        addr,
		TrustDomain: spiffeid.RequireTrustDomainFromString(td),
		ConsumeJWT:  consumeJWT,
		DialTimeout: 10 * time.Second,
		Logf:        func(format string, args ...any) { t.Logf(format, args...) },
	})
	if err != nil {
		t.Fatalf("DialUpstreamWorkloadAPI: %v", err)
	}
	t.Cleanup(func() { _ = feed.Close() })
	return feed
}

func TestUpstreamWorkloadAPIServesTheUpstreamBundleAtBoot(t *testing.T) {
	const td = "upstream.example"
	der, jwks, kid := upstreamGeneration(t, td)
	fake := &fakeWorkloadAPI{
		x509DER: map[string][]byte{"spiffe://" + td: der},
		jwtJWKS: map[string][]byte{"spiffe://" + td: jwks},
	}
	feed := dialFeed(t, startFakeWorkloadAPI(t, fake), td, true)

	bundlePEM, jwtBundle := feed.Material()
	src, err := identity.NewUpstreamSourceWithJWT(td, "", bundlePEM, jwtBundle)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT from the workload API material: %v", err)
	}
	if got := src.SourceKind(); got != identity.SourceSPIREUpstream {
		t.Fatalf("SourceKind() = %q, want %q", got, identity.SourceSPIREUpstream)
	}
	served, err := src.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	if !strings.Contains(string(served), kid) {
		t.Fatalf("served JWKS does not carry the upstream kid %q: %s", kid, served)
	}
}

// X.509-only is the default: nothing fetches the JWT bundle, so the source
// stays unconfigured for JWT rather than serving an empty JWKS.
func TestUpstreamWorkloadAPIX509OnlyLeavesJWTUnconfigured(t *testing.T) {
	const td = "upstream.example"
	der, jwks, _ := upstreamGeneration(t, td)
	fake := &fakeWorkloadAPI{
		x509DER: map[string][]byte{"spiffe://" + td: der},
		jwtJWKS: map[string][]byte{"spiffe://" + td: jwks},
	}
	feed := dialFeed(t, startFakeWorkloadAPI(t, fake), td, false)

	bundlePEM, jwtBundle := feed.Material()
	if jwtBundle != nil {
		t.Fatalf("JWT material fetched without ConsumeJWT: %s", jwtBundle)
	}
	src, err := identity.NewUpstreamSourceWithJWT(td, "", bundlePEM, jwtBundle)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	if _, err := src.ValidateJWTSVID("whatever", "aud"); !errors.Is(err, identity.ErrUpstreamJWTNotConfigured) {
		t.Fatalf("ValidateJWTSVID error = %v, want ErrUpstreamJWTNotConfigured", err)
	}
}

// The regression this transport exists for: the upstream rotates on its own
// schedule and nobody sends a signal.
func TestUpstreamWorkloadAPIFollowsRotationWithoutASignal(t *testing.T) {
	const td = "upstream.example"
	beforeDER, beforeJWKS, beforeKID := upstreamGeneration(t, td)
	fake := &fakeWorkloadAPI{
		x509DER: map[string][]byte{"spiffe://" + td: beforeDER},
		jwtJWKS: map[string][]byte{"spiffe://" + td: beforeJWKS},
	}
	feed := dialFeed(t, startFakeWorkloadAPI(t, fake), td, true)

	bundlePEM, jwtBundle := feed.Material()
	src, err := identity.NewUpstreamSourceWithJWT(td, "", bundlePEM, jwtBundle)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	if got := sequence(t, src); got != 1 {
		t.Fatalf("initial BundleSequence() = %d, want 1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		feed.Run(ctx, reloadable(t, src), func() { changed <- struct{}{} })
	}()

	afterDER, afterJWKS, afterKID := upstreamGeneration(t, td)
	fake.rotate(
		map[string][]byte{"spiffe://" + td: afterDER},
		map[string][]byte{"spiffe://" + td: afterJWKS},
	)

	// Both watches fire; wait for the change carrying the new kid.
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-changed:
			served, err := src.JWTBundle()
			if err != nil {
				t.Fatalf("JWTBundle: %v", err)
			}
			if !strings.Contains(string(served), afterKID) {
				continue
			}
			if strings.Contains(string(served), beforeKID) {
				t.Fatalf("post-rotation JWKS still carries the pre-rotation kid %q", beforeKID)
			}
			if got := sequence(t, src); got < 2 {
				t.Fatalf("BundleSequence() = %d after a rotation, want >= 2", got)
			}
			cancel()
			<-done
			return
		case <-deadline:
			t.Fatal("omega did not follow the upstream rotation")
		}
	}
}

// Fail-closed on the live transport too: serving anchors that are merely
// old beats serving none.
func TestUpstreamWorkloadAPIKeepsPreviousMaterialOnBadUpdate(t *testing.T) {
	const td = "upstream.example"
	beforeDER, beforeJWKS, _ := upstreamGeneration(t, td)
	fake := &fakeWorkloadAPI{
		x509DER: map[string][]byte{"spiffe://" + td: beforeDER},
		jwtJWKS: map[string][]byte{"spiffe://" + td: beforeJWKS},
	}
	feed := dialFeed(t, startFakeWorkloadAPI(t, fake), td, false)

	bundlePEM, _ := feed.Material()
	src, err := identity.NewUpstreamSourceWithJWT(td, "", bundlePEM, nil)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	good := append([]byte(nil), src.BundlePEM()...)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		feed.Run(ctx, reloadable(t, src), nil)
	}()

	// The upstream serves a bundle with no trust anchor in it.
	fake.rotate(map[string][]byte{"spiffe://" + td: leafOnlyDER(t)}, nil)

	// Give the watch time to deliver and be rejected. There is nothing to
	// wait on: the assertion is that nothing happened.
	time.Sleep(2 * time.Second)
	if got := string(src.BundlePEM()); got != string(good) {
		t.Fatalf("bundle changed after a rejected update:\ngot  %s\nwant %s", got, good)
	}
	if got := sequence(t, src); got != 1 {
		t.Fatalf("BundleSequence() = %d after a rejected update, want 1", got)
	}
	cancel()
	<-done
}

// Pointing Omega at the wrong endpoint, or naming the wrong --trust-domain,
// has to fail at startup: publishing an empty bundle would be worse.
func TestUpstreamWorkloadAPIRejectsAMissingTrustDomain(t *testing.T) {
	der, jwks, _ := upstreamGeneration(t, "upstream.example")
	fake := &fakeWorkloadAPI{
		x509DER: map[string][]byte{"spiffe://upstream.example": der},
		jwtJWKS: map[string][]byte{"spiffe://upstream.example": jwks},
	}
	addr := startFakeWorkloadAPI(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := identity.DialUpstreamWorkloadAPI(ctx, identity.UpstreamWorkloadAPIConfig{
		Addr:        addr,
		TrustDomain: spiffeid.RequireTrustDomainFromString("someone.else"),
		DialTimeout: 10 * time.Second,
	})
	if err == nil {
		t.Fatal("expected a dial against a trust domain the upstream does not serve to fail")
	}
	if !strings.Contains(err.Error(), "someone.else") {
		t.Fatalf("error should name the missing trust domain, got: %v", err)
	}
}

func TestDialUpstreamWorkloadAPIRequiresATrustDomain(t *testing.T) {
	_, err := identity.DialUpstreamWorkloadAPI(context.Background(), identity.UpstreamWorkloadAPIConfig{
		Addr: "tcp://127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("expected a zero trust domain to be rejected")
	}
}
