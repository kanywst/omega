package identity

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const defaultUpstreamDialTimeout = 30 * time.Second

// go-spiffe retries transient stream failures itself. This covers the case
// where it gives up: a permanently failing watch keeps complaining instead
// of silently freezing the trust material, which is the failure ADR 0009
// exists to prevent.
const upstreamWatchRetryDelay = 5 * time.Second

// UpstreamWorkloadAPIConfig configures a live feed of upstream trust
// material read from a SPIFFE Workload API endpoint.
type UpstreamWorkloadAPIConfig struct {
	// Addr is the endpoint, e.g. unix:///run/spire/sockets/agent.sock.
	Addr string

	// TrustDomain selects one bundle out of the set the endpoint serves -
	// the local domain plus any federated ones.
	TrustDomain spiffeid.TrustDomain

	// ConsumeJWT also follows the upstream JWT bundle. Off by default: only
	// EC P-256 keys are consumable, so an upstream signing with RSA would
	// otherwise fail startup for a deployment that never wanted JWT.
	ConsumeJWT bool

	// DialTimeout bounds the boot-time fetch. Zero uses 30s.
	DialTimeout time.Duration

	// Logf receives operational messages. Nil discards them.
	Logf func(format string, args ...any)
}

// UpstreamWorkloadAPI is the live transport for the consuming identity
// source (ADR 0010): it holds the upstream's current trust material and
// keeps it current from a SPIFFE Workload API endpoint. What it fetches
// goes through the same ReloadableSource.Reload seam as the file
// transport, so validation and the fail-closed rule are shared.
type UpstreamWorkloadAPI struct {
	client     *workloadapi.Client
	td         spiffeid.TrustDomain
	consumeJWT bool
	logf       func(format string, args ...any)

	// The two watches run independently, so a reader can see a new X.509
	// bundle beside the previous JWKS. Both halves are valid anchors and
	// the other update follows, so the pair is mixed, never invalid.
	mu      sync.Mutex
	x509PEM []byte
	jwtJWKS []byte

	// Capacity 1, sent to non-blocking: the reload re-reads whatever is
	// current, so a dropped notification costs nothing.
	updated chan struct{}
}

// requireUnixAddr rejects every scheme but unix. go-spiffe will happily
// dial tcp://<any-ip>:<port> with no transport security and no server
// authentication, and what arrives over it becomes Omega's entire root of
// trust. The Workload API's security model is kernel-enforced peer
// credentials over a local socket; the rest of the codebase pins unix://
// itself rather than letting a caller pick (internal/cli/svid.go).
func requireUnixAddr(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("identity: upstream workload API address %q is not a valid URI: %w", addr, err)
	}
	if u.Scheme != "unix" {
		return fmt.Errorf("identity: upstream workload API address must use the unix:// scheme, got %q; a network endpoint is dialled without transport security, so Omega would bootstrap its trust anchors over an unauthenticated channel", addr)
	}
	return nil
}

// DialUpstreamWorkloadAPI connects to cfg.Addr and fetches the current
// trust material for cfg.TrustDomain, blocking until it has it.
func DialUpstreamWorkloadAPI(ctx context.Context, cfg UpstreamWorkloadAPIConfig) (_ *UpstreamWorkloadAPI, err error) {
	if cfg.TrustDomain.IsZero() {
		return nil, errors.New("identity: upstream workload API needs the upstream trust domain")
	}
	if err := requireUnixAddr(cfg.Addr); err != nil {
		return nil, err
	}
	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = defaultUpstreamDialTimeout
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr(cfg.Addr))
	if err != nil {
		return nil, fmt.Errorf("identity: connect to the upstream workload API at %s: %w", cfg.Addr, err)
	}
	// Every path below leaves the caller without a handle to close.
	defer func() {
		if err != nil {
			err = errors.Join(err, client.Close())
		}
	}()

	w := &UpstreamWorkloadAPI{
		client:     client,
		td:         cfg.TrustDomain,
		consumeJWT: cfg.ConsumeJWT,
		logf:       logf,
		updated:    make(chan struct{}, 1),
	}

	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	x509Set, err := client.FetchX509Bundles(fetchCtx)
	if err != nil {
		return nil, fmt.Errorf("identity: fetch the upstream X.509 bundle from %s: %w", cfg.Addr, err)
	}
	if err := w.setX509(x509Set); err != nil {
		return nil, err
	}
	if cfg.ConsumeJWT {
		jwtSet, err := client.FetchJWTBundles(fetchCtx)
		if err != nil {
			return nil, fmt.Errorf("identity: fetch the upstream JWT bundle from %s: %w", cfg.Addr, err)
		}
		if err := w.setJWT(jwtSet); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// Material returns copies of the current trust material. jwtJWKS is nil
// when ConsumeJWT is off, which NewUpstreamSourceWithJWT reads as
// X.509-only consumption.
func (w *UpstreamWorkloadAPI) Material() (x509PEM, jwtJWKS []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	x509PEM = append([]byte(nil), w.x509PEM...)
	if w.jwtJWKS != nil {
		jwtJWKS = append([]byte(nil), w.jwtJWKS...)
	}
	return x509PEM, jwtJWKS
}

func (w *UpstreamWorkloadAPI) Close() error { return w.client.Close() }

// Run installs each new generation into src until ctx is done, calling
// onChange (may be nil) when one actually differed. Material src rejects
// is logged and dropped: serving anchors that are merely old beats serving
// none.
func (w *UpstreamWorkloadAPI) Run(ctx context.Context, src ReloadableSource, onChange func()) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.watch(ctx, "X.509", func(c context.Context) error {
			return w.client.WatchX509Bundles(c, x509BundleWatcher{w})
		})
	}()
	if w.consumeJWT {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.watch(ctx, "JWT", func(c context.Context) error {
				return w.client.WatchJWTBundles(c, jwtBundleWatcher{w})
			})
		}()
	}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-w.updated:
			x509PEM, jwtJWKS := w.Material()
			changed, err := src.Reload(x509PEM, jwtJWKS)
			switch {
			case err != nil:
				w.logf("upstream trust material from the workload API rejected, keeping previous: %v", err)
			case changed:
				if onChange != nil {
					onChange()
				}
				w.logf("upstream trust material reloaded from the workload API (%s)", w.td)
			}
		}
	}
}

func (w *UpstreamWorkloadAPI) watch(ctx context.Context, what string, start func(context.Context) error) {
	for {
		err := start(ctx)
		if ctx.Err() != nil {
			return
		}
		w.logf("upstream %s bundle watch ended (%v); retrying in %s, serving the last known-good material", what, err, upstreamWatchRetryDelay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(upstreamWatchRetryDelay):
		}
	}
}

func (w *UpstreamWorkloadAPI) signal() {
	select {
	case w.updated <- struct{}{}:
	default:
	}
}

// setX509 errors when the set omits the trust domain: that means the wrong
// endpoint or the wrong --trust-domain, and publishing an empty bundle
// would break every handshake in the mesh.
func (w *UpstreamWorkloadAPI) setX509(set *x509bundle.Set) error {
	bundle, err := set.GetX509BundleForTrustDomain(w.td)
	if err != nil {
		return fmt.Errorf("identity: the upstream workload API served no X.509 bundle for trust domain %q: %w", w.td, err)
	}
	pemBytes, err := bundle.Marshal()
	if err != nil {
		return fmt.Errorf("identity: encode the upstream X.509 bundle for %q: %w", w.td, err)
	}
	w.mu.Lock()
	w.x509PEM = pemBytes
	w.mu.Unlock()
	w.signal()
	return nil
}

// setJWT runs only when ConsumeJWT is on, so a missing bundle is a
// misconfiguration rather than the X.509-only case.
func (w *UpstreamWorkloadAPI) setJWT(set *jwtbundle.Set) error {
	bundle, err := set.GetJWTBundleForTrustDomain(w.td)
	if err != nil {
		return fmt.Errorf("identity: the upstream workload API served no JWT bundle for trust domain %q: %w", w.td, err)
	}
	jwks, err := bundle.Marshal()
	if err != nil {
		return fmt.Errorf("identity: encode the upstream JWT bundle for %q: %w", w.td, err)
	}
	w.mu.Lock()
	w.jwtJWKS = jwks
	w.mu.Unlock()
	w.signal()
	return nil
}

// Two named types because go-spiffe's watcher interfaces would collide on
// one receiver.
type x509BundleWatcher struct{ w *UpstreamWorkloadAPI }

func (x x509BundleWatcher) OnX509BundlesUpdate(set *x509bundle.Set) {
	if err := x.w.setX509(set); err != nil {
		x.w.logf("upstream X.509 bundle update ignored, keeping previous: %v", err)
	}
}

func (x x509BundleWatcher) OnX509BundlesWatchError(err error) {
	x.w.logf("upstream X.509 bundle watch error: %v", err)
}

type jwtBundleWatcher struct{ w *UpstreamWorkloadAPI }

func (j jwtBundleWatcher) OnJWTBundlesUpdate(set *jwtbundle.Set) {
	if err := j.w.setJWT(set); err != nil {
		j.w.logf("upstream JWT bundle update ignored, keeping previous: %v", err)
	}
}

func (j jwtBundleWatcher) OnJWTBundlesWatchError(err error) {
	j.w.logf("upstream JWT bundle watch error: %v", err)
}
