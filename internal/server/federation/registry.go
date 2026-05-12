// Package federation maintains the set of SPIFFE trust bundles this
// Omega server is willing to vouch for: its own bundle plus the bundles
// of any peer trust domains configured via --federate-with. Agents pull
// the merged map from /v1/federation/bundles and feed it to the
// Workload API's FetchX509Bundles stream so workloads can validate
// cross-trust-domain mTLS handshakes.
//
// Bundle exchange first tries the peer's `GET /v1/spiffe-bundle` SPIFFE
// Trust Domain Format endpoint and falls back to the legacy
// `GET /v1/bundle` PEM endpoint if the peer does not serve the new
// shape. When TDF is available the document's `spiffe_refresh_hint`
// drives the next poll cadence (clamped) so peers can ask for slower
// polling when their bundle changes rarely or faster polling during
// a rotation window.
package federation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// PeerConfig identifies one federated trust domain by its name and the
// HTTP base URL of the peer Omega control plane that vends the bundle.
type PeerConfig struct {
	TrustDomain string
	URL         string
}

// Registry serves the merged trust-bundle map for this control plane.
// The own bundle never expires (it lives as long as the CA). Peer
// bundles are fetched in the background; a peer that has never been
// reached is omitted from the map rather than served as an empty entry.
//
// Each peer runs in its own goroutine inside Run, with an independent
// poll cadence derived from that peer's `spiffe_refresh_hint`. A
// 10s-hint peer and a 1h-hint peer therefore sleep on their own
// rhythms instead of being forced into a single global tick.
type Registry struct {
	ownTD     spiffeid.TrustDomain
	ownBundle []byte

	peers      []PeerConfig
	httpClient *http.Client

	// configuredRefresh is the operator-supplied default (CLI flag).
	// A peer with no TDF refresh hint inherits this; per-peer
	// effective refresh is `min(configuredRefresh, hint)` clamped to
	// [minRefresh, maxRefresh].
	configuredRefresh time.Duration

	mu               sync.RWMutex
	peerBundles      map[string][]byte // trust domain -> PEM
	peerRefreshHints map[string]time.Duration
}

const (
	minRefresh = 10 * time.Second
	maxRefresh = 1 * time.Hour
)

// NewRegistry returns a Registry that always serves ownTD -> ownBundle
// and lazily merges in peer bundles once Run has populated them. The
// caller is responsible for invoking Run; Bundles() is safe to call
// before Run completes (it just returns own-only).
func NewRegistry(ownTD spiffeid.TrustDomain, ownBundle []byte, peers []PeerConfig, refresh time.Duration) *Registry {
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	return &Registry{
		ownTD:             ownTD,
		ownBundle:         ownBundle,
		peers:             peers,
		httpClient:        &http.Client{Timeout: 10 * time.Second},
		configuredRefresh: refresh,
		peerBundles:       map[string][]byte{},
		peerRefreshHints:  map[string]time.Duration{},
	}
}

// Bundles returns a fresh copy of the trust-domain -> PEM map. Callers
// are free to mutate the returned map and slices.
func (r *Registry) Bundles() map[string][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]byte, len(r.peerBundles)+1)
	out[r.ownTD.Name()] = append([]byte(nil), r.ownBundle...)
	for td, pem := range r.peerBundles {
		out[td] = append([]byte(nil), pem...)
	}
	return out
}

// Peers returns the configured peer set (without bundle contents).
// Useful for diagnostics endpoints.
func (r *Registry) Peers() []PeerConfig {
	out := make([]PeerConfig, len(r.peers))
	copy(out, r.peers)
	return out
}

// PeerRefresh returns the effective poll interval for one peer
// (trust-domain key), after the peer's TDF refresh hint is clamped
// against the operator-configured default. Returns 0 if the named
// peer is not configured. Exposed for tests and diagnostics; not
// surfaced through HTTP today.
func (r *Registry) PeerRefresh(trustDomain string) time.Duration {
	r.mu.RLock()
	hint, ok := r.peerRefreshHints[trustDomain]
	r.mu.RUnlock()
	if !r.hasPeer(trustDomain) {
		return 0
	}
	candidate := r.configuredRefresh
	if ok && hint > 0 && hint < candidate {
		candidate = hint
	}
	if candidate < minRefresh {
		candidate = minRefresh
	}
	if candidate > maxRefresh {
		candidate = maxRefresh
	}
	return candidate
}

func (r *Registry) hasPeer(trustDomain string) bool {
	for _, p := range r.peers {
		if p.TrustDomain == trustDomain {
			return true
		}
	}
	return false
}

// Run spawns one goroutine per configured peer (each with its own
// poll cadence) and blocks until ctx is canceled. The initial fetch
// happens inside each goroutine, so a slow peer cannot delay the
// first /v1/federation/bundles answer for the others.
func (r *Registry) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range r.peers {
		wg.Add(1)
		go func(peer PeerConfig) {
			defer wg.Done()
			r.runPeer(ctx, peer)
		}(p)
	}
	wg.Wait()
}

// runPeer is the per-peer loop. It fetches the peer's bundle on
// entry, retries on a short backoff if the first attempt fails (so a
// peer that booted a few hundred milliseconds after omega still
// appears in the merged map promptly), and then sleeps for that
// peer's effective refresh interval before each subsequent fetch.
func (r *Registry) runPeer(ctx context.Context, peer PeerConfig) {
	r.refreshOne(ctx, peer)
	// Initial backoff sequence in case the peer was not ready yet. We
	// only re-fetch when the previous attempt did not populate this
	// peer's bundle.
	for _, d := range []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second, 5 * time.Second} {
		if r.peerHasBundle(peer.TrustDomain) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
			r.refreshOne(ctx, peer)
		}
	}
	// Steady-state loop. NewTimer (not time.After) so a ctx
	// cancellation reclaims the timer immediately instead of pinning
	// it for up to PeerRefresh (1h max with current clamp).
	for {
		timer := time.NewTimer(r.PeerRefresh(peer.TrustDomain))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			r.refreshOne(ctx, peer)
		}
	}
}

func (r *Registry) peerHasBundle(trustDomain string) bool {
	r.mu.RLock()
	_, ok := r.peerBundles[trustDomain]
	r.mu.RUnlock()
	return ok
}

func (r *Registry) refreshOne(ctx context.Context, p PeerConfig) {
	body, hint, err := r.fetchPeer(ctx, p)
	if err != nil {
		slog.Warn("federation: peer bundle fetch failed", "peer", p.TrustDomain, "url", p.URL, "err", err)
		return
	}
	r.mu.Lock()
	r.peerBundles[p.TrustDomain] = body
	if hint > 0 {
		r.peerRefreshHints[p.TrustDomain] = hint
	} else {
		delete(r.peerRefreshHints, p.TrustDomain)
	}
	r.mu.Unlock()
}

// fetchPeer asks the peer for its trust bundle, preferring the SPIFFE
// TDF endpoint. Returns the X.509 anchor bundle as PEM (the storage
// shape the rest of the registry uses) and the peer's
// `spiffe_refresh_hint` value (zero when the peer is on the legacy
// PEM endpoint, which carries no hint).
func (r *Registry) fetchPeer(ctx context.Context, peer PeerConfig) ([]byte, time.Duration, error) {
	pemBytes, hint, err := r.fetchTDF(ctx, peer)
	if err == nil {
		return pemBytes, hint, nil
	}
	if err != errTDFUnavailable {
		return nil, 0, err
	}
	// Peer does not serve /v1/spiffe-bundle; fall back to the legacy
	// PEM endpoint so a freshly-built omega still federates with peers
	// older than the spiffe-bundle PR.
	pemBytes, err = r.fetchPEM(ctx, peer.URL)
	if err != nil {
		return nil, 0, err
	}
	return pemBytes, 0, nil
}

var errTDFUnavailable = fmt.Errorf("federation: peer does not serve /v1/spiffe-bundle")

func (r *Registry) fetchTDF(ctx context.Context, peer PeerConfig) ([]byte, time.Duration, error) {
	td, err := spiffeid.TrustDomainFromString(peer.TrustDomain)
	if err != nil {
		return nil, 0, fmt.Errorf("trust domain: %w", err)
	}
	url := strings.TrimRight(peer.URL, "/") + "/v1/spiffe-bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, 0, errTDFUnavailable
	}
	// 1 MiB cap on the upstream response so a misconfigured or hostile
	// peer cannot exhaust memory; real TDF documents are a few KiB.
	const maxTDF = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTDF))
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Parse through go-spiffe so the same code path a SPIRE agent
	// would walk is exercised here; anything the SDK rejects is
	// rejected on omega's side too.
	bundle, err := spiffebundle.Read(td, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("parse tdf: %w", err)
	}
	anchors := bundle.X509Authorities()
	if len(anchors) == 0 {
		return nil, 0, fmt.Errorf("tdf bundle for %s has no x509 anchors", td)
	}
	var buf bytes.Buffer
	for _, cert := range anchors {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return nil, 0, fmt.Errorf("encode anchor pem: %w", err)
		}
	}
	hint, _ := bundle.RefreshHint()
	return buf.Bytes(), hint, nil
}

func (r *Registry) fetchPEM(ctx context.Context, baseURL string) ([]byte, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const maxPEM = 1 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPEM))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		return nil, fmt.Errorf("response is not a PEM bundle (%d bytes)", len(body))
	}
	// Defence in depth: confirm the bytes actually parse as one or
	// more PEM CERTIFICATE blocks. A peer that returns malformed PEM
	// would otherwise propagate to every workload's TLS handshake.
	rest := body
	saw := false
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("parse anchor: %w", err)
			}
			saw = true
		}
		rest = next
	}
	if !saw {
		return nil, fmt.Errorf("response contains no parseable CERTIFICATE block")
	}
	return body, nil
}
