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
type Registry struct {
	ownTD     spiffeid.TrustDomain
	ownBundle []byte

	peers      []PeerConfig
	httpClient *http.Client

	// configuredRefresh is the operator-supplied default (CLI flag);
	// effectiveRefresh is what Run actually sleeps for. The latter is
	// driven down by the smallest peer refresh hint observed in the
	// previous round, clamped to [minRefresh, maxRefresh].
	configuredRefresh time.Duration

	mu               sync.RWMutex
	peerBundles      map[string][]byte // trust domain -> PEM
	peerRefreshHints map[string]time.Duration
	effectiveRefresh time.Duration
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
		effectiveRefresh:  refresh,
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

// EffectiveRefresh returns the interval Run is currently sleeping
// between refresh rounds, after any TDF refresh-hint clamping. Exposed
// for tests and operator diagnostics; not surfaced through HTTP today.
func (r *Registry) EffectiveRefresh() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.effectiveRefresh
}

// Run blocks until ctx is canceled, refreshing every peer bundle on
// each tick. It performs an immediate fetch on entry so the first
// /v1/federation/bundles caller does not race the timer. If any peer
// is still missing after the initial fetch (typical when peers boot
// concurrently), a short backoff sequence retries before falling back
// to the regular refresh interval.
func (r *Registry) Run(ctx context.Context) {
	r.refreshAll(ctx)
	for _, d := range []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second, 5 * time.Second} {
		if r.allPeersFetched() {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
			r.refreshAll(ctx)
		}
	}
	// Use NewTimer (not time.After) so a context cancellation while
	// the timer is armed lets us Stop() it immediately. With
	// EffectiveRefresh allowed up to 1h, time.After would otherwise
	// keep the timer reachable for up to that hour after the loop
	// exits. Also re-derives the cadence each iteration so the
	// peer-supplied refresh hint takes effect without Ticker.Reset
	// gymnastics.
	for {
		timer := time.NewTimer(r.EffectiveRefresh())
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			r.refreshAll(ctx)
		}
	}
}

func (r *Registry) allPeersFetched() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.peers {
		if _, ok := r.peerBundles[p.TrustDomain]; !ok {
			return false
		}
	}
	return true
}

func (r *Registry) refreshAll(ctx context.Context) {
	for _, p := range r.peers {
		body, hint, err := r.fetchPeer(ctx, p)
		if err != nil {
			slog.Warn("federation: peer bundle fetch failed", "peer", p.TrustDomain, "url", p.URL, "err", err)
			continue
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
	r.recomputeEffectiveRefresh()
}

func (r *Registry) recomputeEffectiveRefresh() {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate := r.configuredRefresh
	for _, h := range r.peerRefreshHints {
		if h > 0 && h < candidate {
			candidate = h
		}
	}
	if candidate < minRefresh {
		candidate = minRefresh
	}
	if candidate > maxRefresh {
		candidate = maxRefresh
	}
	r.effectiveRefresh = candidate
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
