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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

// Profile names a SPIFFE Federation bundle-endpoint authentication
// profile. It controls how the peer's HTTPS endpoint identity is
// verified before its bundle bytes are trusted as a federated anchor.
type Profile string

const (
	// ProfileHTTPSWeb verifies the endpoint with standard web-PKI:
	// system roots (or an operator-supplied endpoint_ca) plus the
	// usual hostname check.
	ProfileHTTPSWeb Profile = "https_web"
	// ProfileHTTPSSPIFFE verifies the endpoint's X.509-SVID against a
	// pinned endpoint SPIFFE ID, chaining to an operator-seeded bundle
	// (endpoint_bundle). This is the SPIFFE-native profile and does
	// not depend on web-PKI for the control-plane link.
	ProfileHTTPSSPIFFE Profile = "https_spiffe"
)

// PeerConfig identifies one federated trust domain by its name and the
// HTTPS base URL of the peer Omega control plane that vends the bundle,
// plus the endpoint-identity verification material used to authenticate
// the fetch (SPIFFE Federation bundle-endpoint profiles).
type PeerConfig struct {
	TrustDomain string
	URL         string

	// Profile selects the endpoint-identity verification profile.
	// Empty defaults to ProfileHTTPSWeb. Ignored for http:// peers
	// (the explicit --federation-allow-insecure escape hatch), whose
	// fetch is plaintext and unverified.
	Profile Profile

	// EndpointSPIFFEID is the SPIFFE ID the peer endpoint must present
	// in its X.509-SVID URI SAN. Required for ProfileHTTPSSPIFFE.
	EndpointSPIFFEID string

	// EndpointCAFile is an optional PEM file of web-PKI roots used to
	// verify the endpoint under ProfileHTTPSWeb. Empty falls back to
	// the system trust store.
	EndpointCAFile string

	// EndpointBundleFile is the operator-seeded PEM trust bundle that
	// bootstraps verification of the peer's X.509-SVID under
	// ProfileHTTPSSPIFFE. Required for that profile.
	EndpointBundleFile string
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

	peers []PeerConfig
	// peerClients holds one verifying http.Client per peer (keyed by
	// trust domain), built from that peer's bundle-endpoint profile.
	// A peer never shares the bare default client: its fetch is
	// authenticated against its own pinned endpoint identity.
	peerClients map[string]*http.Client

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
// and lazily merges in peer bundles once Run has populated them. Each
// peer gets its own verifying http.Client built from its bundle-endpoint
// profile; constructing those clients reads the operator-supplied
// endpoint_ca / endpoint_bundle files, so NewRegistry can fail at
// startup with a clear error instead of silently fetching unverified.
//
// The caller is responsible for invoking Run; Bundles() is safe to call
// before Run completes (it just returns own-only).
func NewRegistry(ownTD spiffeid.TrustDomain, ownBundle []byte, peers []PeerConfig, refresh time.Duration) (*Registry, error) {
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	clients := make(map[string]*http.Client, len(peers))
	for _, p := range peers {
		client, err := buildPeerClient(p)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", p.TrustDomain, err)
		}
		clients[p.TrustDomain] = client
	}
	return &Registry{
		ownTD:             ownTD,
		ownBundle:         ownBundle,
		peers:             peers,
		peerClients:       clients,
		configuredRefresh: refresh,
		peerBundles:       map[string][]byte{},
		peerRefreshHints:  map[string]time.Duration{},
	}, nil
}

// buildPeerClient constructs the verifying http.Client for one peer
// according to its bundle-endpoint authentication profile. http://
// peers (only reachable via the --federation-allow-insecure escape
// hatch, which parseFederatePeers gates) get a plain client with no
// transport verification.
func buildPeerClient(p PeerConfig) (*http.Client, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	// A bundle endpoint is a fixed path; it must never redirect us onto a
	// plaintext leg, which would bypass the per-peer TLS verification that
	// lives on the Transport. Refuse any redirect that leaves https. (A
	// pure network MITM cannot forge this over the authenticated channel,
	// but a malicious/misconfigured peer self-downgrade can.)
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-https %q (federation bundle endpoint must stay on https)", req.URL.Redacted())
		}
		return nil
	}
	u, err := url.Parse(p.URL)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", p.URL, err)
	}
	// Validate the peer trust domain for every profile (it is the bundle
	// map key, and the https_spiffe seed bundle's domain), so a typo fails
	// fast at startup rather than at the first fetch.
	td, err := spiffeid.TrustDomainFromString(p.TrustDomain)
	if err != nil {
		return nil, fmt.Errorf("trust domain %q: %w", p.TrustDomain, err)
	}
	switch u.Scheme {
	case "http":
		// Plaintext, unverified. Only reachable when the operator
		// passed --federation-allow-insecure; the loud warning is
		// emitted at parse time in the CLI.
		return client, nil
	case "https":
		// handled below
	default:
		return nil, fmt.Errorf("unsupported url scheme %q (want https)", u.Scheme)
	}

	profile := p.Profile
	if profile == "" {
		profile = ProfileHTTPSWeb
	}
	switch profile {
	case ProfileHTTPSWeb:
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if p.EndpointCAFile != "" {
			// #nosec G304 -- EndpointCAFile is operator-supplied via --federate-with endpoint_ca, not user input.
			pemBytes, err := os.ReadFile(p.EndpointCAFile)
			if err != nil {
				return nil, fmt.Errorf("read endpoint_ca: %w", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("endpoint_ca %s has no parseable certificates", p.EndpointCAFile)
			}
			tlsCfg.RootCAs = roots
		}
		client.Transport = httpsTransport(tlsCfg)
		return client, nil
	case ProfileHTTPSSPIFFE:
		endpointID, err := spiffeid.FromString(p.EndpointSPIFFEID)
		if err != nil {
			return nil, fmt.Errorf("endpoint_spiffe_id %q: %w", p.EndpointSPIFFEID, err)
		}
		if p.EndpointBundleFile == "" {
			return nil, fmt.Errorf("profile https_spiffe requires endpoint_bundle to seed verification of %s", endpointID)
		}
		bundle, err := x509bundle.Load(td, p.EndpointBundleFile)
		if err != nil {
			return nil, fmt.Errorf("load endpoint_bundle: %w", err)
		}
		if len(bundle.X509Authorities()) == 0 {
			return nil, fmt.Errorf("endpoint_bundle %s has no x509 authorities", p.EndpointBundleFile)
		}
		// tlsconfig builds an InsecureSkipVerify config whose
		// VerifyPeerCertificate checks the endpoint SVID chains to the
		// seeded bundle AND that its URI SAN equals the pinned ID, so
		// hostname/IP in the URL is irrelevant (the SPIFFE ID is the
		// identity). This is the same verification a go-spiffe client
		// would perform.
		tlsCfg := tlsconfig.TLSClientConfig(bundle, tlsconfig.AuthorizeID(endpointID))
		client.Transport = httpsTransport(tlsCfg)
		return client, nil
	default:
		return nil, fmt.Errorf("unknown profile %q (want https_web or https_spiffe)", profile)
	}
}

// httpsTransport clones http.DefaultTransport (keeping its proxy, dialer
// timeouts, keep-alives and HTTP/2 support) and swaps in the per-peer TLS
// config, rather than a bare &http.Transport{} that would drop all those
// defaults.
func httpsTransport(cfg *tls.Config) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = cfg
	return t
}

// clientFor returns the verifying http.Client for a peer trust domain,
// falling back to a default client if (impossibly) absent so a fetch
// never nil-panics.
func (r *Registry) clientFor(trustDomain string) *http.Client {
	if c, ok := r.peerClients[trustDomain]; ok && c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
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
//
// The explicit `<-ctx.Done()` keeps Run's contract intact when no
// peers are configured: WaitGroup.Wait returns immediately on a
// zero counter, so without the ctx receive Run would race ahead of
// its caller's `go fed.Run(ctx)` expectation that it stays alive
// until cancellation.
func (r *Registry) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range r.peers {
		wg.Add(1)
		go func(peer PeerConfig) {
			defer wg.Done()
			r.runPeer(ctx, peer)
		}(p)
	}
	<-ctx.Done()
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
	// peer's bundle. Total sequence is 8.7s, long enough that the
	// time.After leak on cancellation is worth avoiding - use the
	// same NewTimer+Stop dance the steady-state loop uses below.
	for _, d := range []time.Duration{200 * time.Millisecond, 500 * time.Millisecond, 1 * time.Second, 2 * time.Second, 5 * time.Second} {
		if r.peerHasBundle(peer.TrustDomain) {
			break
		}
		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
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
	pemBytes, err = r.fetchPEM(ctx, peer)
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
	resp, err := r.clientFor(peer.TrustDomain).Do(req)
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

func (r *Registry) fetchPEM(ctx context.Context, peer PeerConfig) ([]byte, error) {
	url := strings.TrimRight(peer.URL, "/") + "/v1/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.clientFor(peer.TrustDomain).Do(req)
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
