// Package workloadapi implements the SPIFFE Workload API server side
// that runs inside `omega agent`.
//
// X509: FetchX509SVID attests the peer via UID, looks up the SPIFFE ID
// from the agent's mapping, and serves an X.509-SVID. The first call
// hits the control plane to issue a fresh certificate; subsequent calls
// are served from a per-UID cache. The stream stays open and sends a
// new SVID at the cert's mid-life refresh point.
//
// JWT: FetchJWTSVID forwards an audience-bound JWT-SVID issuance
// request to the control plane and returns one signed JWT per attested
// peer. JWT-SVIDs are not cached (they are short-lived and audience-
// specific). FetchJWTBundles streams the trust domain's JWKS, and
// ValidateJWTSVID verifies a token locally against that JWKS.
package workloadapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/0-draft/omega/internal/agent/attestor"
	"github.com/0-draft/omega/internal/server/api"
)

// Mapping maps a peer UID to the SPIFFE ID the agent will request on
// its behalf. Attestor plugins (K8s SAT, process info, etc.) are
// planned to replace this in a future iteration.
type Mapping map[uint32]string

// svidEntry is one cached, kernel-attested SVID for a UID.
type svidEntry struct {
	spiffeID  string
	svidDER   []byte
	bundleDER []byte
	keyDER    []byte
	notBefore time.Time
	notAfter  time.Time
}

// refreshAt returns the moment past which we should re-issue. We
// refresh at the midpoint of validity so a workload always holds a
// cert with at least ~half its lifetime remaining.
func (e *svidEntry) refreshAt() time.Time {
	return e.notBefore.Add(e.notAfter.Sub(e.notBefore) / 2)
}

func (e *svidEntry) stale(now time.Time) bool {
	return !now.Before(e.refreshAt())
}

// jwksCacheTTL bounds how long the agent serves a stale JWKS to
// `ValidateJWTSVID` and `FetchJWTBundles` callers before re-fetching
// `/v1/jwt/bundle` from the control plane. One minute is a balance
// between picking up CA key rotations promptly (the control plane
// rotates rarely; one-minute lag on rotation is invisible to
// running workloads) and coalescing the burst of validations that
// happens after a workload restart.
const jwksCacheTTL = time.Minute

type Server struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	serverURL  string
	mapping    Mapping
	httpClient *http.Client
	now        func() time.Time

	mu    sync.Mutex
	cache map[uint32]*svidEntry

	// jwksMu guards the JWKS cache. Held for read on cache hits;
	// upgraded to write only across a cache miss + refresh, so
	// concurrent callers that arrive during a refresh serialise
	// behind a single control-plane fetch (no thundering herd).
	jwksMu          sync.RWMutex
	jwksBytes       []byte
	jwksTrustDomain string
	jwksExpiry      time.Time
}

func NewServer(serverURL string, mapping Mapping) *Server {
	return &Server{
		serverURL: strings.TrimRight(serverURL, "/"),
		mapping:   mapping,
		// otelhttp.NewTransport propagates W3C TraceContext from the
		// agent's gRPC span (server-side otelgrpc handler) into the HTTP
		// call to the control plane, so issuance shows as one trace.
		httpClient: &http.Client{Transport: otelhttp.NewTransport(http.DefaultTransport)},
		now:        time.Now,
		cache:      map[uint32]*svidEntry{},
	}
}

func (s *Server) FetchX509SVID(_ *workloadpb.X509SVIDRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	creds, err := credsFromContext(ctx)
	if err != nil {
		return err
	}
	spiffeID, ok := s.mapping[creds.UID]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "no SVID mapping for uid=%d", creds.UID)
	}

	for {
		entry, err := s.getOrRefresh(ctx, creds.UID, spiffeID)
		if err != nil {
			return err
		}
		if err := stream.Send(&workloadpb.X509SVIDResponse{
			Svids: []*workloadpb.X509SVID{{
				SpiffeId:    entry.spiffeID,
				X509Svid:    entry.svidDER,
				X509SvidKey: entry.keyDER,
				Bundle:      entry.bundleDER,
			}},
		}); err != nil {
			return err
		}
		wait := time.Until(entry.refreshAt())
		if wait < time.Second {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func (s *Server) FetchX509Bundles(_ *workloadpb.X509BundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	bundles, err := s.fetchFederationBundles(ctx)
	if err != nil {
		// Older control plane without /v1/federation/bundles: fall back
		// to the single-domain /v1/bundle source so non-federated agents
		// keep working.
		bundleDER, trustDomain, ferr := s.fetchBundle(ctx)
		if ferr != nil {
			return ferr
		}
		bundles = map[string][]byte{trustDomain: bundleDER}
	}
	return stream.Send(&workloadpb.X509BundlesResponse{Bundles: bundles})
}

// FetchJWTSVID issues a single JWT-SVID for the attested peer and the
// requested audience. The peer's SPIFFE ID is taken from the agent's
// mapping; req.SpiffeId, if present, must match.
func (s *Server) FetchJWTSVID(ctx context.Context, req *workloadpb.JWTSVIDRequest) (*workloadpb.JWTSVIDResponse, error) {
	creds, err := credsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	spiffeID, ok := s.mapping[creds.UID]
	if !ok {
		return nil, status.Errorf(codes.PermissionDenied, "no SVID mapping for uid=%d", creds.UID)
	}
	if req.SpiffeId != "" && req.SpiffeId != spiffeID {
		return nil, status.Errorf(codes.PermissionDenied, "spiffe_id %q is not assigned to uid=%d", req.SpiffeId, creds.UID)
	}
	if len(req.Audience) == 0 {
		return nil, status.Error(codes.InvalidArgument, "audience is required")
	}
	// RFC 8705: bind the JWT-SVID to the same X.509-SVID the workload
	// will present over mTLS. We make sure the cert is cached so the
	// workload's first call (X.509 or JWT) primes the entry.
	entry, err := s.getOrRefresh(ctx, creds.UID, spiffeID)
	if err != nil {
		return nil, err
	}
	thumb := certThumbprintS256(entry.svidDER)
	body, err := json.Marshal(api.IssueJWTSVIDRequest{
		SPIFFEID:           spiffeID,
		Audience:           req.Audience,
		BindCertThumbprint: thumb,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal req: %v", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serverURL+"/v1/svid/jwt", bytes.NewReader(body))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "new req: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "control plane: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "control plane %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out api.IssueJWTSVIDResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, status.Errorf(codes.Internal, "decode response: %v", err)
	}
	return &workloadpb.JWTSVIDResponse{
		Svids: []*workloadpb.JWTSVID{{
			SpiffeId: out.SPIFFEID,
			Svid:     out.Token,
		}},
	}, nil
}

// FetchJWTBundles streams the JWKS bundle for the trust domain, fetched
// from the control plane. The current implementation sends one snapshot
// and closes; long-polling for rotation is a planned follow-up.
func (s *Server) FetchJWTBundles(_ *workloadpb.JWTBundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	ctx := stream.Context()
	jwks, td, err := s.cachedFetchJWTBundle(ctx)
	if err != nil {
		return err
	}
	return stream.Send(&workloadpb.JWTBundlesResponse{
		Bundles: map[string][]byte{"spiffe://" + td: jwks},
	})
}

// ValidateJWTSVID verifies the token locally against the JWKS pulled
// from the control plane and returns its SPIFFE ID and claims.
func (s *Server) ValidateJWTSVID(ctx context.Context, req *workloadpb.ValidateJWTSVIDRequest) (*workloadpb.ValidateJWTSVIDResponse, error) {
	if req.Audience == "" {
		return nil, status.Error(codes.InvalidArgument, "audience is required")
	}
	if req.Svid == "" {
		return nil, status.Error(codes.InvalidArgument, "svid is required")
	}
	id, claims, err := validateAgainstJWKS(ctx, s, req.Svid, req.Audience)
	if err != nil {
		return nil, err
	}
	pbClaims, err := structFromMap(claims)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "claims: %v", err)
	}
	return &workloadpb.ValidateJWTSVIDResponse{
		SpiffeId: id,
		Claims:   pbClaims,
	}, nil
}

// getOrRefresh returns a non-stale SVID for the (uid, spiffeID) pair,
// reissuing through the control plane if the cached one is missing or
// past its refresh time. The cache lock is released across the network
// call so a slow control plane doesn't block other UIDs; the cost is
// that two concurrent requests for the same fresh-needed entry may
// both hit the control plane. Acceptable trade-off given how rare a
// concurrent miss for the same uid is in practice.
func (s *Server) getOrRefresh(ctx context.Context, uid uint32, spiffeID string) (*svidEntry, error) {
	s.mu.Lock()
	if entry, ok := s.cache[uid]; ok && entry.spiffeID == spiffeID && !entry.stale(s.now()) {
		s.mu.Unlock()
		return entry, nil
	}
	s.mu.Unlock()

	resp, key, err := s.requestSVID(ctx, spiffeID)
	if err != nil {
		return nil, err
	}
	svidDER, bundleDER, err := pemToDER(resp.SVID, resp.Bundle)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decode pem: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal key: %v", err)
	}
	cert, err := x509.ParseCertificate(svidDER)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "parse svid: %v", err)
	}
	entry := &svidEntry{
		spiffeID:  spiffeID,
		svidDER:   svidDER,
		bundleDER: bundleDER,
		keyDER:    keyDER,
		notBefore: cert.NotBefore,
		notAfter:  cert.NotAfter,
	}
	s.mu.Lock()
	s.cache[uid] = entry
	s.mu.Unlock()
	return entry, nil
}

func (s *Server) requestSVID(ctx context.Context, spiffeID string) (*api.IssueSVIDResponse, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "gen key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, err := json.Marshal(api.IssueSVIDRequest{SPIFFEID: spiffeID, CSR: string(csrPEM)})
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "marshal req: %v", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serverURL+"/v1/svid", bytes.NewReader(body))
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "new req: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "control plane: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, status.Errorf(codes.Internal, "control plane %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out api.IssueSVIDResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "decode response: %v", err)
	}
	return &out, key, nil
}

// fetchFederationBundles asks the control plane for the merged trust
// bundle map (own trust domain + every --federate-with peer that has
// successfully exchanged bundles). Returns ErrNoFederation when the
// control plane does not expose the endpoint so the caller can fall
// back to the single-domain /v1/bundle path.
func (s *Server) fetchFederationBundles(ctx context.Context) (map[string][]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, s.serverURL+"/v1/federation/bundles", nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "new req: %v", err)
	}
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "control plane: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNoFederation
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "federation fetch %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		TrustDomains map[string]string `json:"trust_domains"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, status.Errorf(codes.Internal, "decode federation: %v", err)
	}
	bundles := make(map[string][]byte, len(out.TrustDomains))
	for td, pemStr := range out.TrustDomains {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return nil, status.Errorf(codes.Internal, "federation: trust domain %q has no PEM block", td)
		}
		bundles[td] = block.Bytes
	}
	if len(bundles) == 0 {
		return nil, errNoFederation
	}
	return bundles, nil
}

var errNoFederation = errors.New("control plane has no federation endpoint")

func (s *Server) fetchBundle(ctx context.Context) ([]byte, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, s.serverURL+"/v1/bundle", nil)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "new req: %v", err)
	}
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", status.Errorf(codes.Unavailable, "control plane: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", status.Errorf(codes.Internal, "bundle fetch %d", resp.StatusCode)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, "", status.Error(codes.Internal, "invalid bundle pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "parse bundle: %v", err)
	}
	td := trustDomainFromCertCN(cert.Subject.CommonName)
	return block.Bytes, td, nil
}

// trustDomainFromCertCN reads the trust domain back from the bundle CA
// CN. We currently set CN="Omega Local CA" so this is hard-coded to
// "omega.local"; a dedicated control plane endpoint will replace this
// once the federation hub lands.
func trustDomainFromCertCN(_ string) string {
	return "omega.local"
}

func credsFromContext(ctx context.Context) (attestor.Creds, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return attestor.Creds{}, status.Error(codes.Internal, "no peer info on context")
	}
	creds, ok := attestor.CredsFromAddr(p.Addr)
	if !ok {
		return attestor.Creds{}, status.Error(codes.PermissionDenied, "peer is not UID-attested (not connected via omega agent listener)")
	}
	return creds, nil
}

// cachedFetchJWTBundle returns the trust domain's JWKS and trust
// domain name, serving from an in-memory cache when the previous
// fetch is still within jwksCacheTTL. On a miss it serialises
// concurrent callers behind a single control-plane fetch so
// 100-workload-restarts don't trigger 100 round trips.
func (s *Server) cachedFetchJWTBundle(ctx context.Context) ([]byte, string, error) {
	now := s.now()
	s.jwksMu.RLock()
	if len(s.jwksBytes) > 0 && now.Before(s.jwksExpiry) {
		b, td := s.jwksBytes, s.jwksTrustDomain
		s.jwksMu.RUnlock()
		return b, td, nil
	}
	s.jwksMu.RUnlock()

	s.jwksMu.Lock()
	defer s.jwksMu.Unlock()
	// Double-check: another goroutine may have populated the cache
	// while we were waiting on the write lock.
	if len(s.jwksBytes) > 0 && s.now().Before(s.jwksExpiry) {
		return s.jwksBytes, s.jwksTrustDomain, nil
	}
	body, td, err := s.fetchJWTBundle(ctx)
	if err != nil {
		return nil, "", err
	}
	s.jwksBytes = body
	s.jwksTrustDomain = td
	s.jwksExpiry = s.now().Add(jwksCacheTTL)
	return body, td, nil
}

func (s *Server) fetchJWTBundle(ctx context.Context) ([]byte, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, s.serverURL+"/v1/jwt/bundle", nil)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "new req: %v", err)
	}
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", status.Errorf(codes.Unavailable, "control plane: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", status.Errorf(codes.Internal, "jwt bundle fetch %d", resp.StatusCode)
	}
	_, td, err := s.fetchBundle(ctx)
	if err != nil {
		return nil, "", err
	}
	return body, td, nil
}

func validateAgainstJWKS(ctx context.Context, s *Server, token, audience string) (string, map[string]any, error) {
	jwks, _, err := s.cachedFetchJWTBundle(ctx)
	if err != nil {
		return "", nil, err
	}
	keySet, err := parseJWKS(jwks)
	if err != nil {
		return "", nil, status.Errorf(codes.Internal, "parse jwks: %v", err)
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return "", nil, status.Errorf(codes.InvalidArgument, "parse jwt: %v", err)
	}
	if len(parsed.Headers) == 0 {
		return "", nil, status.Error(codes.InvalidArgument, "jwt has no header")
	}
	kid := parsed.Headers[0].KeyID
	pub, ok := keySet[kid]
	if !ok {
		return "", nil, status.Errorf(codes.PermissionDenied, "unknown kid %q", kid)
	}
	var claims jwt.Claims
	var raw map[string]any
	if err := parsed.Claims(pub, &claims, &raw); err != nil {
		return "", nil, status.Errorf(codes.PermissionDenied, "verify: %v", err)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		AnyAudience: jwt.Audience{audience},
		Time:        time.Now(),
	}, 30*time.Second); err != nil {
		return "", nil, status.Errorf(codes.PermissionDenied, "validate: %v", err)
	}
	return claims.Subject, raw, nil
}

func parseJWKS(raw []byte) (map[string]*ecdsa.PublicKey, error) {
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil {
		return nil, err
	}
	out := make(map[string]*ecdsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk x: %w", err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwk y: %w", err)
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
		out[k.Kid] = pub
	}
	return out, nil
}

func structFromMap(m map[string]any) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	return structpb.NewStruct(m)
}

// certThumbprintS256 is the RFC 8705 cnf.x5t#S256 value: SHA-256 over
// the DER-encoded certificate, base64url without padding.
func certThumbprintS256(certDER []byte) string {
	sum := sha256.Sum256(certDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pemToDER(svidPEM, bundlePEM string) (svidDER, bundleDER []byte, err error) {
	sb, _ := pem.Decode([]byte(svidPEM))
	if sb == nil {
		return nil, nil, errors.New("svid pem")
	}
	bb, _ := pem.Decode([]byte(bundlePEM))
	if bb == nil {
		return nil, nil, errors.New("bundle pem")
	}
	return sb.Bytes, bb.Bytes, nil
}

var _ workloadpb.SpiffeWorkloadAPIServer = (*Server)(nil)
