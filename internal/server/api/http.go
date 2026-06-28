// Package api exposes the Omega control plane over HTTP/JSON. The
// surface is intentionally small: net/http + encoding/json so the
// reference implementation stays auditable. AuthZEN evaluation lives
// at /access/v1/evaluation; the gRPC Workload API is served separately
// from the agent process.
package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/kanywst/omega/internal/server/attest"
	"github.com/kanywst/omega/internal/server/federation"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/metrics"
	"github.com/kanywst/omega/internal/server/oidc"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
	"github.com/kanywst/omega/internal/server/tracing"
)

var tracer = tracing.Tracer("github.com/kanywst/omega/internal/server/api")

// errIssuanceDisabledUpstream is surfaced (501) on the issuance and
// token-exchange routes when the server runs in spire-upstream identity
// mode: there is no local CA, so SVIDs come from the upstream SPIFFE
// issuer and Omega serves only the authorization + audit layer.
var errIssuanceDisabledUpstream = errors.New("issuance disabled: omega is in spire-upstream identity mode; obtain SVIDs from the upstream SPIFFE issuer")

type Server struct {
	store                   *storage.Store
	ca                      identity.Source
	policy                  *policy.Engine
	federation              *federation.Registry
	enforceExchangePolicy   bool
	k8sAttestor             *attest.K8sAttestor
	k8sSVIDTemplate         string
	oidc                    *oidc.Registry
	spiffeBundleRefreshHint time.Duration
	requireAuth             bool
}

// NewServer takes an issuing Authority for backward compatibility and
// adapts it to the identity-source seam via identity.AsSource, so an
// upstream-SPIFFE Source can be wired in later without touching the
// handlers, which only ever call the embedded Authority method set.
func NewServer(store *storage.Store, ca identity.Authority, pdp *policy.Engine) *Server {
	return &Server{store: store, ca: identity.AsSource(ca), policy: pdp}
}

// WithFederation wires a federation registry into the server. Passing
// nil disables the /v1/federation/bundles endpoint (it returns 404).
func (s *Server) WithFederation(reg *federation.Registry) *Server {
	s.federation = reg
	return s
}

// WithEnforceTokenExchangePolicy turns on AuthZEN evaluation for
// POST /v1/token/exchange. When enabled the handler builds a
// `{action: token.exchange}` request whose subject carries kind /
// acting_for / delegation_chain / scope attrs and whose context carries
// delegation_depth + requested_audience, then routes the decision
// through the configured policy engine. When disabled (default) the
// handler keeps the lightweight `requested == actor` check as the sole
// gate, for operators who have not yet authored token-exchange
// policies.
func (s *Server) WithEnforceTokenExchangePolicy(v bool) *Server {
	s.enforceExchangePolicy = v
	return s
}

// WithK8sAttestor wires a TokenReview-backed attestor and the SPIFFE
// ID template used to derive the issued SPIFFE ID from the validated
// `(namespace, serviceaccount[, podname])` triple. Passing a nil
// attestor (or an empty template) leaves `POST /v1/attest/k8s`
// disabled - it returns 404.
func (s *Server) WithK8sAttestor(a *attest.K8sAttestor, template string) *Server {
	s.k8sAttestor = a
	s.k8sSVIDTemplate = template
	return s
}

// WithSPIFFEBundleRefreshHint sets the `spiffe_refresh_hint` field of
// the SPIFFE Trust Domain Format document served at
// `GET /v1/spiffe-bundle`. The value is the recommended minimum
// interval before peers should re-fetch the bundle. A non-positive
// duration falls back to the default (300s) so callers that wire
// `WithSPIFFEBundleRefreshHint(0)` get the default rather than a doc
// that tells peers to poll continuously.
func (s *Server) WithSPIFFEBundleRefreshHint(d time.Duration) *Server {
	s.spiffeBundleRefreshHint = d
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Each route is wrapped per-pattern: metrics.InstrumentHandler tags
	// the route label, then otelhttp.NewHandler wraps that and emits one
	// server span per request named after the registered pattern. We do
	// this per-route (rather than wrapping the mux) so the span name and
	// http.route attribute match the registered Go 1.22 ServeMux pattern
	// - wrapping the bare mux loses the pattern because otelhttp runs
	// before mux dispatch sets r.Pattern.
	handle := func(pattern string, h http.HandlerFunc) {
		instrumented := metrics.InstrumentHandler(pattern, h)
		mux.Handle(pattern, otelhttp.NewHandler(instrumented, pattern))
	}
	// Endpoints whose handler ends up calling AppendAudit / CreateDomain
	// are wrapped with leaderOnly so that, when the Postgres advisory
	// lock has been promised to a different replica, this process fails
	// fast with 503 + Retry-After instead of hitting ErrNotLeader deeper
	// in the call stack.
	leaderOnly := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !s.store.IsLeader() {
				w.Header().Set("Retry-After", "1")
				writeErr(w, http.StatusServiceUnavailable, storage.ErrNotLeader)
				return
			}
			h(w, r)
		}
	}
	// gated wraps the write / PDP / issuance surface with both the HA
	// leader gate and (when --require-auth is on) caller authentication.
	// The leader gate runs first so a follower answers 503 with the usual
	// Retry-After before any auth check — a client (or leader-routing load
	// balancer) that hit the wrong replica learns to reroute without
	// having to present a client cert just to discover it. Auth is still
	// enforced on the leader, the only replica that serves writes.
	gated := func(h http.HandlerFunc) http.HandlerFunc {
		return leaderOnly(s.requireSPIFFEAuth(h))
	}
	// issuingOnly fails an issuance / token-exchange route with 501 when
	// the server runs in spire-upstream identity mode (no local CA). It is
	// the outermost wrapper so the route reports "not supported here"
	// regardless of leader state or auth - it is a property of the mode,
	// not of this request.
	issuingOnly := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.ca.SourceKind() == identity.SourceSPIREUpstream {
				writeErr(w, http.StatusNotImplemented, errIssuanceDisabledUpstream)
				return
			}
			h(w, r)
		}
	}
	handle("GET /healthz", s.healthz)
	handle("GET /v1/leader", s.leaderState)
	handle("POST /v1/domains", gated(s.createDomain))
	handle("GET /v1/domains", s.listDomains)
	handle("GET /v1/domains/{name}", s.getDomain)
	handle("POST /v1/svid", issuingOnly(gated(s.issueSVID)))
	// The attestation enrollment paths (POST /v1/attest/k8s and
	// POST /v1/oidc/exchange) carry their own platform-rooted / external-
	// IdP proof and are how a workload obtains its *first* SVID, so they
	// are gated by the leader check only, not by requireSPIFFEAuth -
	// requiring an Omega client SVID here would break the bootstrap
	// chicken-and-egg the trust-model design (#83) calls out. They derive
	// identity from validated input, never a caller-asserted spiffe_id.
	handle("POST /v1/attest/k8s", issuingOnly(leaderOnly(s.attestK8s)))
	handle("GET /v1/bundle", s.getBundle)
	handle("GET /v1/spiffe-bundle", s.getSPIFFEBundle)
	handle("POST /access/v1/evaluation", gated(s.evaluateAccess))
	handle("POST /access/v1/evaluations", gated(s.evaluateAccessBatch))
	handle("POST /access/v1/search/subject", gated(s.searchSubject))
	handle("POST /access/v1/search/resource", gated(s.searchResource))
	handle("POST /access/v1/search/action", gated(s.searchAction))
	// Audit reads expose every decision's subject and full request /
	// response payload, so when --require-auth is on they are closed to
	// authenticated callers too. They are NOT leader-gated (reads are
	// served by followers), hence requireSPIFFEAuth alone, not gated.
	handle("GET /v1/audit", s.requireSPIFFEAuth(s.listAudit))
	handle("GET /v1/audit/verify", s.requireSPIFFEAuth(s.verifyAudit))
	handle("POST /v1/svid/jwt", issuingOnly(gated(s.issueJWTSVID)))
	handle("POST /v1/token/exchange", issuingOnly(gated(s.tokenExchange)))
	handle("POST /v1/oidc/exchange", issuingOnly(leaderOnly(s.exchangeOIDC)))
	handle("GET /v1/jwt/bundle", s.getJWTBundle)
	handle("GET /v1/federation/bundles", s.getFederationBundles)
	handle("GET /.well-known/openid-configuration", s.getOIDCDiscovery)
	handle("GET /.well-known/authzen-configuration", s.getAuthzenDiscovery)
	mux.Handle("GET /metrics", metrics.Handler())
	return mux
}

// LeaderStateResponse is the shape of GET /v1/leader. Operators and
// load balancers use it to route writes only to the current leader; the
// payload is intentionally tiny so a probe over a slow link still
// converges fast.
type LeaderStateResponse struct {
	IsLeader bool `json:"is_leader"`
}

func (s *Server) leaderState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, LeaderStateResponse{IsLeader: s.store.IsLeader()})
}

// FederationBundlesResponse is the shape of GET /v1/federation/bundles.
// Keys are SPIFFE trust domain names (no scheme), values are PEM-encoded
// X.509 trust anchor bundles. The map always includes this server's own
// trust domain; peers configured via --federate-with appear once their
// bundles have been fetched at least once.
type FederationBundlesResponse struct {
	TrustDomains map[string]string `json:"trust_domains"`
}

func (s *Server) getFederationBundles(w http.ResponseWriter, _ *http.Request) {
	if s.federation == nil {
		writeErr(w, http.StatusNotFound, errors.New("federation is not configured on this server"))
		return
	}
	raw := s.federation.Bundles()
	out := make(map[string]string, len(raw))
	for td, pem := range raw {
		out[td] = string(pem)
	}
	writeJSON(w, http.StatusOK, FederationBundlesResponse{TrustDomains: out})
}

type IssueJWTSVIDRequest struct {
	SPIFFEID   string   `json:"spiffe_id"`
	Audience   []string `json:"audience"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	// BindCertThumbprint, if set, embeds an RFC 8705 cnf.x5t#S256 claim
	// that binds the issued JWT-SVID to the SHA-256 thumbprint of the
	// client X.509-SVID. Encoded as base64url (no padding).
	BindCertThumbprint string `json:"bind_cert_thumbprint,omitempty"`
}

type IssueJWTSVIDResponse struct {
	Token     string    `json:"token"`
	SPIFFEID  string    `json:"spiffe_id"`
	Audience  []string  `json:"audience"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID     string    `json:"kid"`
}

func (s *Server) issueJWTSVID(w http.ResponseWriter, r *http.Request) {
	var req IssueJWTSVIDRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	id, err := spiffeid.FromString(req.SPIFFEID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("spiffe_id: %w", err))
		return
	}
	if !s.authorizeIssuance(w, r, id.String()) {
		return
	}
	if len(req.Audience) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("audience is required"))
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	var extra map[string]any
	if req.BindCertThumbprint != "" {
		extra = map[string]any{
			"cnf": map[string]string{"x5t#S256": req.BindCertThumbprint},
		}
	}
	_, issueSpan := tracer.Start(r.Context(), "ca.IssueJWTSVID",
		trace.WithAttributes(
			attribute.String("spiffe.id", id.String()),
			attribute.StringSlice("jwt.audience", req.Audience),
			attribute.Bool("rfc8705.bound", req.BindCertThumbprint != ""),
		),
	)
	svid, err := s.ca.IssueJWTSVID(id, req.Audience, ttl, extra)
	if err != nil {
		issueSpan.RecordError(err)
		issueSpan.SetStatus(codes.Error, "issue jwt svid")
		issueSpan.End()
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	issueSpan.SetAttributes(attribute.String("jwt.kid", svid.KeyID))
	issueSpan.End()
	metrics.SVIDIssued.WithLabelValues("jwt").Inc()
	auditPayload := map[string]any{
		"audience":   svid.Audience,
		"kid":        svid.KeyID,
		"issued_at":  svid.IssuedAt,
		"expires_at": svid.ExpiresAt,
	}
	if req.BindCertThumbprint != "" {
		auditPayload["cnf_x5t_s256"] = req.BindCertThumbprint
	}
	s.audit(r.Context(), storage.AuditEvent{
		Kind:     "svid.issue.jwt",
		Subject:  svid.SPIFFEID,
		Decision: "ok",
		Payload:  mustJSON(auditPayload),
	})
	writeJSON(w, http.StatusOK, IssueJWTSVIDResponse{
		Token:     svid.Token,
		SPIFFEID:  svid.SPIFFEID,
		Audience:  svid.Audience,
		IssuedAt:  svid.IssuedAt,
		ExpiresAt: svid.ExpiresAt,
		KeyID:     svid.KeyID,
	})
}

// OIDCDiscoveryResponse is the minimal OIDC 1.0 discovery document
// Omega exposes at /.well-known/openid-configuration when the
// authority was constructed with a non-empty Issuer. The fields are
// the subset required by relying parties that only verify
// JWT-SVIDs (AWS IAM OIDC trust, GCP Workload Identity Federation,
// Kubernetes ServiceAccount issuer trust). Omega is not an
// interactive OIDC IdP, so authorization_endpoint / token_endpoint
// / userinfo_endpoint are intentionally omitted.
type OIDCDiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

func (s *Server) getOIDCDiscovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.ca.IssuerURL()
	if iss == "" {
		writeErr(w, http.StatusNotFound, errors.New("OIDC discovery is disabled (start omega server with --issuer-url)"))
		return
	}
	writeJSON(w, http.StatusOK, OIDCDiscoveryResponse{
		Issuer:                           iss,
		JWKSURI:                          iss + "/v1/jwt/bundle",
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"ES256"},
	})
}

// AuthzenDiscoveryResponse is the discovery document advertised at
// /.well-known/authzen-configuration. The shape matches OpenID AuthZEN
// 1.0 §8: `policy_decision_point` is the PDP base; only the endpoints
// Omega actually implements are advertised. The three Search API
// endpoints (`subject_search_endpoint`, `resource_search_endpoint`,
// `action_search_endpoint`) are present because Omega ships
// candidate-set-based Search; the deviation from the spec's pattern
// shape is documented on the search handlers themselves.
type AuthzenDiscoveryResponse struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint"`
	SubjectSearchEndpoint     string `json:"subject_search_endpoint"`
	ResourceSearchEndpoint    string `json:"resource_search_endpoint"`
	ActionSearchEndpoint      string `json:"action_search_endpoint"`
}

func (s *Server) getAuthzenDiscovery(w http.ResponseWriter, _ *http.Request) {
	// The PDP base URL must be the operator-configured issuer URL:
	// `--issuer-url` is validated to be https + no query/fragment at
	// startup, and using a single, canonical source prevents a PEP
	// from being pointed at an attacker-controlled URL through a
	// spoofed Host header. Mirrors getOIDCDiscovery: when the
	// authority was constructed without an issuer, discovery is
	// disabled and returns 404.
	base := s.ca.IssuerURL()
	if base == "" {
		writeErr(w, http.StatusNotFound, errors.New("AuthZEN discovery is disabled (start omega server with --issuer-url)"))
		return
	}
	writeJSON(w, http.StatusOK, AuthzenDiscoveryResponse{
		PolicyDecisionPoint:       base,
		AccessEvaluationEndpoint:  base + "/access/v1/evaluation",
		AccessEvaluationsEndpoint: base + "/access/v1/evaluations",
		SubjectSearchEndpoint:     base + "/access/v1/search/subject",
		ResourceSearchEndpoint:    base + "/access/v1/search/resource",
		ActionSearchEndpoint:      base + "/access/v1/search/action",
	})
}

func (s *Server) getJWTBundle(w http.ResponseWriter, _ *http.Request) {
	raw, err := s.ca.JWTBundle()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// audit emits one audit_log row. Failures are logged but never block the
// caller's response - the HTTP request has already succeeded by the time
// audit is called.
func (s *Server) audit(ctx context.Context, ev storage.AuditEvent) {
	ctx, span := tracer.Start(ctx, "audit.append",
		trace.WithAttributes(
			attribute.String("audit.kind", ev.Kind),
			attribute.String("audit.subject", ev.Subject),
			attribute.String("audit.decision", ev.Decision),
		),
	)
	defer span.End()
	if _, err := s.store.AppendAudit(ctx, ev); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "audit append failed")
		slog.Error("audit append failed", "kind", ev.Kind, "err", err)
		return
	}
	metrics.AuditAppended.WithLabelValues(ev.Kind).Inc()
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) {
	var d storage.Domain
	if !decodeJSONBody(w, r, &d) {
		return
	}
	created, err := s.store.CreateDomain(r.Context(), d)
	switch {
	case errors.Is(err, storage.ErrAlreadyExists):
		writeErr(w, http.StatusConflict, err)
	case err != nil:
		writeErr(w, http.StatusBadRequest, err)
	default:
		metrics.DomainsCreated.Inc()
		s.audit(r.Context(), storage.AuditEvent{
			Kind:     "domain.create",
			Subject:  created.Name,
			Decision: "ok",
			Payload:  mustJSON(created),
		})
		writeJSON(w, http.StatusCreated, created)
	}
}

func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDomain(r.Context(), r.PathValue("name"))
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListDomains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if items == nil {
		items = []storage.Domain{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type IssueSVIDRequest struct {
	SPIFFEID string `json:"spiffe_id"`
	CSR      string `json:"csr"`
}

type IssueSVIDResponse struct {
	SVID      string    `json:"svid"`
	Bundle    string    `json:"bundle"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) issueSVID(w http.ResponseWriter, r *http.Request) {
	var req IssueSVIDRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	id, err := spiffeid.FromString(req.SPIFFEID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("spiffe_id: %w", err))
		return
	}
	if !s.authorizeIssuance(w, r, id.String()) {
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		writeErr(w, http.StatusBadRequest, errors.New("csr: invalid PEM"))
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("csr: parse: %w", err))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("csr: signature: %w", err))
		return
	}
	_, issueSpan := tracer.Start(r.Context(), "ca.IssueSVID",
		trace.WithAttributes(attribute.String("spiffe.id", id.String())),
	)
	svid, err := s.ca.IssueSVID(id, csr)
	if err != nil {
		issueSpan.RecordError(err)
		issueSpan.SetStatus(codes.Error, "issue x509 svid")
		issueSpan.End()
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	issueSpan.SetAttributes(attribute.String("svid.not_after", svid.NotAfter.Format(time.RFC3339)))
	issueSpan.End()
	metrics.SVIDIssued.WithLabelValues("x509").Inc()
	s.audit(r.Context(), storage.AuditEvent{
		Kind:     "svid.issue.x509",
		Subject:  id.String(),
		Decision: "ok",
		Payload: mustJSON(map[string]any{
			"not_before": svid.NotBefore,
			"not_after":  svid.NotAfter,
		}),
	})
	writeJSON(w, http.StatusOK, IssueSVIDResponse{
		SVID:      string(svid.CertPEM),
		Bundle:    string(svid.BundlePEM),
		ExpiresAt: svid.NotAfter,
	})
}

// K8sAttestRequest is the request body for POST /v1/attest/k8s. The
// token is a Kubernetes ServiceAccount projected token (issued with an
// `audience` matching what omega was started with); the CSR is the
// usual PEM-encoded x509 CertificateRequest used by every other SVID
// issuance path.
type K8sAttestRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

// K8sAttestResponse mirrors IssueSVIDResponse and additionally
// surfaces the SPIFFE ID derived from the token claims, so the
// workload does not have to parse the certificate to learn its own
// identity.
type K8sAttestResponse struct {
	SPIFFEID  string    `json:"spiffe_id"`
	SVID      string    `json:"svid"`
	Bundle    string    `json:"bundle"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) attestK8s(w http.ResponseWriter, r *http.Request) {
	if s.k8sAttestor == nil || s.k8sSVIDTemplate == "" {
		writeErr(w, http.StatusNotFound, errors.New("k8s attestation is not configured on this server (start omega server with --k8s-attest=true and --k8s-svid-template=...)"))
		return
	}
	var req K8sAttestRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	claims, err := s.k8sAttestor.Attest(r.Context(), req.Token)
	if err != nil {
		// Distinguish a real token rejection (audited as deny, 401)
		// from an apiserver / network failure (502, no audit row -
		// it is not a security event, and counting it as deny would
		// skew the rejection rate operators chart against).
		if errors.Is(err, attest.ErrTokenRejected) {
			s.audit(r.Context(), storage.AuditEvent{
				Kind:     "attest.k8s",
				Decision: "deny",
				Payload:  mustJSON(map[string]string{"error": err.Error()}),
			})
			writeErr(w, http.StatusUnauthorized, err)
			return
		}
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	idStr, err := attest.RenderSPIFFEID(s.k8sSVIDTemplate, claims)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	id, err := spiffeid.FromString(idStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("rendered spiffe id %q invalid: %w", idStr, err))
		return
	}
	if !id.MemberOf(s.ca.TrustDomain()) {
		writeErr(w, http.StatusBadRequest,
			fmt.Errorf("rendered spiffe id %q is not in trust domain %q (check --k8s-svid-template)", id, s.ca.TrustDomain()))
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		writeErr(w, http.StatusBadRequest, errors.New("csr: invalid PEM"))
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("csr: parse: %w", err))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("csr: signature: %w", err))
		return
	}
	svid, err := s.ca.IssueSVID(id, csr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	metrics.SVIDIssued.WithLabelValues("x509").Inc()
	s.audit(r.Context(), storage.AuditEvent{
		Kind:     "attest.k8s",
		Subject:  id.String(),
		Decision: "ok",
		Payload: mustJSON(map[string]any{
			"namespace":       claims.Namespace,
			"service_account": claims.ServiceAccount,
			"pod_name":        claims.PodName,
			"audiences":       claims.Audiences,
			"not_after":       svid.NotAfter,
		}),
	})
	writeJSON(w, http.StatusOK, K8sAttestResponse{
		SPIFFEID:  id.String(),
		SVID:      string(svid.CertPEM),
		Bundle:    string(svid.BundlePEM),
		ExpiresAt: svid.NotAfter,
	})
}

func (s *Server) evaluateAccess(w http.ResponseWriter, r *http.Request) {
	var req policy.EvalRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	_, evalSpan := tracer.Start(r.Context(), "policy.Evaluate",
		trace.WithAttributes(
			attribute.String("authzen.subject.id", req.Subject.ID),
			attribute.String("authzen.subject.type", req.Subject.Type),
			attribute.String("authzen.action", req.Action.Name),
			attribute.String("authzen.resource.type", req.Resource.Type),
			attribute.String("authzen.resource.id", req.Resource.ID),
		),
	)
	start := time.Now()
	resp, err := s.policy.Evaluate(req)
	metrics.DecisionLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		evalSpan.RecordError(err)
		evalSpan.SetStatus(codes.Error, "evaluate")
		evalSpan.End()
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	decision := "deny"
	if resp.Decision {
		decision = "allow"
	}
	evalSpan.SetAttributes(
		attribute.String("authzen.decision", decision),
		attribute.StringSlice("authzen.reasons", resp.Reasons),
	)
	evalSpan.End()
	metrics.Decisions.WithLabelValues(decision).Inc()
	s.audit(r.Context(), storage.AuditEvent{
		Kind:     "access.evaluate",
		Subject:  req.Subject.ID,
		Decision: decision,
		Payload: mustJSON(map[string]any{
			"request":  req,
			"response": resp,
		}),
	})
	writeJSON(w, http.StatusOK, resp)
}

// BatchEvalSubrequest is one entry in a POST /access/v1/evaluations
// request body. Each field is optional: when omitted, the request
// inherits the top-level default from BatchEvalRequest.
type BatchEvalSubrequest struct {
	Subject  *policy.Entity `json:"subject,omitempty"`
	Action   *policy.Action `json:"action,omitempty"`
	Resource *policy.Entity `json:"resource,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

// BatchEvalRequest is the request body for POST /access/v1/evaluations
// (AuthZEN 1.0 §5.2). Top-level subject/action/resource/context act as
// defaults that every entry in `evaluations` inherits unless the entry
// overrides them. The most common use is "one subject, many resources"
// or "one subject, many actions" - the caller fills in the constant
// fields at the top and varies only the differing one per sub-request.
type BatchEvalRequest struct {
	Subject     *policy.Entity        `json:"subject,omitempty"`
	Action      *policy.Action        `json:"action,omitempty"`
	Resource    *policy.Entity        `json:"resource,omitempty"`
	Context     map[string]any        `json:"context,omitempty"`
	Evaluations []BatchEvalSubrequest `json:"evaluations"`
}

// BatchEvalResponse mirrors AuthZEN 1.0 §5.2: a parallel array of
// per-evaluation decisions in the same order as the request.
type BatchEvalResponse struct {
	Evaluations []policy.EvalResponse `json:"evaluations"`
}

// MaxBatchEvaluations caps the number of sub-requests one batch may
// carry. AuthZEN 1.0 §5.2 does not mandate a value, but every batch
// evaluation request holds the audit-log mutex for the duration of
// its processing (see evaluateAccessBatch and audit.AppendAudit), so
// an unbounded batch is a DoS surface against the hash-chain writer.
// 100 is in line with peer implementations (AVP: 30, Aserto: 50,
// Topaz: 100); operators who need more should fan out batches on
// the client. Exposing a flag is on the roadmap if the limit
// becomes a real friction point.
const MaxBatchEvaluations = 100

// evaluateAccessBatch implements the AuthZEN 1.0 batch endpoint.
// Each sub-request inherits defaults from the top-level fields, is
// validated as a complete EvalRequest, evaluated through the same
// PDP path as single evaluation, and audited per-decision so the
// hash chain records one row per decision (matching what callers
// already see when they fan out single calls themselves).
func (s *Server) evaluateAccessBatch(w http.ResponseWriter, r *http.Request) {
	var req BatchEvalRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if n := len(req.Evaluations); n > MaxBatchEvaluations {
		writeErr(w, http.StatusBadRequest,
			fmt.Errorf("batch too large: %d evaluations (max %d); fan out on the client", n, MaxBatchEvaluations))
		return
	}
	// Capture the context returned by tracer.Start so per-evaluation
	// spans (policy.Evaluate, audit.append) nest under this batch
	// span instead of becoming siblings of it.
	ctx, batchSpan := tracer.Start(r.Context(), "policy.EvaluateBatch",
		trace.WithAttributes(
			attribute.Int("authzen.batch.size", len(req.Evaluations)),
		),
	)
	defer batchSpan.End()

	// NOTE on serial processing: each sub-request appends one audit
	// row, and AppendAudit serialises on a process-wide mutex so the
	// hash-chain prev_hash lookup and INSERT are atomic. Batch latency
	// therefore grows linearly with N (the response is held until the
	// last audit row commits). The MaxBatchEvaluations cap bounds the
	// worst case; a true throughput optimisation would be a bulk
	// AppendAudit at the storage layer, tracked as a follow-up.
	out := BatchEvalResponse{Evaluations: make([]policy.EvalResponse, 0, len(req.Evaluations))}
	for i, sub := range req.Evaluations {
		merged, err := mergeBatchEval(req, sub)
		if err != nil {
			batchSpan.RecordError(err)
			batchSpan.SetStatus(codes.Error, "merge")
			writeErr(w, http.StatusBadRequest, fmt.Errorf("evaluations[%d]: %w", i, err))
			return
		}
		start := time.Now()
		resp, err := s.policy.Evaluate(merged)
		metrics.DecisionLatency.Observe(time.Since(start).Seconds())
		if err != nil {
			batchSpan.RecordError(err)
			batchSpan.SetStatus(codes.Error, "evaluate")
			writeErr(w, http.StatusBadRequest, fmt.Errorf("evaluations[%d]: %w", i, err))
			return
		}
		decision := "deny"
		if resp.Decision {
			decision = "allow"
		}
		metrics.Decisions.WithLabelValues(decision).Inc()
		s.audit(ctx, storage.AuditEvent{
			Kind:     "access.evaluate",
			Subject:  merged.Subject.ID,
			Decision: decision,
			Payload: mustJSON(map[string]any{
				"request":  merged,
				"response": resp,
				"batch":    map[string]any{"index": i, "size": len(req.Evaluations)},
			}),
		})
		out.Evaluations = append(out.Evaluations, resp)
	}
	writeJSON(w, http.StatusOK, out)
}

// mergeBatchEval applies per-evaluation overrides on top of the
// batch-level defaults and returns a complete EvalRequest. Missing
// required fields after merging are a validation error: the spec
// expects every evaluation to resolve to a full request.
func mergeBatchEval(top BatchEvalRequest, sub BatchEvalSubrequest) (policy.EvalRequest, error) {
	pick := func(override, def *policy.Entity) *policy.Entity {
		if override != nil {
			return override
		}
		return def
	}
	pickAction := func(override, def *policy.Action) *policy.Action {
		if override != nil {
			return override
		}
		return def
	}
	subject := pick(sub.Subject, top.Subject)
	action := pickAction(sub.Action, top.Action)
	resource := pick(sub.Resource, top.Resource)
	if subject == nil {
		return policy.EvalRequest{}, errors.New("subject is required (no default at top level, no override on this evaluation)")
	}
	if action == nil {
		return policy.EvalRequest{}, errors.New("action is required")
	}
	if resource == nil {
		return policy.EvalRequest{}, errors.New("resource is required")
	}
	ctx := top.Context
	if sub.Context != nil {
		ctx = sub.Context
	}
	return policy.EvalRequest{
		Subject:  *subject,
		Action:   *action,
		Resource: *resource,
		Context:  ctx,
	}, nil
}

// AuthZEN 1.0 §5.3 Search APIs.
//
// The spec's Search request describes a partially-specified target
// (e.g. `subject: {type: "user"}` with no id) and leaves candidate
// enumeration to the PDP. omega's default PDP is Cedar, which has no
// global principal / resource / action directory - omega therefore
// cannot enumerate candidates on its own and the spec (§5.3.2)
// explicitly tells PDPs to error when they cannot resolve a search.
//
// To make the endpoints useful in practice rather than just spec-
// compliantly returning errors, omega accepts an explicit candidate
// list in the request:
//
//	{
//	  "candidates": [ {entity}, ... ],   // the dimension being searched
//	  "subject":    {entity},            // the two other dimensions are
//	  "action":     {action},            // fully specified
//	  "resource":   {entity},
//	  "context":    {...},
//	  "page":       {"size": N, "offset": M}
//	}
//
// For each candidate, omega builds a complete EvalRequest, runs it
// through the same PDP path as `POST /access/v1/evaluation`, and
// returns only those candidates whose decision is `allow`. Pagination
// is offset/size; opaque tokens add no value when the caller already
// supplies the candidate list.
//
// Every candidate evaluation is audited the same way single
// evaluations are, so the hash chain records one row per decision
// the PDP made on behalf of this Search.

// SearchPage controls the optional offset/size pagination on Search
// responses. The spec defines opaque `next_token` pagination; we use
// offsets because omega's candidate set is supplied by the caller and
// is already enumerable.
type SearchPage struct {
	Size      int    `json:"size,omitempty"`
	Offset    int    `json:"offset,omitempty"`
	NextToken string `json:"next_token,omitempty"`
}

// MaxSearchCandidates caps the per-request candidate list. Each
// candidate runs a full PDP evaluation and emits one audit row, so
// the bound prevents a single Search from monopolising the hash-chain
// writer. Same rationale as MaxBatchEvaluations; same value.
const MaxSearchCandidates = 100

// SubjectSearchRequest is the request body for
// `POST /access/v1/search/subject`. `subjects` is the candidate list
// of subjects to test against the (action, resource) pair.
type SubjectSearchRequest struct {
	Subjects []policy.Entity `json:"subjects"`
	Action   policy.Action   `json:"action"`
	Resource policy.Entity   `json:"resource"`
	Context  map[string]any  `json:"context,omitempty"`
	Page     *SearchPage     `json:"page,omitempty"`
}

// ResourceSearchRequest mirrors SubjectSearchRequest with the search
// dimension on `resources` instead.
type ResourceSearchRequest struct {
	Resources []policy.Entity `json:"resources"`
	Subject   policy.Entity   `json:"subject"`
	Action    policy.Action   `json:"action"`
	Context   map[string]any  `json:"context,omitempty"`
	Page      *SearchPage     `json:"page,omitempty"`
}

// ActionSearchRequest searches over a candidate list of action names
// against the same (subject, resource) pair.
type ActionSearchRequest struct {
	Actions  []policy.Action `json:"actions"`
	Subject  policy.Entity   `json:"subject"`
	Resource policy.Entity   `json:"resource"`
	Context  map[string]any  `json:"context,omitempty"`
	Page     *SearchPage     `json:"page,omitempty"`
}

// SubjectSearchResponse / ResourceSearchResponse / ActionSearchResponse
// each carry the matched candidates. AuthZEN §5.3.4 names the field
// `results`.
type SubjectSearchResponse struct {
	Results []policy.Entity `json:"results"`
	Page    *SearchPage     `json:"page,omitempty"`
}

type ResourceSearchResponse struct {
	Results []policy.Entity `json:"results"`
	Page    *SearchPage     `json:"page,omitempty"`
}

type ActionSearchResponse struct {
	Results []policy.Action `json:"results"`
	Page    *SearchPage     `json:"page,omitempty"`
}

func (s *Server) searchSubject(w http.ResponseWriter, r *http.Request) {
	var req SubjectSearchRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if len(req.Subjects) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("subjects: candidate list is required (omega's PDP cannot enumerate principals)"))
		return
	}
	if len(req.Subjects) > MaxSearchCandidates {
		writeErr(w, http.StatusBadRequest,
			fmt.Errorf("subjects: too many candidates: %d (max %d); fan out on the client", len(req.Subjects), MaxSearchCandidates))
		return
	}
	ctx, span := tracer.Start(r.Context(), "policy.SearchSubject",
		trace.WithAttributes(
			attribute.Int("authzen.search.candidates", len(req.Subjects)),
			attribute.String("authzen.action", req.Action.Name),
			attribute.String("authzen.resource.type", req.Resource.Type),
			attribute.String("authzen.resource.id", req.Resource.ID),
		),
	)
	defer span.End()

	matched := make([]policy.Entity, 0, len(req.Subjects))
	for i := range req.Subjects {
		eval := policy.EvalRequest{
			Subject:  req.Subjects[i],
			Action:   req.Action,
			Resource: req.Resource,
			Context:  req.Context,
		}
		decision, ok := s.evaluateForSearch(ctx, eval, span, "subject", i)
		if !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("subjects[%d]: evaluation failed", i))
			return
		}
		if decision {
			matched = append(matched, req.Subjects[i])
		}
	}
	results, page := paginate(matched, req.Page)
	writeJSON(w, http.StatusOK, SubjectSearchResponse{Results: results, Page: page})
}

func (s *Server) searchResource(w http.ResponseWriter, r *http.Request) {
	var req ResourceSearchRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if len(req.Resources) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("resources: candidate list is required"))
		return
	}
	if len(req.Resources) > MaxSearchCandidates {
		writeErr(w, http.StatusBadRequest,
			fmt.Errorf("resources: too many candidates: %d (max %d); fan out on the client", len(req.Resources), MaxSearchCandidates))
		return
	}
	ctx, span := tracer.Start(r.Context(), "policy.SearchResource",
		trace.WithAttributes(
			attribute.Int("authzen.search.candidates", len(req.Resources)),
			attribute.String("authzen.subject.id", req.Subject.ID),
			attribute.String("authzen.subject.type", req.Subject.Type),
			attribute.String("authzen.action", req.Action.Name),
		),
	)
	defer span.End()

	matched := make([]policy.Entity, 0, len(req.Resources))
	for i := range req.Resources {
		eval := policy.EvalRequest{
			Subject:  req.Subject,
			Action:   req.Action,
			Resource: req.Resources[i],
			Context:  req.Context,
		}
		decision, ok := s.evaluateForSearch(ctx, eval, span, "resource", i)
		if !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("resources[%d]: evaluation failed", i))
			return
		}
		if decision {
			matched = append(matched, req.Resources[i])
		}
	}
	results, page := paginate(matched, req.Page)
	writeJSON(w, http.StatusOK, ResourceSearchResponse{Results: results, Page: page})
}

func (s *Server) searchAction(w http.ResponseWriter, r *http.Request) {
	var req ActionSearchRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if len(req.Actions) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("actions: candidate list is required"))
		return
	}
	if len(req.Actions) > MaxSearchCandidates {
		writeErr(w, http.StatusBadRequest,
			fmt.Errorf("actions: too many candidates: %d (max %d); fan out on the client", len(req.Actions), MaxSearchCandidates))
		return
	}
	ctx, span := tracer.Start(r.Context(), "policy.SearchAction",
		trace.WithAttributes(
			attribute.Int("authzen.search.candidates", len(req.Actions)),
			attribute.String("authzen.subject.id", req.Subject.ID),
			attribute.String("authzen.resource.type", req.Resource.Type),
			attribute.String("authzen.resource.id", req.Resource.ID),
		),
	)
	defer span.End()

	matched := make([]policy.Action, 0, len(req.Actions))
	for i := range req.Actions {
		eval := policy.EvalRequest{
			Subject:  req.Subject,
			Action:   req.Actions[i],
			Resource: req.Resource,
			Context:  req.Context,
		}
		decision, ok := s.evaluateForSearch(ctx, eval, span, "action", i)
		if !ok {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("actions[%d]: evaluation failed", i))
			return
		}
		if decision {
			matched = append(matched, req.Actions[i])
		}
	}
	results, page := paginate(matched, req.Page)
	writeJSON(w, http.StatusOK, ActionSearchResponse{Results: results, Page: page})
}

// evaluateForSearch runs one candidate through the PDP and emits an
// audit row. Returns (decision, ok). On evaluation error it records
// the failure on the parent span and returns false so the caller can
// short-circuit with a 400. The audit kind is the same `access.evaluate`
// the single and batch endpoints use, with a `search` discriminator
// in the payload so operators can grep by API surface.
func (s *Server) evaluateForSearch(ctx context.Context, eval policy.EvalRequest, span trace.Span, dimension string, index int) (bool, bool) {
	start := time.Now()
	resp, err := s.policy.Evaluate(eval)
	metrics.DecisionLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "evaluate")
		return false, false
	}
	decision := "deny"
	if resp.Decision {
		decision = "allow"
	}
	metrics.Decisions.WithLabelValues(decision).Inc()
	s.audit(ctx, storage.AuditEvent{
		Kind:     "access.evaluate",
		Subject:  eval.Subject.ID,
		Decision: decision,
		Payload: mustJSON(map[string]any{
			"request":  eval,
			"response": resp,
			"search":   map[string]any{"dimension": dimension, "index": index},
		}),
	})
	return resp.Decision, true
}

// paginate applies the request's offset/size to a matched-candidate
// list and returns the slice plus the page envelope echoed back to
// the caller (with a next_token marker when more results remain).
// Generic over the candidate element type so subject/resource/action
// search all share one implementation.
func paginate[T any](matched []T, page *SearchPage) ([]T, *SearchPage) {
	offset, size := 0, len(matched)
	if page != nil {
		if page.Offset > 0 {
			offset = page.Offset
		}
		if page.Size > 0 && page.Size < size-offset {
			size = page.Size
		} else {
			size = max(0, len(matched)-offset)
		}
	}
	if offset >= len(matched) {
		return []T{}, &SearchPage{Size: 0, Offset: offset}
	}
	end := min(offset+size, len(matched))
	out := SearchPage{Size: size, Offset: offset}
	if end < len(matched) {
		out.NextToken = fmt.Sprintf("offset:%d", end)
	}
	return matched[offset:end], &out
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.ListAudit(r.Context(), since, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if events == nil {
		events = []storage.AuditEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": events})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	// Optional external checkpoint: ?expected_head=<hash>&expected_count=<n>
	// lets a caller pin the chain so tail truncation below the anchor is
	// reported. Both must be present to anchor; otherwise the walk is
	// unanchored (truncation above the live tail is invisible, as before).
	var anchor *storage.AuditAnchor
	head := r.URL.Query().Get("expected_head")
	countStr := r.URL.Query().Get("expected_count")
	if (head != "") != (countStr != "") {
		// Only one of the pair was supplied. Anchoring needs both; silently
		// falling back to an unanchored walk would skip the truncation
		// check the caller asked for, so reject instead.
		writeErr(w, http.StatusBadRequest, errors.New("expected_head and expected_count must be provided together for anchored verification"))
		return
	}
	if head != "" {
		count, err := strconv.ParseInt(countStr, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("expected_count must be an integer: %w", err))
			return
		}
		if count < 0 {
			// A negative anchor count can never exceed the live row count,
			// so the truncation check would silently never fire. Reject it.
			writeErr(w, http.StatusBadRequest, errors.New("expected_count must be non-negative"))
			return
		}
		anchor = &storage.AuditAnchor{HeadHash: head, Count: count}
	}

	res, err := s.store.VerifyAudit(r.Context(), anchor)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	// Response shape is extended, not broken: `valid` and `first_bad_seq`
	// keep their meaning; `truncated`, `count`, and `head_hash` are added.
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":         res.Valid,
		"first_bad_seq": res.FirstBadSeq,
		"truncated":     res.Truncated,
		"count":         res.Count,
		"head_hash":     res.HeadHash,
	})
}

func (s *Server) getBundle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.ca.BundlePEM())
}

// defaultSPIFFEBundleRefreshHint mirrors the SPIRE default. The spec
// itself says nothing about a default value and lets peers fall back
// to their own polling cadence, but a stated value helps callers that
// honour the hint converge faster than the conservative defaults they
// would otherwise pick.
const defaultSPIFFEBundleRefreshHint = 5 * time.Minute

// getSPIFFEBundle serves the SPIFFE Trust Domain Format JSON document
// (SPIFFE Trust Domain and Bundle 1.0 §4). The document carries both
// the X.509-SVID trust anchors and the JWT-SVID public keys in one
// JWK set, each tagged with `use` so a single endpoint replaces the
// pair of `/v1/bundle` (PEM) + `/v1/jwt/bundle` (JWKS) for SPIFFE-
// native consumers.
//
// `spiffe_sequence` is fixed to 1 today; omega does not yet rotate the
// X.509 root or the JWT signing key at runtime, so the bundle is in
// fact monotonic-at-one for the lifetime of a server process. A real
// counter lands with key rotation.
func (s *Server) getSPIFFEBundle(w http.ResponseWriter, _ *http.Request) {
	hint := s.spiffeBundleRefreshHint
	if hint <= 0 {
		hint = defaultSPIFFEBundleRefreshHint
	}
	raw, err := identity.BuildSPIFFEBundle(s.ca, identity.SPIFFEBundleOptions{
		Sequence:    1,
		RefreshHint: hint,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// maxJSONBodyBytes caps the size of any JSON request body the API will
// read. 1 MiB is two orders of magnitude above the largest realistic
// payload (even a 50-group OIDC token or a batch of 100 evaluations is
// a few KiB) and bounds the memory an abusive caller can force omega to
// buffer.
const maxJSONBodyBytes = 1 << 20

// decodeJSONBody reads and decodes a single JSON value from the request
// body with the body size capped at maxJSONBodyBytes via
// http.MaxBytesReader. It writes the error response itself (413 when the
// cap is exceeded, 400 for malformed JSON) and returns false so the
// caller can simply `return`. Every JSON-decoding handler routes through
// this so no endpoint can be used as a memory-exhaustion DoS surface.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, fmt.Errorf("request body too large (max %d bytes)", maxJSONBodyBytes))
			return false
		}
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
