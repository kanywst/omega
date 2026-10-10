package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/metrics"
	"github.com/kanywst/omega/internal/server/oidc"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant), RFC 7523,
// and SPIFFE client authentication (draft-ietf-oauth-spiffe-client-auth).
const (
	grantTypeJWTBearer        = "urn:ietf:params:oauth:grant-type:jwt-bearer"            // #nosec G101 -- RFC 7523 grant-type URN
	grantProfileIDJAG         = "urn:ietf:params:oauth:grant-profile:id-jag"             // #nosec G101 -- grant-profile URN
	clientAssertionTypeSPIFFE = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe" // #nosec G101 -- client-assertion-type URN
	authMethodSPIFFEX509      = "spiffe_x509"
	authMethodSPIFFEJWT       = "spiffe_jwt"

	IDJAGTyp                    = "oauth-id-jag+jwt"
	actionIDJAG                 = "token.id_jag"
	DefaultIDJAGMaxAssertionTTL = 5 * time.Minute

	maxFormBodyBytes = 64 << 10
)

// IDJAGConfig wires the ID-JAG grant. Registry entries must set
// RequiredTyp = IDJAGTyp, ExactAudience, and omega's issuer URL as the
// only audience. MTLSClientAuth and JWTClientAuth say which client
// authentication methods the listener lets through, for the metadata.
type IDJAGConfig struct {
	Registry        *oidc.Registry
	MaxAssertionTTL time.Duration
	MTLSClientAuth  bool
	JWTClientAuth   bool
}

// WithIDJAG enables POST /oauth2/token and the RFC 8414 metadata.
// A nil Registry leaves both returning 404.
func (s *Server) WithIDJAG(cfg IDJAGConfig) *Server {
	s.idJAG = cfg.Registry
	s.idJAGMaxAssertionTTL = cfg.MaxAssertionTTL
	if s.idJAGMaxAssertionTTL <= 0 {
		s.idJAGMaxAssertionTTL = DefaultIDJAGMaxAssertionTTL
	}
	s.idJAGMTLS = cfg.MTLSClientAuth
	s.idJAGJWT = cfg.JWTClientAuth
	return s
}

// OAuthTokenResponse is the RFC 6749 §5.1 response plus the granted
// resource and the SPIFFE metadata other issuance endpoints return.
type OAuthTokenResponse struct {
	AccessToken     string   `json:"access_token"`
	TokenType       string   `json:"token_type"`
	ExpiresIn       int      `json:"expires_in"`
	Scope           string   `json:"scope,omitempty"`
	Resource        []string `json:"resource"`
	SPIFFEID        string   `json:"spiffe_id"`
	DelegationChain []string `json:"delegation_chain"`
	KeyID           string   `json:"kid"`
}

type oauthError struct {
	status int
	code   string
	desc   string
}

func (e *oauthError) Error() string { return e.code + ": " + e.desc }

func newOAuthErr(status int, code, format string, args ...any) *oauthError {
	return &oauthError{status: status, code: code, desc: fmt.Sprintf(format, args...)}
}

func writeOAuthErr(w http.ResponseWriter, e *oauthError) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, e.status, map[string]string{"error": e.code, "error_description": e.desc})
}

// oauthToken accepts an ID-JAG as an RFC 7523 jwt-bearer assertion from
// a SPIFFE-authenticated client and issues the client a JWT-SVID whose
// `act` names the asserted user, so /v1/token/exchange can extend it.
func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	if s.idJAG == nil {
		writeErr(w, http.StatusNotFound, errors.New("the ID-JAG grant is not configured on this server (start omega server with at least one --id-jag-idp)"))
		return
	}
	issuer := s.ca.IssuerURL()
	if issuer == "" {
		writeOAuthErr(w, newOAuthErr(http.StatusInternalServerError, "server_error", "omega has no issuer URL; the ID-JAG grant requires --issuer-url"))
		return
	}
	form, oerr := parseTokenForm(w, r)
	if oerr != nil {
		writeOAuthErr(w, oerr)
		return
	}
	if form.Get("grant_type") != grantTypeJWTBearer {
		writeOAuthErr(w, newOAuthErr(http.StatusBadRequest, "unsupported_grant_type", "grant_type must be %q", grantTypeJWTBearer))
		return
	}

	// Unauthenticated requests are not audited, so they cannot grow the
	// chain; the route's request metrics still count the 401s.
	clientID, authMethod, oerr := s.authenticateSPIFFEClient(r, form, issuer)
	if oerr != nil {
		writeOAuthErr(w, oerr)
		return
	}

	// Every refusal from here on is an authenticated client's ID-JAG
	// attempt and is audited.
	client := clientID.String()
	var user string
	audit := map[string]any{"client_auth": authMethod}
	fail := func(e *oauthError, detail string) {
		audit["error"] = e.code
		if detail != "" {
			audit["detail"] = detail
		}
		s.auditIDJAG(r, "deny", client, user, audit)
		writeOAuthErr(w, e)
	}
	assertion := form.Get("assertion")
	if assertion == "" {
		fail(newOAuthErr(http.StatusBadRequest, "invalid_request", "assertion is required"), "")
		return
	}

	claims, err := s.idJAG.ValidateByIssuer(r.Context(), assertion)
	if err != nil {
		// The detail stays in the audit log: echoing it would reveal which
		// issuers omega trusts, which the metadata deliberately hides.
		fail(newOAuthErr(http.StatusBadRequest, "invalid_grant", "assertion could not be validated"), err.Error())
		return
	}
	audit["idp"] = claims.IDPName
	audit["upstream_iss"] = claims.Issuer
	audit["upstream_sub"] = claims.Subject
	if oerr := s.checkIDJAGClaims(claims, clientID); oerr != nil {
		fail(oerr, "")
		return
	}
	jti, _ := claims.Raw["jti"].(string)
	audit["jti"] = jti

	// A cnf.jkt assertion is redeemable only with a DPoP proof for that
	// key; any valid proof binds the issued token to its key.
	boundJKT, err := confirmationJKT(claims.Raw)
	if err != nil {
		fail(newOAuthErr(http.StatusBadRequest, "invalid_grant", "%s", err), "")
		return
	}
	var proofJKT string
	if boundJKT != "" || len(r.Header.Values("DPoP")) > 0 {
		if len(r.Header.Values("DPoP")) == 0 {
			fail(newOAuthErr(http.StatusBadRequest, "invalid_grant", "the assertion is DPoP-bound and no DPoP proof was sent"), "")
			return
		}
		proofJKT, err = s.verifyDPoPProof(r, issuer+"/oauth2/token")
		if err != nil {
			fail(newOAuthErr(http.StatusBadRequest, "invalid_dpop_proof", "%s", err), "")
			return
		}
		if boundJKT != "" && proofJKT != boundJKT {
			fail(newOAuthErr(http.StatusBadRequest, "invalid_grant", "DPoP proof key does not match the assertion's cnf.jkt"), "")
			return
		}
		audit["dpop_jkt"] = proofJKT
	}

	resources, oerr := grantedResources(claims.Raw, form["resource"])
	if oerr != nil {
		fail(oerr, "")
		return
	}
	scope, oerr := grantedScope(claims.Raw, form.Get("scope"))
	if oerr != nil {
		fail(oerr, "")
		return
	}
	audit["resource"] = resources
	audit["scope"] = scope

	cfg, err := s.idJAG.Lookup(claims.IDPName)
	if err != nil {
		fail(newOAuthErr(http.StatusInternalServerError, "server_error", "idp lookup failed"), err.Error())
		return
	}
	userID, err := renderUserID(cfg.SPIFFEIDTemplate, claims, s.ca.TrustDomain())
	if err != nil {
		fail(newOAuthErr(http.StatusBadRequest, "invalid_grant", "%s", err), "")
		return
	}
	user = userID.String()
	chain := []string{user, client}
	audit["chain"] = chain

	// Always gated, under its own action so that existing token.exchange
	// permits cannot authorize it: Cedar's default deny applies until an
	// operator writes a token.id_jag permit.
	{
		resp, err := s.policy.Evaluate(policy.EvalRequest{
			Subject: policy.Entity{
				Type: "Spiffe",
				ID:   client,
				Attrs: map[string]any{
					"kind":             inferKind(clientID),
					"acting_for":       user,
					"delegation_chain": chain,
					"scope":            scope,
				},
			},
			Action:   policy.Action{Name: actionIDJAG},
			Resource: policy.Entity{Type: "Spiffe", ID: client},
			Context: map[string]any{
				"delegation_depth":   1,
				"requested_audience": resources,
				"idp":                claims.IDPName,
			},
		})
		if err != nil {
			fail(newOAuthErr(http.StatusInternalServerError, "server_error", "policy evaluation failed"), err.Error())
			return
		}
		if len(resp.Reasons) > 0 {
			audit["reasons"] = resp.Reasons
		}
		if !resp.Decision {
			audit["policy"] = "deny"
			fail(newOAuthErr(http.StatusBadRequest, "invalid_grant", "denied by policy"), "")
			return
		}
	}
	audit["policy"] = "allow"

	// Like /v1/token/exchange, the delegated token never outlives the grant.
	ttl := time.Until(claims.ExpiresAt)
	if ttl <= 0 {
		fail(newOAuthErr(http.StatusBadRequest, "invalid_grant", "assertion has expired"), "")
		return
	}
	extra := map[string]any{
		"act": map[string]any{
			"sub":          user,
			"kind":         "id-jag",
			"idp":          claims.IDPName,
			"upstream_iss": claims.Issuer,
			"upstream_sub": claims.Subject,
			"jti":          jti,
		},
	}
	if scope != "" {
		extra["scope"] = scope
	}
	tokenType := "Bearer"
	if proofJKT != "" {
		extra["cnf"] = map[string]any{"jkt": proofJKT}
		tokenType = "DPoP"
	}
	svid, err := s.ca.IssueJWTSVID(clientID, resources, ttl, extra)
	if err != nil {
		fail(newOAuthErr(http.StatusBadRequest, "invalid_request", "%s", err), "")
		return
	}
	audit["ttl_seconds"] = int(ttl / time.Second)
	audit["kid"] = svid.KeyID
	// The token is released only once its grant is on the audit chain.
	if err := s.appendAudit(r.Context(), idJAGEvent("allow", client, user, audit)); err != nil {
		writeOAuthErr(w, newOAuthErr(http.StatusInternalServerError, "server_error", "could not record the grant"))
		return
	}
	metrics.SVIDIssued.WithLabelValues("jwt-id-jag").Inc()

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, OAuthTokenResponse{
		AccessToken:     svid.Token,
		TokenType:       tokenType,
		ExpiresIn:       int(ttl / time.Second),
		Scope:           scope,
		Resource:        svid.Audience,
		SPIFFEID:        svid.SPIFFEID,
		DelegationChain: chain,
		KeyID:           svid.KeyID,
	})
}

func renderUserID(template string, claims *oidc.Claims, td spiffeid.TrustDomain) (spiffeid.ID, error) {
	str, err := oidc.RenderSPIFFEID(template, claims)
	if err != nil {
		return spiffeid.ID{}, err
	}
	id, err := spiffeid.FromString(str)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("rendered spiffe id %q invalid: %w", str, err)
	}
	if !id.MemberOf(td) {
		return spiffeid.ID{}, fmt.Errorf("rendered spiffe id %q is not in trust domain %q", id, td)
	}
	return id, nil
}

func (s *Server) auditIDJAG(r *http.Request, decision, client, user string, payload map[string]any) {
	s.audit(r.Context(), idJAGEvent(decision, client, user, payload))
}

func idJAGEvent(decision, client, user string, payload map[string]any) storage.AuditEvent {
	return storage.AuditEvent{
		Kind:     "token.id_jag",
		Actor:    client,
		Subject:  user,
		Decision: decision,
		Payload:  mustJSON(payload),
	}
}

// parseTokenForm reads the body only; every parameter except the
// repeatable RFC 8707 `resource` must appear at most once.
func parseTokenForm(w http.ResponseWriter, r *http.Request) (url.Values, *oauthError) {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if ct != "application/x-www-form-urlencoded" {
		return nil, newOAuthErr(http.StatusBadRequest, "invalid_request", "content type must be application/x-www-form-urlencoded")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		return nil, newOAuthErr(http.StatusBadRequest, "invalid_request", "invalid form body: %s", err)
	}
	for k, v := range r.PostForm {
		if k != "resource" && len(v) > 1 {
			return nil, newOAuthErr(http.StatusBadRequest, "invalid_request", "parameter %q is repeated", k)
		}
	}
	return r.PostForm, nil
}

// authenticateSPIFFEClient accepts exactly one of spiffe_x509 (verified
// mTLS client SVID) or spiffe_jwt (JWT-SVID client_assertion whose sole
// aud is omega's issuer). spiffe_jwt binds the client only under
// --require-auth, where a JWT-SVID without act can come from the client
// alone; reaching it there needs --client-cert-optional.
func (s *Server) authenticateSPIFFEClient(r *http.Request, form url.Values, issuer string) (spiffeid.ID, string, *oauthError) {
	assertionType := form.Get("client_assertion_type")
	assertion := form.Get("client_assertion")
	hasCert := r.TLS != nil && len(r.TLS.VerifiedChains) > 0

	var (
		id     spiffeid.ID
		method string
	)
	switch {
	case assertionType != "" || assertion != "":
		if hasCert {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusBadRequest, "invalid_request", "use one client authentication method: mTLS or client_assertion, not both")
		}
		if assertionType != clientAssertionTypeSPIFFE {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion_type must be %q", clientAssertionTypeSPIFFE)
		}
		if assertion == "" {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion is required")
		}
		parsed, claims, err := s.ca.ParseJWTSVIDClaims(assertion)
		if err != nil {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion: %s", err)
		}
		exp, okExp := claimExpiry(claims)
		iat, okIat := claimNumericDate(claims, "iat")
		if !okExp || !okIat {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion must carry iat and exp")
		}
		if jti, _ := claims["jti"].(string); jti == "" {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion must carry jti")
		}
		if life := exp.Sub(iat); life > s.idJAGMaxAssertionTTL {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion lifetime %s exceeds the accepted maximum %s", life, s.idJAGMaxAssertionTTL)
		}
		if aud := audienceValues(claims["aud"]); len(aud) != 1 || aud[0] != issuer {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion aud must be exactly %q", issuer)
		}
		// A delegated or cert-bound JWT-SVID is not the client's own
		// credential and must not authenticate it as a bearer.
		if _, ok := claims["act"]; ok {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion must not carry act")
		}
		if _, ok := claims["cnf"]; ok {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_assertion must not carry cnf")
		}
		id, method = parsed, authMethodSPIFFEJWT
	case hasCert:
		str, err := spiffeIDFromTLS(r.TLS)
		if err != nil {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "%s", err)
		}
		parsed, err := spiffeid.FromString(str)
		if err != nil {
			return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "%s", err)
		}
		id, method = parsed, authMethodSPIFFEX509
	default:
		return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client authentication is required (mTLS X.509-SVID or a jwt-spiffe client_assertion)")
	}
	if !id.MemberOf(s.ca.TrustDomain()) {
		return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client %q is not in trust domain %q", id, s.ca.TrustDomain())
	}
	if cid := form.Get("client_id"); cid != "" && cid != id.String() {
		return spiffeid.ID{}, "", newOAuthErr(http.StatusUnauthorized, "invalid_client", "client_id %q does not match the authenticated SPIFFE ID %q", cid, id)
	}
	return id, method, nil
}

// checkIDJAGClaims applies the profile rules the registry does not.
func (s *Server) checkIDJAGClaims(c *oidc.Claims, client spiffeid.ID) *oauthError {
	if c.Subject == "" {
		return newOAuthErr(http.StatusBadRequest, "invalid_grant", "assertion has no sub claim")
	}
	if jti, _ := c.Raw["jti"].(string); jti == "" {
		return newOAuthErr(http.StatusBadRequest, "invalid_grant", "assertion has no jti claim")
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() {
		return newOAuthErr(http.StatusBadRequest, "invalid_grant", "assertion must carry both iat and exp")
	}
	if life := c.ExpiresAt.Sub(c.IssuedAt); life > s.idJAGMaxAssertionTTL {
		return newOAuthErr(http.StatusBadRequest, "invalid_grant", "assertion lifetime %s exceeds the accepted maximum %s", life, s.idJAGMaxAssertionTTL)
	}
	// The client's identifier at omega is its SPIFFE ID.
	if cid, _ := c.Raw["client_id"].(string); cid != client.String() {
		return newOAuthErr(http.StatusBadRequest, "invalid_grant", "assertion client_id %q does not match the authenticated client %q", cid, client)
	}
	return nil
}

// grantedResources narrows the assertion's resources to the requested
// RFC 8707 subset. An assertion that names no resource grants none: the
// issued JWT-SVID's audience must come from the IdP's decision.
func grantedResources(raw map[string]any, requested []string) ([]string, *oauthError) {
	granted := audienceValues(raw["resource"])
	if len(granted) == 0 {
		return nil, newOAuthErr(http.StatusBadRequest, "invalid_target", "the assertion grants no resource")
	}
	for _, res := range requested {
		if !slices.Contains(granted, res) {
			return nil, newOAuthErr(http.StatusBadRequest, "invalid_target", "resource %q is not granted by the assertion", res)
		}
	}
	if len(requested) > 0 {
		return requested, nil
	}
	return granted, nil
}

func grantedScope(raw map[string]any, requested string) (string, *oauthError) {
	granted, _ := raw["scope"].(string)
	if requested == "" {
		return granted, nil
	}
	have := strings.Fields(granted)
	for _, sc := range strings.Fields(requested) {
		if !slices.Contains(have, sc) {
			return "", newOAuthErr(http.StatusBadRequest, "invalid_scope", "scope %q is not granted by the assertion", sc)
		}
	}
	return strings.Join(strings.Fields(requested), " "), nil
}

// audienceValues normalises a string-or-array claim.
func audienceValues(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}

// OAuthASMetadata is the RFC 8414 document. Trusted issuers are
// deliberately not listed.
type OAuthASMetadata struct {
	Issuer                              string   `json:"issuer"`
	TokenEndpoint                       string   `json:"token_endpoint"`
	JWKSURI                             string   `json:"jwks_uri"`
	GrantTypesSupported                 []string `json:"grant_types_supported"`
	AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported"`
	TokenEndpointAuthMethodsSupported   []string `json:"token_endpoint_auth_methods_supported"`
	DPoPSigningAlgValuesSupported       []string `json:"dpop_signing_alg_values_supported"`
}

func (s *Server) getOAuthASMetadata(w http.ResponseWriter, _ *http.Request) {
	iss := s.ca.IssuerURL()
	if s.idJAG == nil || iss == "" || s.ca.SourceKind() == identity.SourceSPIREUpstream {
		writeErr(w, http.StatusNotFound, errors.New("OAuth authorization server metadata is served only when the ID-JAG grant is configured (--id-jag-idp with --issuer-url)"))
		return
	}
	var methods []string
	if s.idJAGMTLS {
		methods = append(methods, authMethodSPIFFEX509)
	}
	if s.idJAGJWT {
		methods = append(methods, authMethodSPIFFEJWT)
	}
	writeJSON(w, http.StatusOK, OAuthASMetadata{
		Issuer:                              iss,
		TokenEndpoint:                       iss + "/oauth2/token",
		JWKSURI:                             iss + "/v1/jwt/bundle",
		GrantTypesSupported:                 []string{grantTypeJWTBearer},
		AuthorizationGrantProfilesSupported: []string{grantProfileIDJAG},
		TokenEndpointAuthMethodsSupported:   methods,
		DPoPSigningAlgValuesSupported:       dpopAlgNames(),
	})
}
