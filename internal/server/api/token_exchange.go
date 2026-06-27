package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/metrics"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// RFC 8693 grant- and token-type identifiers we recognise. The current
// implementation accepts the JWT subject/actor token type only;
// OIDC id_token / SAML2 / X.509 token types are not implemented yet.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- RFC 8693 grant-type URN
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"            // #nosec G101 -- RFC 8693 token-type URN
)

// TokenExchangeRequest is the JSON shape of POST /v1/token/exchange.
// We use JSON (not RFC 8693's form-encoded variant) for consistency
// with the rest of the Omega API. Field names mirror the RFC so SDKs
// can keep them as-is.
type TokenExchangeRequest struct {
	GrantType         string   `json:"grant_type"`
	SubjectToken      string   `json:"subject_token"`
	SubjectTokenType  string   `json:"subject_token_type"`
	ActorToken        string   `json:"actor_token"`
	ActorTokenType    string   `json:"actor_token_type"`
	RequestedSPIFFEID string   `json:"requested_spiffe_id"`
	Audience          []string `json:"audience"`
	Scope             string   `json:"scope,omitempty"`
	TTLSeconds        int      `json:"ttl_seconds,omitempty"`
}

// TokenExchangeResponse keeps the RFC 8693 token-response fields
// (`access_token`, `issued_token_type`, `token_type`, `expires_in`,
// `scope`) and adds SPIFFE-specific metadata so callers don't have to
// re-parse the JWT to learn its sub / aud / kid. `delegation_chain`
// is the flattened root → leaf list of subjects, derived from the
// token's nested `act` claim.
type TokenExchangeResponse struct {
	AccessToken     string   `json:"access_token"`
	IssuedTokenType string   `json:"issued_token_type"`
	TokenType       string   `json:"token_type"`
	ExpiresIn       int      `json:"expires_in"`
	Scope           string   `json:"scope,omitempty"`
	SPIFFEID        string   `json:"spiffe_id"`
	Audience        []string `json:"audience"`
	DelegationChain []string `json:"delegation_chain"`
	KeyID           string   `json:"kid"`
}

// tokenExchange implements POST /v1/token/exchange. Both subject and
// actor tokens are JWT-SVIDs we issued ourselves. The output token's
// nested `act` claim follows RFC 8693 §4.1: `sub` is the actor that
// is now authorised, `act` carries the principal claims object copied
// verbatim from the subject token (so multi-hop chains preserve
// every prior `act` nesting).
func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request) {
	var req TokenExchangeRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.GrantType != grantTypeTokenExchange {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("grant_type must be %q", grantTypeTokenExchange))
		return
	}
	if req.SubjectToken == "" || req.SubjectTokenType != tokenTypeJWT {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("subject_token (type=%q) is required", tokenTypeJWT))
		return
	}
	if req.ActorToken == "" || req.ActorTokenType != tokenTypeJWT {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("actor_token (type=%q) is required", tokenTypeJWT))
		return
	}
	if req.RequestedSPIFFEID == "" {
		writeErr(w, http.StatusBadRequest, errors.New("requested_spiffe_id is required"))
		return
	}
	if len(req.Audience) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("audience is required"))
		return
	}

	subjectID, subjectClaims, err := s.ca.ParseJWTSVIDClaims(req.SubjectToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("subject_token: %w", err))
		return
	}
	actorID, _, err := s.ca.ParseJWTSVIDClaims(req.ActorToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("actor_token: %w", err))
		return
	}

	requestedID, err := spiffeid.FromString(req.RequestedSPIFFEID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("requested_spiffe_id: %w", err))
		return
	}
	if !requestedID.MemberOf(s.ca.TrustDomain()) {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("requested_spiffe_id %q not in trust domain %q", requestedID, s.ca.TrustDomain()))
		return
	}
	// Hard-coded baseline: an agent can only request a delegated token
	// whose `sub` equals its own SPIFFE ID. This prevents impersonation
	// independent of policy configuration. When the AuthZEN gate is
	// enabled (WithEnforceTokenExchangePolicy) Cedar evaluates further
	// constraints on top of this baseline.
	if requestedID.String() != actorID.String() {
		writeErr(w, http.StatusForbidden,
			fmt.Errorf("requested_spiffe_id %q must match actor_token sub %q", requestedID, actorID))
		return
	}

	// Build the new act claim: `sub` = subject token's sub, then copy
	// the subject token's own `act` (if any) so prior chain segments
	// stay nested. RFC 8693 §4.1 says act is "the party that is
	// delegating authority" - for u-alice → claude-code → sub-agent
	// the new token has sub=sub-agent, act={sub:claude-code,
	// act:{sub:u-alice}}.
	newAct := map[string]any{"sub": subjectID.String()}
	if priorAct, ok := subjectClaims["act"].(map[string]any); ok {
		newAct["act"] = priorAct
	}

	chain := flattenActChain(newAct) // root → leaf
	chain = append(chain, requestedID.String())

	// AuthZEN gate. Off by default so existing callers who have not yet
	// authored token-exchange policies keep the baseline `requested ==
	// actor` rule above as the sole check. When enabled the policy
	// engine has the final say - Cedar's default-deny applies, so a
	// permit policy targeting `Action::"token.exchange"` is required to
	// allow any exchange.
	policyDecision := "skipped"
	var policyReasons []string
	if s.enforceExchangePolicy {
		evalReq := policy.EvalRequest{
			Subject: policy.Entity{
				Type: "Spiffe",
				ID:   requestedID.String(),
				Attrs: map[string]any{
					"kind":             inferKind(requestedID),
					"acting_for":       chain[0],
					"delegation_chain": chain,
					"scope":            req.Scope,
				},
			},
			Action: policy.Action{Name: "token.exchange"},
			Resource: policy.Entity{
				Type: "Spiffe",
				ID:   requestedID.String(),
			},
			Context: map[string]any{
				"delegation_depth":   len(chain) - 1,
				"requested_audience": req.Audience,
			},
		}
		resp, err := s.policy.Evaluate(evalReq)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Errorf("policy: %w", err))
			return
		}
		policyReasons = resp.Reasons
		if resp.Decision {
			policyDecision = "allow"
		} else {
			s.audit(r.Context(), storage.AuditEvent{
				Kind:     "token.exchange",
				Actor:    requestedID.String(),
				Subject:  chain[0],
				Decision: "deny",
				Payload: mustJSON(map[string]any{
					"chain":              chain,
					"requested_audience": req.Audience,
					"scope":              req.Scope,
					"actor":              actorID.String(),
					"policy":             "deny",
					"reasons":            policyReasons,
				}),
			})
			writeErr(w, http.StatusForbidden,
				fmt.Errorf("token-exchange denied by policy: reasons=%v", policyReasons))
			return
		}
	}

	ttl := time.Duration(req.TTLSeconds) * time.Second
	if subjectExp, ok := claimExpiry(subjectClaims); ok {
		// Output TTL must not exceed the subject token's remaining life,
		// otherwise the delegated authority outlives the principal.
		remaining := time.Until(subjectExp)
		if remaining <= 0 {
			writeErr(w, http.StatusBadRequest, errors.New("subject_token has expired"))
			return
		}
		if ttl <= 0 || ttl > remaining {
			ttl = remaining
		}
	}

	extra := map[string]any{"act": newAct}
	if req.Scope != "" {
		extra["scope"] = req.Scope
	}

	svid, err := s.ca.IssueJWTSVID(requestedID, req.Audience, ttl, extra)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	metrics.SVIDIssued.WithLabelValues("jwt-exchange").Inc()

	auditPayload := map[string]any{
		"chain":              chain,
		"requested_audience": svid.Audience,
		"scope":              req.Scope,
		"ttl_seconds":        int(ttl / time.Second),
		"kid":                svid.KeyID,
		"actor":              actorID.String(),
		"policy":             policyDecision,
	}
	if len(policyReasons) > 0 {
		auditPayload["reasons"] = policyReasons
	}
	rootSubject := chain[0]
	s.audit(r.Context(), storage.AuditEvent{
		Kind:     "token.exchange",
		Actor:    requestedID.String(),
		Subject:  rootSubject,
		Decision: "allow",
		Payload:  mustJSON(auditPayload),
	})

	writeJSON(w, http.StatusOK, TokenExchangeResponse{
		AccessToken:     svid.Token,
		IssuedTokenType: tokenTypeJWT,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl / time.Second),
		Scope:           req.Scope,
		SPIFFEID:        svid.SPIFFEID,
		Audience:        svid.Audience,
		DelegationChain: chain,
		KeyID:           svid.KeyID,
	})
}

// flattenActChain walks an RFC 8693 nested `act` object outward-in
// (innermost = root principal, outermost = most recent actor) and
// returns subjects in root → leaf order. Tokens that lack an act
// claim (a fresh subject token) yield a single-element slice.
func flattenActChain(act map[string]any) []string {
	var stack []string
	for cur := act; cur != nil; {
		sub, _ := cur["sub"].(string)
		if sub != "" {
			stack = append(stack, sub)
		}
		next, _ := cur["act"].(map[string]any)
		cur = next
	}
	// stack is leaf → root because of the act-nesting direction.
	for i, j := 0, len(stack)-1; i < j; i, j = i+1, j-1 {
		stack[i], stack[j] = stack[j], stack[i]
	}
	return stack
}

// inferKind classifies a SPIFFE ID into the principal-kind vocabulary
// (`service` / `human` / `ai`) Omega exposes to AuthZEN policies via
// `principal.kind`. The mapping uses the path-prefix convention adopted
// across the example workloads and CRDs - `/humans/...` is a federated
// user, `/agents/...` is an AI agent workload, anything else is treated
// as a plain service. Operators can override the default by declaring
// the entity in Cedar `entities.json`, or by writing policies that
// ignore `principal.kind` entirely.
func inferKind(id spiffeid.ID) string {
	p := id.Path()
	switch {
	case strings.HasPrefix(p, "/humans/"):
		return "human"
	case strings.HasPrefix(p, "/agents/"):
		return "ai"
	default:
		return "service"
	}
}

// claimExpiry pulls the standard `exp` claim out of a parsed JWT
// claims map. go-jose decodes `exp` as float64 (JSON number); we
// accept int64 as a fallback for callers that pre-marshal.
func claimExpiry(claims map[string]any) (time.Time, bool) {
	switch v := claims["exp"].(type) {
	case float64:
		return time.Unix(int64(v), 0).UTC(), true
	case int64:
		return time.Unix(v, 0).UTC(), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return time.Unix(i, 0).UTC(), true
		}
	}
	return time.Time{}, false
}
