package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/0-draft/omega/internal/server/metrics"
	"github.com/0-draft/omega/internal/server/oidc"
	"github.com/0-draft/omega/internal/server/storage"
)

// OIDCExchangeRequest is the JSON body of POST /v1/oidc/exchange.
// `idp` selects which configured IdP omega should validate the ID
// token against (the per-IdP audience / issuer / SPIFFE template
// were declared at server startup). `audience` becomes the `aud`
// claim of the issued omega JWT-SVID.
type OIDCExchangeRequest struct {
	IDP        string   `json:"idp"`
	IDToken    string   `json:"id_token"`
	Audience   []string `json:"audience"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
}

// OIDCExchangeResponse mirrors the shape of TokenExchangeResponse
// and IssueJWTSVIDResponse so callers can treat any omega-issued
// JWT-SVID source uniformly.
type OIDCExchangeResponse struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	SPIFFEID    string   `json:"spiffe_id"`
	Audience    []string `json:"audience"`
	ExpiresIn   int      `json:"expires_in"`
	KeyID       string   `json:"kid"`
	IdP         string   `json:"idp"`
}

// WithOIDCRegistry attaches the IdP registry. Passing nil leaves
// POST /v1/oidc/exchange disabled (it returns 404), preserving
// backward compatibility for deployments that have not yet
// configured any external IdP.
func (s *Server) WithOIDCRegistry(r *oidc.Registry) *Server {
	s.oidc = r
	return s
}

func (s *Server) exchangeOIDC(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeErr(w, http.StatusNotFound, errors.New("OIDC IdP federation is not configured on this server (start omega server with at least one --oidc-idp)"))
		return
	}
	// 1 MiB is two orders of magnitude above the largest realistic
	// OIDC ID token (a few KiB even for a 50-group user) and bounds
	// the memory cost of an abusive caller.
	var req OIDCExchangeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
		return
	}
	if req.IDP == "" {
		writeErr(w, http.StatusBadRequest, errors.New("idp is required"))
		return
	}
	if req.IDToken == "" {
		writeErr(w, http.StatusBadRequest, errors.New("id_token is required"))
		return
	}
	if len(req.Audience) == 0 {
		writeErr(w, http.StatusBadRequest, errors.New("audience is required"))
		return
	}
	claims, err := s.oidc.Validate(r.Context(), req.IDP, req.IDToken)
	if err != nil {
		if errors.Is(err, oidc.ErrUnknownIdP) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// Anything else is a token-validation failure (signature,
		// iss, aud, exp). Audit as a deny and answer 401.
		s.audit(r.Context(), storage.AuditEvent{
			Kind:     "oidc.exchange",
			Decision: "deny",
			Payload:  mustJSON(map[string]string{"idp": req.IDP, "error": err.Error()}),
		})
		writeErr(w, http.StatusUnauthorized, err)
		return
	}
	cfg, err := s.oidc.Lookup(req.IDP)
	if err != nil {
		// Concurrent reconfig between Validate and Lookup would be
		// the only path here; treat defensively as 500.
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	idStr, err := oidc.RenderSPIFFEID(cfg.SPIFFEIDTemplate, claims)
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
			fmt.Errorf("rendered spiffe id %q is not in trust domain %q (check the idp's spiffe_id_template)", id, s.ca.TrustDomain()))
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	// Cap the issued JWT-SVID's TTL at the upstream ID token's
	// remaining lifetime so the delegated authority does not outlive
	// the principal.
	if !claims.ExpiresAt.IsZero() {
		remaining := time.Until(claims.ExpiresAt)
		if remaining <= 0 {
			writeErr(w, http.StatusUnauthorized, errors.New("id_token has expired"))
			return
		}
		if ttl <= 0 || ttl > remaining {
			ttl = remaining
		}
	}
	extra := map[string]any{
		// RFC 8693 §4.1: `act` records the actor that asserted the
		// principal. Here the actor is the upstream OIDC IdP.
		"act": map[string]any{
			"sub":     claims.Subject,
			"iss":     claims.Issuer,
			"idp":     claims.IdPName,
			"kind":    "oidc-idp",
		},
	}
	svid, err := s.ca.IssueJWTSVID(id, req.Audience, ttl, extra)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	metrics.SVIDIssued.WithLabelValues("jwt-oidc").Inc()
	s.audit(r.Context(), storage.AuditEvent{
		Kind:     "oidc.exchange",
		Subject:  id.String(),
		Decision: "ok",
		Payload: mustJSON(map[string]any{
			"idp":           claims.IdPName,
			"upstream_sub":  claims.Subject,
			"upstream_iss":  claims.Issuer,
			"audience":      req.Audience,
			"expires_in":    int(ttl / time.Second),
			"kid":           svid.KeyID,
		}),
	})
	writeJSON(w, http.StatusOK, OIDCExchangeResponse{
		AccessToken: svid.Token,
		TokenType:   "Bearer",
		SPIFFEID:    id.String(),
		Audience:    svid.Audience,
		ExpiresIn:   int(ttl / time.Second),
		KeyID:       svid.KeyID,
		IdP:         claims.IdPName,
	})
}
