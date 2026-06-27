package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// callerCtxKey is the context key under which the authenticated caller's
// SPIFFE ID is stored by requireSPIFFEAuth. Unexported so only this
// package can set it; handlers read it back via CallerSPIFFEID.
type callerCtxKey struct{}

// WithRequireAuth toggles caller authentication. When true, every gated
// write / PDP / issuance endpoint requires the request to arrive over
// mTLS carrying a verified client certificate with a `spiffe://...` URI
// SAN, and the issuance handlers bind the issued identity to that
// authenticated caller. When false (the default) behaviour is unchanged
// from the unauthenticated, open-CA status quo so existing deployments,
// demos, and CI keep working on upgrade. The TLS / mTLS transport itself
// is configured independently in the server bootstrap (--tls-cert /
// --tls-key / --client-ca); this flag only governs whether the
// application layer enforces and binds to the client identity.
func (s *Server) WithRequireAuth(v bool) *Server {
	s.requireAuth = v
	return s
}

// CallerSPIFFEID returns the authenticated caller's SPIFFE ID extracted
// from the verified client certificate, or "" when the request was not
// authenticated (require-auth off, or a public endpoint). Handlers use
// it to bind an action to the caller's own identity.
func CallerSPIFFEID(ctx context.Context) string {
	id, _ := ctx.Value(callerCtxKey{}).(string)
	return id
}

// spiffeIDFromTLS pulls the SPIFFE URI SAN out of the verified client
// certificate. It keys off cs.VerifiedChains, which the TLS stack only
// populates after it has actually verified the leaf against the trust
// anchors (the configured --client-ca, via RequireAndVerifyClientCert),
// so an unverified or self-signed peer cert can never reach the identity
// projection even if an embedder fronts this Server with a laxer
// ClientAuth mode. It deliberately trusts no caller-supplied header — the
// identity is the cert. Per the X.509-SVID spec a cert carries exactly
// one URI SAN; we reject anything else rather than picking the first, and
// return the canonical SPIFFE ID so the caller-vs-requested comparison in
// authorizeIssuance is normalization-stable.
func spiffeIDFromTLS(cs *tls.ConnectionState) (string, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", errors.New("verified client certificate required")
	}
	leaf := cs.VerifiedChains[0][0]
	// An X.509-SVID carries exactly one URI SAN. Reject any other count —
	// including one spiffe:// plus an extra non-spiffe URI — so a broader
	// client-CA that mints multi-URI certs can't smuggle a second SAN past
	// the identity projection.
	if len(leaf.URIs) != 1 {
		return "", fmt.Errorf("client certificate must have exactly one URI SAN, got %d", len(leaf.URIs))
	}
	if leaf.URIs[0] == nil || leaf.URIs[0].Scheme != "spiffe" {
		return "", errors.New("client certificate URI SAN is not a spiffe:// id")
	}
	// Parse the already-parsed *url.URL directly rather than round-tripping
	// through a string.
	id, err := spiffeid.FromURI(leaf.URIs[0])
	if err != nil {
		return "", fmt.Errorf("client certificate SPIFFE ID: %w", err)
	}
	return id.String(), nil
}

// requireSPIFFEAuth wraps a gated handler with caller authentication.
//
// When require-auth is off it is a transparent pass-through (compat: the
// status-quo open behaviour). When on, the request must present a
// verified client cert with a SPIFFE URI SAN; otherwise it is rejected
// with 401 and the inner handler never runs. On success the caller's
// SPIFFE ID is stashed in the request context for downstream issuance
// binding (see issueSVID / issueJWTSVID).
func (s *Server) requireSPIFFEAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuth {
			h(w, r)
			return
		}
		id, err := spiffeIDFromTLS(r.TLS)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err)
			return
		}
		ctx := context.WithValue(r.Context(), callerCtxKey{}, id)
		h(w, r.WithContext(ctx))
	}
}

// authorizeIssuance binds an SVID issuance request to the authenticated
// caller. It returns true when the handler may proceed and false when it
// has already written an error response.
//
// When require-auth is off it is a no-op (true) - the legacy open-CA
// behaviour is preserved verbatim so existing demos / CI keep working.
// When on, the caller (a verified mTLS client SVID, populated by
// requireSPIFFEAuth) may only obtain an SVID for its *own* identity:
// self-renewal is allowed (the CSR public key may rotate), but minting a
// *different* identity is denied with 403. This closes the C1 open-CA
// defect where spiffe_id was caller-asserted and unauthenticated.
//
// Extension point: admin / delegated cross-identity issuance (a caller
// minting an SVID for a different ID) is intentionally NOT built here.
// The follow-up authorizes it through the Cedar PDP (an `svid.issue`
// permit on the requested ID, mirroring the token-exchange guard), so
// that "deny cross-identity by default" is the safe Phase-1 floor.
func (s *Server) authorizeIssuance(w http.ResponseWriter, r *http.Request, requested string) bool {
	if !s.requireAuth {
		return true
	}
	caller := CallerSPIFFEID(r.Context())
	if caller == "" {
		// Defense in depth: an issuance route should always be wrapped by
		// requireSPIFFEAuth when require-auth is on, so this is unreachable
		// in normal wiring. Fail closed rather than minting unbound.
		writeErr(w, http.StatusUnauthorized, errors.New("authenticated client certificate required"))
		return false
	}
	if caller != requested {
		writeErr(w, http.StatusForbidden,
			fmt.Errorf("caller %q may not issue an SVID for a different identity %q (self-renewal only; delegated issuance is gated by policy and not yet enabled)", caller, requested))
		return false
	}
	return true
}
