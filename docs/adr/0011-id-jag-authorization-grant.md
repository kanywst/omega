# ADR 0011: Accept ID-JAG as an RFC 7523 authorization grant

## Status

Accepted.

## Context

Enterprise IdPs have started issuing the Identity Assertion JWT Authorization Grant (ID-JAG, [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)). An AI agent that holds a user's SSO session asks the IdP, through RFC 8693 token exchange, for an ID-JAG naming a downstream authorization server, then presents it there as an RFC 7523 JWT bearer assertion. The IdP decides whether this client may act for this user toward that server; the downstream server issues the access token. The MCP enterprise-managed authorization extension builds on this flow, and several IdPs and authorization servers implement it.

Omega already turns an external ID token into a Human JWT-SVID (`POST /v1/oidc/exchange`) and extends delegation chains with nested `act` claims (`POST /v1/token/exchange`). What it lacked was the receiving side of ID-JAG, so an agent with an IdP-issued grant had no standard way to obtain an Omega delegated token.

## Decision

Omega acts as the ID-JAG resource authorization server at `POST /oauth2/token`, enabled per trusted IdP with `--id-jag-idp` and requiring `--issuer-url`.

1. The request is form-encoded with `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and `assertion=<ID-JAG>`, as the draft requires. It is not a token-exchange `subject_token`.
2. The client authenticates with its SPIFFE ID, using the two methods of [draft-ietf-oauth-spiffe-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-spiffe-client-auth/): a verified X.509-SVID on the mTLS connection (`spiffe_x509`), or a JWT-SVID `client_assertion` of type `urn:ietf:params:oauth:client-assertion-type:jwt-spiffe` whose only `aud` is Omega's issuer, which carries `iat` and `jti` and no `act` or `cnf`, and whose lifetime is within `--id-jag-max-assertion-ttl` (`spiffe_jwt`). The client's identifier at Omega is its SPIFFE ID, so the ID-JAG's `client_id` must equal it. This binding holds only under `--require-auth`, where every connection carries a verified X.509-SVID and only `spiffe_x509` is accepted. Without it any caller can mint the client's JWT-SVID, so `--id-jag-idp` refuses to start without `--require-auth` unless the operator opts in with `--id-jag-insecure-client-binding` for development.
3. The ID-JAG must carry `typ: oauth-id-jag+jwt`, a single `aud` equal to Omega's issuer, and `iss`, `sub`, `client_id`, `jti`, `iat`, `exp`. It is verified against the IdP's JWKS through the same discovery path as `--oidc-idp`, routed by `iss`.
4. The issued token is a JWT-SVID for the client with `act.sub` set to the user's SPIFFE ID (rendered from the IdP's template). It has the same shape as a `/v1/token/exchange` result, so it can be the `subject_token` of the next hop.
5. `resource` and `scope` may only narrow what the ID-JAG grants. An ID-JAG with no `resource` claim grants no audience and is refused (`invalid_target`), so the issued JWT-SVID's audience always comes from the IdP's decision.
6. Every grant is evaluated as its own action, `Action::"token.id_jag"`, whether or not `--enforce-token-exchange-policy` is set. `/v1/token/exchange` keeps a baseline `requested == actor` rule when its gate is off; this grant has no such fallback, so Cedar's default deny applies until the operator writes a permit. A separate action means no existing `token.exchange` permit can authorize the grant after an upgrade. The token is released only after its `allow` row is on the audit chain; if the append fails the client gets `server_error`. Every grant and every refusal after `grant_type` is recognised is written to the audit chain as `token.id_jag`. Validation failures are answered with a generic description, and the detail goes only to the audit row, so a client cannot probe which issuers are trusted.
7. With more than one `--id-jag-idp`, every template must contain `{idp}`, so two IdPs asserting the same `sub` never map to one user. `--id-jag-idp` is refused in `spire-upstream` mode, which issues no JWT-SVIDs.

Omega deliberately departs from or narrows the draft in four places:

1. The issued token never outlives the ID-JAG. The draft's example returns a day-long access token; Omega keeps the rule `/v1/token/exchange` already applies, that delegated authority must not outlive its grant. A client re-presents the ID-JAG, which the draft allows, or asks its IdP for a new one.
2. ID-JAGs with a lifetime (`exp - iat`) above `--id-jag-max-assertion-ttl` (default 5m) are rejected. The draft sets no bound.
3. `jti` is required but not tracked for replay, because the draft lets a client re-present the same ID-JAG until it expires.
4. An ID-JAG with a `cnf` claim is rejected. Omega does not verify DPoP proofs, and the draft requires refusing a bound assertion presented without one.

`GET /.well-known/oauth-authorization-server` (RFC 8414) advertises the token endpoint, the jwt-bearer grant, the `urn:ietf:params:oauth:grant-profile:id-jag` profile, and the one SPIFFE authentication method that can succeed on this listener (`spiffe_x509` with `--client-ca`, otherwise `spiffe_jwt`). It does not list trusted issuers, which the draft forbids.

## Consequences

Easier:

- An agent that already speaks SPIFFE can turn an IdP-issued ID-JAG into an Omega delegated token with no shared secret, then extend the chain through `/v1/token/exchange` and have every hop gated by AuthZEN and recorded in one audit chain.
- An ID token can no longer be replayed as an authorization grant: explicit typing (RFC 8725 §3.11) separates the two even when one IdP issues both.

Harder:

- Short-lived delegated tokens mean the client calls the IdP more often.
- Production deployments need `--require-auth` and mTLS; a JWT-SVID-only client cannot use the grant there until Omega supports a cert-optional TLS mode.
- Operators must write a `token.id_jag` permit before any grant succeeds.
- The draft is not final. Claim names and the DPoP grant type may still change, and this endpoint follows the draft.

New obligations:

- Track the draft revisions and keep the processing rules above in step with them.
- Add DPoP verification before accepting `cnf`-bound ID-JAGs.

## Scope fit

Rule 1 in [design-philosophy.md](../design-philosophy.md): *"Does Omega produce or consume the wire format?"*

Yes. ID-JAG is a token format Omega consumes on the same OIDC federation path as ID tokens, and the result is a JWT-SVID Omega already produces. It belongs in Core.
