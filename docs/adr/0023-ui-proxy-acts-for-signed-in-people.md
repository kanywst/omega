# ADR 0023: A web UI acts for signed-in people through their JWT-SVIDs

## Status

Accepted.

## Context

The web UI in `ui/` reads the control plane through its own server-side proxy. Under `--require-auth` every admin route needs an mTLS client X.509-SVID, and the policy API (ADR 0022) lets only a `--domain-root-admin` write. The UI had no identity of its own and no notion of who was using it, so its Policies page was read-only: a write path through an unauthenticated proxy would let anyone who reached the UI change policy, and giving the proxy a root admin's certificate would make every visitor a root admin and every change anonymous.

People already have an identity Omega understands. `--oidc-idp` federates with the organisation's OIDC IdP, and `POST /v1/oidc/exchange` turns a person's ID token into a JWT-SVID for a SPIFFE ID such as `spiffe://<td>/humans/<idp>/<user>`, with an `act` claim naming the IdP. What was missing is a way for a trusted server to present that identity on the person's behalf, without the browser ever holding an Omega credential.

## Decision

1. **The UI signs people in with OIDC.** The UI server runs the authorization code flow with PKCE (S256), a `state` bound to the browser by a short-lived cookie, and a `nonce` it checks in the ID token. It exchanges the ID token at `POST /v1/oidc/exchange` for the person's JWT-SVID, with the audience `--ui-proxy-audience` (default `omega-ui`). The session lives in the UI server's memory; the browser holds only a random session id in an `httpOnly`, `Secure`, `SameSite=Lax` cookie. Neither the ID token, the JWT-SVID nor the IdP refresh token reaches the browser.
2. **The UI is a named proxy.** `--ui-proxy <spiffe-id>` (repeatable) names the SPIFFE IDs trusted to act for a person. The UI calls Omega over mTLS with its own X.509-SVID and puts the person's JWT-SVID in the `Omega-User-Token` header. A header of its own, rather than `Authorization`, so a token that leaks into a request is never taken as a credential by itself.
3. **The person becomes the caller, only on the policy API.** When the mTLS caller is a `--ui-proxy` and `Omega-User-Token` holds a valid user token, the token's subject is the caller for authorization and audit on `/v1/policies` (list, read, validate, create, update, delete), and nowhere else. Authorization is unchanged: a write still needs that person to be a `--domain-root-admin`.
4. **A user token is narrow.** It must verify against Omega's own JWT keys, be unexpired (without the 30-second leeway other JWT-SVIDs get), carry exactly the `--ui-proxy-audience`, have a lifetime (`exp - iat`) of at most `--ui-proxy-max-token-ttl` (default one hour), carry an `act` claim of kind `oidc-idp` with no nested delegation, and carry no `cnf`. So only a JWT-SVID minted by `POST /v1/oidc/exchange` for a signed-in person qualifies: a workload's own JWT-SVID, a token-exchange or ID-JAG result, or a sender-constrained token does not.
5. **Fail closed.** A user token from a caller that is not a `--ui-proxy` is refused with `403`, on a route outside the policy API with `403`, and an invalid one with `401`, rather than ignored. A refusal is audited (`ui_proxy.delegate`, the proxy as actor) when the leader serves the request; a follower serving a read only logs it, since only the leader appends to the chain. The proxy without a user token is an ordinary authenticated caller. `--ui-proxy` requires `--require-auth` and `--oidc-idp`, is refused in `spire-upstream` mode, and may not name a `--domain-root-admin`, so the proxy alone never holds write authority.
6. **The audit row names both.** Every policy write and every refused write made through a proxy is recorded with the person as actor and the proxy as `via` in the payload.
7. **The UI defends its own session.** State-changing requests through the UI must come from its own origin (`Origin`, or `Sec-Fetch-Site: same-origin`), and from a signed-in browser must carry the session's CSRF token in `X-Omega-CSRF`. The UI forwards only the calls its own pages make (a fixed list of methods and paths), forwards a policy write only with a person's token, forwards audit reads only for a signed-in browser while it presents its own SVID, forwards the person's token only on the policy API, and strips cookies and any client-supplied `Omega-User-Token` before calling Omega. It renews the person's JWT-SVID through the IdP's refresh token shortly before it expires, which re-checks the person at the IdP, and ends the session when renewal fails or the person changes. A session lasts at most `OMEGA_UI_SESSION_MAX_AGE`.

## Consequences

Easier:

- A person manages stored policies from the UI with their own identity, and the audit chain records who made each change and through which UI.
- The browser holds no Omega credential: a stolen session cookie works only through the UI, from a client that can reach it, and only while the session lives.
- A stolen user token alone is useless: only a caller holding a `--ui-proxy` X.509-SVID can present it.

Harder:

- **The proxy can act as any person whose token it holds.** A compromised UI server can make policy changes as every root admin signed in to it, for as long as their tokens live (the TTL the UI requests, capped by the ID token's remaining lifetime and `--ui-proxy-max-token-ttl`), and renew them while it holds their IdP refresh tokens. Its X.509-SVID must be protected like an admin credential, and the UI host treated as part of the admin plane.
- **No revocation of a single token.** JWT-SVIDs are short-lived and not revocable (ADR 0003). To cut a person off at once, remove them from `--domain-root-admin`; to cut off a proxy, remove its `--ui-proxy` flag or stop issuing its SVID. Both need a server restart. Disabling the person at the IdP stops the next renewal.
- **Sessions are in one process's memory.** A UI restart signs everyone out, and several UI replicas need sticky sessions.
- **A browser that is not signed in reads with the UI's identity.** Without a session cookie the UI calls the policy API as itself, so anyone who reaches the UI sees what the UI's own SVID may read. Restrict who reaches the UI, or what its SVID may read, if stored policies are sensitive.
- Only the policy API accepts a user token. Extending it to domains, groups or audit reads is a later decision per route, so each grant to the proxy is deliberate.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Who may change what Omega decides is Omega's decision, and so is recording it. The UI does not get a second authorization model: it carries the person's Omega identity to the same authorization and audit path the CLI uses. Signing people in stays with the IdP Omega already federates with.
