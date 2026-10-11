# ADR 0012: Optional client certificates on the TLS listener

## Status

Accepted. Amends the client-authentication consequence of [ADR 0011](0011-id-jag-authorization-grant.md).

## Context

`--client-ca` turned on `tls.RequireAndVerifyClientCert`, so every connection had to present a verified client certificate before any route ran. `--require-auth` then bound gated routes to that certificate's SPIFFE ID.

That made two things impossible under `--require-auth`:

1. The `spiffe_jwt` method of the ID-JAG grant (ADR 0011). A client that only holds JWT-SVIDs, for example one behind a TLS-terminating proxy or one that fetches only JWT-SVIDs from the Workload API, could never reach `POST /oauth2/token`: a connection without a cert failed the handshake, and a connection with one was rejected for using two authentication methods.
2. The enrollment paths the router already treats as open (`POST /v1/attest/k8s`, `POST /v1/oidc/exchange`) and the public reads (health, bundles, discovery). Their handlers do not require a caller identity, but the handshake did, so a workload without an SVID could not obtain its first one over a `--client-ca` listener.

## Decision

`--client-cert-optional`, valid only with `--client-ca` and `--require-auth`, switches the listener to `tls.VerifyClientCertIfGiven`. A certificate that is presented is still verified against `--client-ca`; a connection without one is accepted.

Authorization does not move. Routes gated by `--require-auth` already check the verified chain per request (`requireSPIFFEAuth`), so they keep answering `401` without a client SVID. The ungated routes become reachable without one: `GET /healthz`, `GET /v1/leader`, `GET /v1/domains` and `GET /v1/domains/{name}` (domain data, without the admin lists, which are shown only to authenticated callers), `GET /v1/bundle`, `GET /v1/spiffe-bundle`, `GET /v1/jwt/bundle`, `GET /v1/federation/bundles` (federation peers), the `/.well-known/` discovery documents, `GET /metrics`, and the enrollment paths `POST /v1/attest/k8s` and `POST /v1/oidc/exchange`. So does `POST /oauth2/token`, which authenticates its own client.

Under `--require-auth` a `spiffe_jwt` client assertion is a real credential: the server only mints a JWT-SVID for the caller's own identity, and the grant refuses assertions that carry `act` (delegated tokens) or `cnf` (cert-bound tokens), so a JWT-SVID for client C without `act` comes from C. The grant is refused in spire-upstream mode, so this rests on Omega's own issuance policy, not an upstream issuer's.

The trade-off is that `spiffe_jwt` is a bearer credential where `spiffe_x509` is proof of possession. To bound that, a client assertion must be short-lived (`exp - iat` within `--id-jag-max-assertion-ttl`) and is single use: its `jti` is remembered per client until it can no longer validate, so a leaked assertion cannot be replayed while the process that saw it keeps serving. The memory is per process, so after a restart or a leader failover an assertion captured earlier could be replayed until it expires, at most `--id-jag-max-assertion-ttl` plus 30 seconds. Each client may hold at most 1,000 entries at once (`429` beyond that), so one client cannot fill the shared cache and lock the others out; filling the 100,000-entry cap takes a hundred distinct clients. The ID-JAG metadata advertises `spiffe_x509` when `--client-ca` is set and `spiffe_jwt` when the listener admits connections without a certificate.

It is refused without `--require-auth`. There the handshake is the only gate on write, issuance and PDP routes, and dropping it would turn a certificate-gated server into one that mints any identity for any caller.

The default is unchanged: without the flag, `--client-ca` still requires a certificate on every connection.

## Consequences

Easier:

- JWT-SVID-only agents can use the ID-JAG grant in a `--require-auth` deployment.
- A workload without an SVID can reach the enrollment paths on an mTLS listener.

Harder:

- With the flag, the ungated routes listed above, including domain data, federation peer lists and `/metrics`, are anonymous reads for anyone who can reach the listener. Operators who relied on the handshake to hide them must restrict them at the network layer or leave the flag off.
- The enrollment paths become reachable without a certificate, as they already are on a listener without `--client-ca`. Their failed attempts append audit deny rows, and `POST /v1/attest/k8s` costs a TokenReview call per request, so an unauthenticated caller can generate both.
- Every new ungated route is now reachable without a certificate in this mode, so the "wrap it" rule for write and PDP routes in the project guide matters more.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Which callers the control plane admits, and where it authenticates them, is Omega's own trust-boundary decision. It belongs in Core.
