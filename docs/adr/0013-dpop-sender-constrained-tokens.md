# ADR 0013: Verify DPoP proofs and honour sender-constrained tokens

## Status

Accepted. Replaces the "reject `cnf`-bound ID-JAGs" rule of [ADR 0011](0011-id-jag-authorization-grant.md).

## Context

ADR 0011 refused any ID-JAG carrying `cnf`, because Omega could not verify DPoP proofs and the ID-JAG draft (§9.8.1.2.2) requires refusing a bound assertion presented without one. IdPs that bind ID-JAGs to the client's DPoP key could therefore not be used at all.

A related gap sat in `POST /v1/token/exchange`. It never looked at `cnf` on the subject or actor token, so a token bound to a key or a certificate (RFC 9449 `cnf.jkt`, RFC 8705 `cnf.x5t#S256`) could be exchanged by anyone holding the token string, as if it were a bearer token.

## Decision

Omega verifies RFC 9449 DPoP proofs on the two endpoints that accept or mint delegated tokens.

1. **Proof checks.** Exactly one `DPoP` header in JWS compact serialization; JOSE `typ` `dpop+jwt`; an asymmetric algorithm; a public `jwk` header that verifies the signature; `htm` equal to the request method; `htu` equal to the endpoint under `--issuer-url` (query and fragment ignored, scheme and host compared case-insensitively, default ports dropped); `iat` within one minute of now; a `jti` of at most 256 bytes not seen for that key within the proof window. The key's RFC 7638 SHA-256 thumbprint is what `cnf.jkt` binds to.
2. **ID-JAG grant.** An ID-JAG with `cnf.jkt` is redeemed only with a valid proof for that key. A missing proof or a proof for another key answers `invalid_grant`; a proof that is present but invalid answers `invalid_dpop_proof` (RFC 9449 §5), so the client knows to retry with a fresh one. A valid proof sent with an unbound ID-JAG is accepted too. Either way the issued JWT-SVID carries `cnf.jkt` for the proof key and the response says `token_type: DPoP`. Only the `jwt-bearer` grant type is accepted, not the `jwt-dpop` variant one example in the draft uses.
3. **Token exchange.** A subject or actor token with `cnf.jkt` requires a proof for that key at `/v1/token/exchange`; one with `cnf.x5t#S256` requires the matching verified client certificate on the connection; any other `cnf` is refused. One proof may satisfy both tokens when they share a key. The exchanged token belongs to the actor, so it keeps the actor token's `cnf`; when the actor is the subject's own principal and its token is unbound, it keeps the subject token's `cnf`. A key holder therefore cannot turn its bound token into a bearer token by exchanging it with itself. A `cnf.jkt` output answers `token_type: DPoP`.
4. **Metadata.** `GET /.well-known/oauth-authorization-server` lists `dpop_signing_alg_values_supported`.

The `jti` replay cache is held in memory as SHA-256 hashes in two generations that rotate every two minutes, so eviction costs nothing per request and an entry lives at least two minutes: the whole span a proof can be valid, since `iat` may be up to a minute ahead of first use and is accepted for a minute after. It is capped at 100,000 entries; when full, proofs are refused rather than accepted unchecked. The cap is shared by all callers that get as far as proof verification, so a client flooding it can deny DPoP to others until entries age out; it cannot bypass the check. Both endpoints are leader-only, so in an HA deployment one process sees every proof; a leader change clears the cache, which the one-minute `iat` window bounds.

## Consequences

Easier:

- IdPs that bind ID-JAGs to the client's DPoP key work, and the binding carries through to the token Omega issues.
- Sender-constrained tokens can no longer be exchanged as bearer tokens.

Harder:

- Resource servers that receive a `token_type: DPoP` JWT-SVID must verify the DPoP proof and `ath` themselves; a validator that ignores `cnf` treats it as a bearer token. The agent's Workload API `ValidateJWTSVID` returns the claims, including `cnf`, but does not enforce the binding, so a workload that validates through it must check `cnf` itself.
- A client that sent a bound token to `/v1/token/exchange` without a proof, which used to work, now gets `400`.

## Scope fit

Rule 1 in [design-philosophy.md](../design-philosophy.md): *"Does Omega produce or consume the wire format?"*

Yes. DPoP proofs and `cnf` claims are part of the tokens Omega consumes and issues. They belong in Core.
