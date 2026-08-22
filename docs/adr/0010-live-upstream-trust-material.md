# ADR 0010: Follow upstream trust material over the SPIFFE Workload API

## Status

Accepted.

## Context

[ADR 0009](0009-upstream-trust-material-reload.md) made the `spire-upstream` source rotatable: `Reload` swaps a validated generation of trust material behind an `atomic.Pointer`, `spiffe_sequence` advances only on a real change, and a rejected generation leaves the previous one serving. It did not settle who supplies the new bytes. The only transport is a pair of files plus SIGHUP, and ADR 0009 named the residual gap: "an operator who rotates without signalling is still stale — the failure mode is narrowed, not removed."

That gap is where the deployment work lands. SPIRE already publishes its current trust bundle over the SPIFFE Workload API and updates the stream when the CA or the JWT signing key rolls. Reading it from a file leaves the operator to build the missing half: a sidecar that watches SPIRE, writes two files atomically, and signals Omega. That machinery is outside the charter, is rewritten per deployment, and when it dies quietly the result is the delayed failure ADR 0009 exists to prevent, this time caused by a stalled copy loop rather than by a boot-time snapshot.

ADR 0009 declined automatic upstream fetch because it "would add a boot-time and runtime network dependency on the upstream that ADR 0007 explicitly avoided". That still holds for the default. It does not hold as a prohibition: a control plane running beside a SPIRE agent already depends on that agent, and refusing to read its socket moves the coupling into untested shell rather than removing it.

## Decision

The `spire-upstream` source gains a second transport. `--identity-source-workload-api` names a SPIFFE Workload API endpoint that Omega follows for the life of the process.

- The transports are mutually exclusive and exactly one is required. Allowing both would let one shadow the other, so a rotation applied to the wrong one looks like it did nothing.
- Everything downstream of the transport is unchanged. Fetched material goes through the same `ReloadableSource.Reload` seam: same validation, same atomic generation swap, same `spiffe_sequence`, same fail-closed rule.
- Omega consumes bundles only, via `FetchX509Bundles` and `FetchJWTBundles`, not `FetchX509SVID`. A non-issuing source has no use for an SVID of its own.
- JWT consumption is opt-in through `--identity-source-workload-api-jwt`, mirroring the file transport's optional `--identity-source-jwt-bundle`. Omega consumes only EC P-256 (ES256) signing keys, so an upstream configured with an RSA JWT key has no usable key and startup fails closed. A deployment that only wants X.509 should not break on a key type it does not use.
- The X.509 and JWT watches run independently, so a reader can briefly see a new X.509 bundle beside the previous JWKS. Both halves are valid anchors and the other update follows, so the pair is mixed rather than invalid. Synchronising them would stall one rotation behind the other for no gain.
- A watch that ends in error is restarted after a fixed delay and logged. go-spiffe retries transient stream errors itself; this covers the case where it gives up, so a permanently failing upstream keeps complaining instead of freezing the trust material silently.
- The boot fetch is a bounded one-shot (30s). An endpoint that is not there fails startup with a message naming the address instead of hanging a process that never listens.
- Only `unix://` addresses are accepted. go-spiffe will dial `tcp://<any address>` with no transport security and no server authentication, and what arrives over that channel becomes Omega's entire root of trust — a strictly weaker boundary than the file transport, which at least requires local write access. The Workload API's security model is kernel-enforced peer credentials over a local socket, which is also what "Omega must be an attested workload of that endpoint" assumes; the rest of the codebase pins `unix://` itself rather than letting a caller choose. A remote transport would need mTLS and its own ADR.

`--trust-domain` stays explicitly required. The Workload API serves a set of bundles — the local domain plus any federated ones — and Omega publishes exactly one; inferring it could publish a federated peer's anchors as Omega's own.

Issuance posture is unchanged: no CA, issuance routes still 501.

## Consequences

Easier:

- An upstream CA or signing-key rotation reaches agents with no operator in the loop and no per-deployment sidecar.
- Misconfiguration surfaces at startup, with the trust domain and address in the message, instead of as a verification failure days later.
- "Omega consumes SPIRE" describes the running system rather than a file an operator keeps current.

Harder:

- Omega gains a startup dependency on the Workload API endpoint when this transport is selected. That is the trade ADR 0009 declined by default, and is why this is a second transport rather than a replacement.
- Omega must be an attested workload of that endpoint. Under SPIRE that means a registration entry for the control-plane process, which the file transport does not need.
- Two transports are two paths to keep tested. They converge at `Reload`, so the divergent surface is the fetch and the flag validation, both covered directly.

New obligations:

- A future credential type added to the upstream snapshot needs a watch here as well as a file read, or the live transport will serve it frozen while the file transport rotates it.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md): *"Is it an upstream system Omega depends on but does not own?"*

Yes — the same seam as ADRs 0007, 0008, and 0009. This is a transport for material Omega already consumes. It adds no new surface and no new authority over the upstream.
