# ADR 0009: Reload upstream trust material on SIGHUP

## Status

Accepted.

## Context

[ADR 0007](0007-pluggable-identity-source.md) introduced the
`spire-upstream` identity source and
[ADR 0008](0008-upstream-jwt-svid-validation.md) extended it from X.509
to the full SPIFFE credential set. Both wired the trust material the same
way: read the file once at boot, hold it for the process lifetime. ADR
0008 listed the cost under *Harder* — "Rotation is a file swap plus
restart" — and
[docs/conformance-spiffe.md](../conformance-spiffe.md) recorded the
matching gap, with `spiffe_sequence` "fixed at 1 until runtime rotation
ships".

That boot-time snapshot is a correctness problem, not just an
inconvenience, because **the upstream rotates on its own schedule**.
SPIRE rolls its X.509 CA and its JWT signing key without asking the
consumers. The failure is delayed and total:

- Omega serves `/v1/bundle` and `/v1/jwt/bundle` from the snapshot.
  Agents re-fetch on their own cadence and faithfully cache whatever the
  control plane hands them, so a stale server propagates staleness to
  every agent rather than any one of them recovering independently.
- Once the upstream root rolls, Omega is serving a bundle that lacks the
  new anchor. Freshly-issued upstream SVIDs fail to verify. A `kid`
  rotation produces "jwt signed by unknown kid" — precisely the failure
  ADR 0008 set out to remove, reintroduced by the passage of time instead
  of by misconfiguration.
- Nothing surfaces at boot or in a health check. The deployment is
  correct on Monday and broken on Wednesday with no operator action in
  between.

Restarting to pick up new anchors is a poor answer for a control plane
whose whole job is to be available when workloads are establishing
identity.

## Decision

The `spire-upstream` source can replace its trust material at runtime,
driven by **SIGHUP** — the signal the audit keyring already uses for
rotation, so operators learn one reload mechanism rather than two.

- A new `identity.ReloadableSource` interface adds
  `Reload(x509BundlePEM, jwtJWKS []byte) (bool, error)` above `Source`.
  Only the consuming source implements it; an issuing Authority owns its
  key material and has nothing to re-read, so callers type-assert rather
  than assume.
- `upstreamSource` holds its material as an immutable snapshot behind an
  `atomic.Pointer`. Reload validates a whole replacement generation and
  swaps the pointer. Readers on the request and validation paths take no
  lock, and a JWT validation pins one generation for its whole duration
  so the `kid` lookup and the signature check cannot straddle a rotation.
- Reload runs **the same validation as boot** — one shared constructor
  for the snapshot — and is fail-closed in the strong sense: on any
  error the previous generation stays installed. A rotation that would
  replace good anchors with corrupt ones leaves Omega serving the good
  ones. Serving nothing would break every handshake, which is strictly
  worse than serving material that is merely old.
- Reload reports whether the material actually changed, and the
  generation counter advances only when it did. `spiffe_sequence` is
  wired to that counter through a `BundleSequencer` assertion, so
  federation peers can distinguish a rotated bundle from a re-served
  one. A source that cannot rotate keeps reporting `1`, which is now a
  true statement about that process rather than a placeholder.
- `federation.Registry` gains `SetOwnBundle`. The registry snapshots the
  local bundle at construction, so without this the peers would keep
  being served pre-rotation anchors even after the source rotated.

The reload re-reads the files on each signal rather than watching them.
An operator rotating trust material swaps a file — often two, the bundle
and the JWKS — and the signal is where they assert the swap is complete.
Watching would race a half-written file and a two-file rotation that is
only half-applied.

Issuance posture is unchanged: this source still runs no CA and the
issuance routes still return 501. Reload replaces what Omega *consumes*.

## Consequences

Easier:

- An upstream CA or signing-key rotation is followed with `kill -HUP`
  instead of a control-plane restart, and the new anchors reach agents
  through the fetch path they already use.
- A bad rotation is survivable: the failed reload is logged and Omega
  keeps serving the last good material, so the operator has time to fix
  the file rather than an outage to fix it during.
- `spiffe_sequence` becomes meaningful for upstream deployments, closing
  the conformance gap ADR 0008 left open.

Harder:

- Reload is operator-driven. Omega does not poll the files or fetch from
  the upstream's bundle endpoint, so an operator who rotates without
  signalling is still stale — the failure mode is narrowed, not removed.
  Automatic upstream fetch is deliberately not taken here: it would add a
  boot-time and runtime network dependency on the upstream that ADR 0007
  explicitly avoided.
- One more piece of runtime state can differ across replicas: two servers
  signalled at different times briefly serve different generations. Both
  are valid trust material during an upstream's overlap window, which is
  exactly the window rotation is designed around.

New obligations:

- Any future field added to the upstream trust snapshot must be part of
  the same atomic generation. Adding one outside the snapshot would
  reintroduce the torn-read the `atomic.Pointer` exists to prevent.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md):
*"Is it an upstream system Omega depends on but does not own?"*

Yes — same seam as ADRs 0007 and 0008. This makes the consumption of that
upstream correct over time rather than only at boot; it adds no new
surface of its own.
