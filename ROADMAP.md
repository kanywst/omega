# Roadmap

This page is the public roadmap for Omega. It complements the charter
in [docs/scope.md](docs/scope.md) and the layer rules in
[docs/design-philosophy.md](docs/design-philosophy.md): scope says
*what* is in, design philosophy says *where* a feature lives, and this
page says *when*.

Items are grouped by horizon, not by semver version. Pre-1.0 we
release as features are ready rather than on a fixed cadence; see
[RELEASING.md](RELEASING.md).

## Now (next release, post-0.15.1)

Nothing is committed yet. Sign-in to the UI and policy writes as the signed-in person, through `--ui-proxy` ([ADR 0023](docs/adr/0023-ui-proxy-acts-for-signed-in-people.md)), shipped in 0.14.0, with chart values and multi-replica sign-in in 0.15.0. 0.15.1 is a security fix for `null` values in AuthZEN requests.

## Next (3-6 months)

Nothing is queued here; the items below are the next candidates.

## Later (6-12 months)

- Further Cloud HSM / KMS-backed CA upstream plugins. The interface seam is in place
  ([ADR 0005](docs/adr/0005-ca-plugin-architecture.md)) and five
  non-disk backends have shipped (`--ca-backend=vault-pki`,
  `--ca-backend=step-ca`, `--ca-backend=aws-pca`, `--ca-backend=gcp-cas` and `--ca-backend=azure-keyvault`); the remaining backends follow the same shape
  (one `Kind` constant + one `Authority` impl + one `identity.New`
  switch case + tests against a fake HTTP backend), with
  [`docs/ca-plugin-guide.md`](docs/ca-plugin-guide.md) as the
  walkthrough. Demoted from Now in September 2026: these extend the
  **issuing** side, and the project's near-term weight is on consuming
  an upstream SPIFFE trust domain and on the AuthZEN / Cedar surface.
  Nothing blocks a contributor from picking one up: the seam and the
  guide exist precisely so that is a self-contained change.

## Tracking (research / spec watch)

- IETF WIMSE multi-domain identity. Track WG draft progress before
  committing to an in-tree implementation.
- NIST PQC: ML-DSA support for CA and JWT-SVID signing. The Go side
  is no longer the gate: Go 1.27 ships `crypto/mldsa` and ML-DSA in
  `crypto/x509` and `crypto/tls`, and TLS already negotiates the hybrid
  `X25519MLKEM768` key exchange by default, so ML-KEM needs nothing
  from omega. What still blocks an in-tree ML-DSA CA (re-checked
  October 2026) is everything around it: a SPIFFE bundle carries keys
  as JWKs and there is no registered JWK form for ML-DSA yet (the
  JOSE/COSE ML-DSA draft is still a draft and go-jose does not support
  it), and SPIRE has not shipped ML-DSA SVIDs (spiffe/spire issues for
  X.509 / JWT ML-DSA SVIDs and PQC are open), so an omega trust domain
  signed with ML-DSA could not federate with, or consume from, SPIRE.
  Revisit when either lands. SLH-DSA has no Go standard library
  package.
- AuthZEN PDP capability metadata (§9.1.2) and the `page.properties`
  Search extension that depends on it. Moved here from Now in October
  2026: the Final specification creates the "AuthZEN Policy Decision
  Point Capabilities" registry (§12.3) with no initial entries, so
  there is no URN omega could declare, and the spec names the metadata
  key both `capabilities` (§9.1.2) and `supported_capabilities`
  (§8.2.1). Revisit when the first capability is registered.

## Non-goals

Items in [docs/non-goals.md](docs/non-goals.md) are not on the roadmap
and will not be added without a scope amendment via GitHub Discussion.

## How this roadmap is maintained

This file is the roadmap of record; there is no parallel issue-tracker
representation to keep in sync. An item is added by opening a PR that
places it under a horizon and says why it belongs there, and removed by
the PR that ships it, which also lands the `CHANGELOG.md` entry, so a
horizon and a release note never disagree about whether something is
done.

Beyond that, the horizons are re-read against the tree on a fixed
schedule (currently every 30 days) rather than only when someone
remembers: every item's claim is checked against the code that would
implement it, anything that shipped without being listed is added, and
a horizon that no longer matches the project's direction is moved with
a dated note explaining the demotion rather than silently deleted. The
September 2026 pass is what moved the KMS-backed CA plugins from Now to
Later and corrected this section, which had described an issue-label
process this repository has never used.
