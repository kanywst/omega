# Roadmap

This page is the public roadmap for Omega. It complements the charter
in [docs/scope.md](docs/scope.md) and the layer rules in
[docs/design-philosophy.md](docs/design-philosophy.md): scope says
*what* is in, design philosophy says *where* a feature lives, and this
page says *when*.

Items are grouped by horizon, not by semver version. Pre-1.0 we
release as features are ready rather than on a fixed cadence; see
[RELEASING.md](RELEASING.md).

## Now (next release, post-0.9.0)

Nothing is committed yet. Runtime rotation of the built-in CA ([ADR 0019](docs/adr/0019-runtime-ca-rotation.md)), the opt-in overlap across Vault PKI and step-ca rotations, and the SPIFFE CSI driver in the Helm chart shipped in 0.9.0.

## Next (3-6 months)

Nothing is queued here; the items below are the next candidates.

## Later (6-12 months)

- Cloud HSM / KMS-backed CA upstream plugins (AWS Private CA, GCP CAS).
  The interface seam is in place
  ([ADR 0005](docs/adr/0005-ca-plugin-architecture.md)) and three
  non-disk backends have shipped (`--ca-backend=vault-pki`,
  `--ca-backend=step-ca` and `--ca-backend=azure-keyvault`); the remaining backends follow the same shape
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
- NIST PQC: ML-DSA / ML-KEM / SLH-DSA support for CA and JWT-SVID
  signing once Go's standard library exposes stable APIs.
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
