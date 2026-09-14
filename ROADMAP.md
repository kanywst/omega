# Roadmap

This page is the public roadmap for Omega. It complements the charter
in [docs/scope.md](docs/scope.md) and the layer rules in
[docs/design-philosophy.md](docs/design-philosophy.md): scope says
*what* is in, design philosophy says *where* a feature lives, and this
page says *when*.

Items are grouped by horizon, not by semver version. Pre-1.0 we
release as features are ready rather than on a fixed cadence; see
[RELEASING.md](RELEASING.md).

## Now (next release, post-0.4.0)

- Agent-side Kubernetes workload attestor (cgroup-based pod
  introspection). The server-side `POST /v1/attest/k8s` endpoint
  has shipped (TokenReview-backed); the SPIRE-style "agent attests
  workloads by inspecting `/proc/<pid>/cgroup` then calling
  kube-apiserver" path is the remaining bit.
- AuthZEN entity-store mode for Search. Today's
  `POST /access/v1/search/{subject,resource,action}` requires an
  explicit candidate list because Cedar has no global directory.
  An opt-in in-process entity store would let the spec's pattern
  shape return a full enumeration without leaving Cedar.

## Next (3-6 months)

- Runtime key rotation for the **issuing** authorities. The consuming
  side is done as of 0.4.0: `--identity-source=spire-upstream` follows
  an upstream CA / JWKS rotation either on `SIGHUP` when the material
  comes from files
  ([ADR 0009](docs/adr/0009-upstream-trust-material-reload.md)) or
  unprompted over the upstream's SPIFFE Workload API with
  `--identity-source-workload-api`
  ([ADR 0010](docs/adr/0010-live-upstream-trust-material.md)), both
  incrementing the `spiffe_sequence` envelope field. When omega is the
  issuer the bundle is still monotonic-at-one for the lifetime of a
  server process, so the disk authority cannot roll its own root
  without a restart.
- SPIFFE CSI driver integration so workloads can mount SVIDs as a
  volume instead of dialing the agent's Unix socket.
- step-ca and Vault PKI rotation handling (today they serve a
  stale bundle on transient errors; rotation-aware short-circuit
  via `spiffe_sequence` comparison waits on the issuing-side
  rotation work above).

## Later (6-12 months)

- SCIM 2.0 provisioning endpoint for the Human subject (the OIDC
  side - `POST /v1/oidc/exchange` accepting Keycloak / Okta / Entra
  ID / Google Workspace ID tokens against per-IdP audience and
  template - has shipped; provisioning the user catalog ahead of
  first login is the remaining piece).
- Native-arm64 image build matrix (today the multi-arch image is
  cross-compiled on amd64 runners; `ubuntu-24.04-arm` runners would
  give a faster + more honest arm64 binary).
- Cloud HSM / KMS-backed CA upstream plugins (AWS Private CA, GCP CAS,
  Azure Key Vault). The interface seam is in place
  ([ADR 0005](docs/adr/0005-ca-plugin-architecture.md)) and two
  non-disk backends have shipped (`--ca-backend=vault-pki` and
  `--ca-backend=step-ca`); the remaining backends follow the same shape
  (one `Kind` constant + one `Authority` impl + one `identity.New`
  switch case + tests against a fake HTTP backend), with
  [`docs/ca-plugin-guide.md`](docs/ca-plugin-guide.md) as the
  walkthrough. Demoted from Now in September 2026: these extend the
  **issuing** side, and the project's near-term weight is on consuming
  an upstream SPIFFE trust domain and on the AuthZEN / Cedar surface.
  Nothing blocks a contributor from picking one up — the seam and the
  guide exist precisely so that is a self-contained change.

## Tracking (research / spec watch)

- IETF WIMSE multi-domain identity. Track WG draft progress before
  committing to an in-tree implementation.
- NIST PQC: ML-DSA / ML-KEM / SLH-DSA support for CA and JWT-SVID
  signing once Go's standard library exposes stable APIs.

## Non-goals

Items in [docs/non-goals.md](docs/non-goals.md) are not on the roadmap
and will not be added without a scope amendment via GitHub Discussion.

## How this roadmap is maintained

This file is the roadmap of record; there is no parallel issue-tracker
representation to keep in sync. An item is added by opening a PR that
places it under a horizon and says why it belongs there, and removed by
the PR that ships it — which also lands the `CHANGELOG.md` entry, so a
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
