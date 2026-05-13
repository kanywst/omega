# Roadmap

This page is the public roadmap for Omega. It complements the charter
in [docs/scope.md](docs/scope.md) and the layer rules in
[docs/design-philosophy.md](docs/design-philosophy.md): scope says
*what* is in, design philosophy says *where* a feature lives, and this
page says *when*.

Items are grouped by horizon, not by semver version. Pre-1.0 we
release as features are ready rather than on a fixed cadence; see
[RELEASING.md](RELEASING.md).

## Now (next release, post-0.0.2)

- Cloud HSM / KMS-backed CA upstream plugins (AWS Private CA,
  GCP CAS, Azure Key Vault). The interface seam is in place
  ([ADR 0005](docs/adr/0005-ca-plugin-architecture.md)) and two
  non-disk backends have shipped (`--ca-backend=vault-pki` and
  `--ca-backend=step-ca`); remaining backends follow the same shape
  (one `Kind` constant + one `Authority` impl + one `identity.New`
  switch case + tests against a fake HTTP backend), with
  [`docs/ca-plugin-guide.md`](docs/ca-plugin-guide.md) as the
  walkthrough.
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

- Runtime key rotation for the disk authority, with the
  `spiffe_sequence` envelope field in the TDF bundle finally
  incrementing on each rotation. Today the bundle is
  monotonic-at-one for the lifetime of a server process.
- SPIFFE CSI driver integration so workloads can mount SVIDs as a
  volume instead of dialing the agent's Unix socket.
- step-ca and Vault PKI rotation handling (today they serve a
  stale bundle on transient errors; rotation-aware short-circuit
  via `spiffe_sequence` comparison waits on the rotation work
  above).

## Later (6-12 months)

- SCIM 2.0 provisioning endpoint for the Human subject (the OIDC
  side - `POST /v1/oidc/exchange` accepting Keycloak / Okta / Entra
  ID / Google Workspace ID tokens against per-IdP audience and
  template - has shipped; provisioning the user catalog ahead of
  first login is the remaining piece).
- Native-arm64 image build matrix (today the multi-arch image is
  cross-compiled on amd64 runners; `ubuntu-24.04-arm` runners would
  give a faster + more honest arm64 binary).

## Tracking (research / spec watch)

- IETF WIMSE multi-domain identity. Track WG draft progress before
  committing to an in-tree implementation.
- NIST PQC: ML-DSA / ML-KEM / SLH-DSA support for CA and JWT-SVID
  signing once Go's standard library exposes stable APIs.
- SPIFFE CSI driver integration.

## Non-goals

Items in [docs/non-goals.md](docs/non-goals.md) are not on the roadmap
and will not be added without a scope amendment via GitHub Discussion.

## How this roadmap is maintained

Each item here corresponds to an open issue with the `kind/roadmap`
label. Closing the issue removes the item; opening one in the right
horizon adds it. Maintainers revisit horizons quarterly and update
this page in the same PR that updates `CHANGELOG.md` for a release.
