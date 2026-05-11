# Roadmap

This page is the public roadmap for Omega. It complements the charter
in [docs/scope.md](docs/scope.md) and the layer rules in
[docs/design-philosophy.md](docs/design-philosophy.md): scope says
*what* is in, design philosophy says *where* a feature lives, and this
page says *when*.

Items are grouped by horizon, not by semver version. Pre-1.0 we
release as features are ready rather than on a fixed cadence; see
[RELEASING.md](RELEASING.md).

## Now (next release)

- CNCF supply-chain baseline: OpenSSF Scorecard, CodeQL, container
  signing (cosign keyless), SBOM (SPDX), SLSA Level 3 provenance.
- OpenAPI 3.1 specification covering every HTTP endpoint, validated
  in CI.
- Threat model document (`docs/threat-model.md`) and the first batch
  of architecture decision records (`docs/adr/`) covering CA, PDP,
  HA, and scope boundaries.

## Next (3-6 months)

- AuthZEN 1.0 batch evaluation endpoint
  (`POST /access/v1/evaluations`) and Search APIs (subject / resource
  / action). Required for full spec conformance and for the admin
  UI's "what can this subject do" inventory view.
- Agent-side Kubernetes workload attestor (cgroup-based pod
  introspection): the server-side `POST /v1/attest/k8s` endpoint
  has shipped; the SPIRE-style "agent attests workloads by
  inspecting `/proc/<pid>/cgroup` then calling kube-apiserver" path
  is the remaining bit.

## Later (6-12 months)

- SCIM 2.0 provisioning endpoint for the Human subject (the OIDC
  side - `POST /v1/oidc/exchange` accepting Keycloak / Okta / Entra
  ID / Google Workspace ID tokens against per-IdP audience and
  template - has shipped; provisioning the user catalog ahead of
  first login is the remaining piece).
- HSM / KMS-backed CA upstream plugins (Vault PKI, step-ca,
  AWS Private CA, GCP CAS, Azure Key Vault). The interface seam
  is in place ([ADR 0005](docs/adr/0005-ca-plugin-architecture.md)
  with the per-backend how-to in
  [docs/ca-plugin-guide.md](docs/ca-plugin-guide.md)); individual
  backend PRs land here as upstream vendors are picked off the
  list.

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
