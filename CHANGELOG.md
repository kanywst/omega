# Changelog

All notable changes to Omega are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and
versions follow [Semantic Versioning 2.0.0](https://semver.org/), with
the pre-1.0 caveat that minor version bumps may include breaking
changes (see [SECURITY.md](SECURITY.md)).

## [Unreleased]

### Added

- [`ROADMAP.md`](ROADMAP.md) enumerating the public roadmap by
  horizon.
- [`ADOPTERS.md`](ADOPTERS.md) template for production and evaluating
  users.
- [`CHANGELOG.md`](CHANGELOG.md) (this file) in Keep a Changelog
  1.1.0 format.
- [`RELEASING.md`](RELEASING.md) documenting the tag-to-release flow.
- [`.github/CODEOWNERS`](.github/CODEOWNERS) for review routing.
- [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
  with the design-philosophy layer check.
- [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) forms for bug,
  feature, and RFC.
- OpenSSF Scorecard and CodeQL workflows under `.github/workflows/`,
  with the corresponding badges in the README.
- [`api/openapi.yaml`](api/openapi.yaml) - OpenAPI 3.1 specification
  covering every HTTP endpoint the control plane serves, with a CI
  `openapi` job that runs `redocly lint` on every push.
- [`docs/threat-model.md`](docs/threat-model.md) - STRIDE-based
  threat model covering the trust boundaries, assets, and threats
  the project mitigates today, plus the out-of-scope threats and
  their recommended out-of-tree mitigations.
- [`docs/adr/`](docs/adr/) - Architecture Decision Records, with the
  retroactive 0001-0004 covering Cedar as the default PDP, Postgres
  advisory-lock HA over in-process Raft, short-lived SVIDs over
  CRL/OCSP, and the single-binary three-roles packaging.
- Release supply-chain steps in the `image` job, gated to tag pushes:
  - cosign keyless signing of the multi-arch image at digest;
  - per-platform SPDX SBOM generation via `anchore/sbom-action`,
    each attached to its own per-arch manifest as a cosign
    attestation (Syft resolves a manifest-list reference to one
    platform, so an index-level attestation would describe only
    amd64 and silently mis-cover arm64 consumers);
  - GitHub-native SLSA Build Level 3 provenance attestation
    pushed to the registry alongside the image.

  Verification commands (`cosign verify`, `cosign verify-attestation`,
  `gh attestation verify`) are documented in `RELEASING.md`.
- Helm chart cosign keyless signing in the `chart-release` job. After
  `helm/chart-releaser-action` packages `omega-X.Y.Z.tgz` and creates
  the matching GitHub Release, the tarball is signed with
  `cosign sign-blob` and the resulting sigstore bundle is uploaded
  to the same release. Downstream consumers can `gh release download`
  the bundle and `cosign verify-blob` against the chart after
  `helm pull` (verification command in `RELEASING.md`).
- `omega server --issuer-url <url>` flag and a new
  `GET /.well-known/openid-configuration` endpoint. When the flag
  is set, JWT-SVIDs carry `iss: <url>` and the discovery document
  advertises `<url>/v1/jwt/bundle` as `jwks_uri`, so external OIDC
  relying parties (AWS IAM OIDC trust, GCP Workload Identity
  Federation, Kubernetes ServiceAccount issuer trust) can verify
  Omega-issued tokens without a custom adapter. With the flag
  unset, JWT-SVID behaviour is unchanged (no `iss` claim, no
  discovery document - the endpoint returns 404).
- `POST /access/v1/evaluations` - AuthZEN 1.0 batch evaluation. Top
  level `subject` / `action` / `resource` / `context` act as
  defaults that each entry in `evaluations` inherits unless
  overridden. Returns decisions in input order. Audited per
  decision so the hash chain records one row per decision, same
  shape as the single-evaluation endpoint. Closes the spec-required
  AuthZEN 1.0 §5.2 conformance gap (Search APIs are optional and
  remain on the roadmap).
- `examples/audit-otlp/` - end-to-end demo of the OTLP/HTTP-protobuf
  audit forwarder. `cmd/otlp-sink` decodes
  `ExportLogsServiceRequest` bodies into JSONL; `run-demo.sh`
  drives a domain create + an AuthZEN evaluation and asserts both
  rows arrived at the sink with their hash-chain attributes
  populated. Added to the CI examples matrix.
- `examples/oidc-federation/` - end-to-end demo of
  `POST /v1/oidc/exchange` driven by a tiny in-process mock OIDC
  IdP (`mock-idp`). `make demo` exchanges an ID token for an omega
  JWT-SVID and verifies the rendered SPIFFE ID plus the RFC 8693
  `act` claim recording the upstream IdP. Added to the CI examples
  matrix so a regression in the OIDC path fails the same way every
  other example demo would.
- OIDC IdP federation for the Human principal. `omega server` gains
  a repeatable `--oidc-idp 'name=...,issuer=...,audience=...,
  template=...'` flag and a new `POST /v1/oidc/exchange` endpoint:
  a workload presents an ID token issued by a configured upstream
  IdP (Keycloak / Okta / Entra ID / Google Workspace / Dex /
  Authentik / ...), omega validates the token against the IdP's
  JWKS (OIDC Discovery + signature + iss / aud / exp), renders a
  SPIFFE ID from the IdP's template using `{idp}`, `{sub}`,
  `{email}`, `{preferred_username}`, `{name}` placeholders, and
  issues a fresh omega JWT-SVID with the upstream IdP recorded as
  an RFC 8693 `act` claim. JWT-SVID TTL is capped at the upstream
  token's remaining lifetime. Promotes the Human row in the
  "Three subjects" table from `tracked` to `partial` (OIDC done,
  SCIM still tracked).
- OTLP/HTTP-protobuf audit forwarder. `omega server` gains
  `--audit-otlp-endpoint`, `--audit-otlp-insecure`, and a repeatable
  `--audit-otlp-header 'Key: value'` flag; each audit row is shipped
  to the configured collector as one `LogRecord` with hash-chain
  fields surfaced as attributes (`omega.audit.{seq,kind,hash,
  prev_hash,subject,decision,payload}`). Watermark is independent
  from the existing webhook forwarder, so the two can run together.
  Empty endpoint keeps OTLP forwarding off.
- `POST /v1/attest/k8s` - Kubernetes ServiceAccount projected token
  attestation. Workload presents the projected token plus a CSR;
  the server validates the token through kube-apiserver's
  `TokenReview` API, renders a SPIFFE ID from a configurable
  template (`{namespace}`, `{serviceaccount}`, `{podname}`), and
  signs the CSR. Wired through three new flags on `omega server`:
  `--k8s-attest=true` to enable, `--k8s-svid-template=...` to
  shape the SPIFFE ID, `--k8s-token-audience=...` to constrain
  the accepted audience, plus the existing `--kubeconfig` for
  out-of-cluster runs. Default is disabled; the endpoint returns
  404 in that case.

## [0.0.1] - 2026-05-01

Initial public release. Establishes the project skeleton, the
SPIFFE-compatible single-binary control plane, the AuthZEN 1.0 PDP,
and the Kubernetes operator.

### Added

- `omega` single binary with `server`, `agent`, `operator`, `domain`,
  `policy`, `svid` subcommands.
- Self-signed CA with X.509-SVID (30-minute) and JWT-SVID (5-minute)
  issuance.
- SPIFFE Workload API over a Unix socket with peercred (UID)
  attestation. `FetchX509SVID`, `FetchX509Bundles`, `FetchJWTSVID`,
  `FetchJWTBundles` are all served.
- SQLite default storage; Postgres backend with `pg_try_advisory_lock`
  leader election for HA.
- AuthZEN 1.0 PDP endpoint at `POST /access/v1/evaluation`, Cedar
  embedded as the default policy engine.
- RFC 8693 token exchange endpoint at `POST /v1/token/exchange` with
  nested `act` claims for delegation chains.
- SPIFFE federation via `--federate-with name=...,url=...`.
- Tamper-evident audit log with hash chain, `GET /v1/audit/verify`
  walker, and webhook forwarder (`audit.Pump`).
- `OmegaDomain` CRD and Kubernetes operator (`omega operator`).
- cert-manager external Issuer (`OmegaIssuer`).
- Next.js admin dashboard under `ui/`.
- Prometheus metrics and OpenTelemetry tracing; self-contained
  Prometheus + Grafana stack in `examples/observability/`.
- Examples: `hello-svid`, `federation`, `postgres`, `postgres-ha`,
  `mcp-a2a-delegation`, `audit-siem`, `envoy-ext-authz`, `operator`.
- Helm chart published at <https://0-draft.github.io/omega/> via
  `chart-releaser`.
- CI matrix: build, race tests, cross-compile, end-to-end demo,
  example demos, helm lint, kind-based operator smoke test,
  govulncheck, gosec, markdownlint.

[Unreleased]: https://github.com/0-draft/omega/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/0-draft/omega/releases/tag/v0.0.1
