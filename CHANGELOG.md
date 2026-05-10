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
