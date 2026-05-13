# Changelog

All notable changes to Omega are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and
versions follow [Semantic Versioning 2.0.0](https://semver.org/), with
the pre-1.0 caveat that minor version bumps may include breaking
changes (see [SECURITY.md](SECURITY.md)).

## [Unreleased]

## [0.0.2] - 2026-05-13

Substantial conformance, supply-chain, and CA-plugin work since
0.0.1. Highlights: SPIFFE Trust Domain Format endpoint and
federation pump migration; AuthZEN discovery, batch, and
candidate-set Search APIs; OIDC discovery + IdP federation; K8s
attestor; Vault PKI and step-ca CA backends; Authority plugin
architecture (ADR 0005); cosign-signed images, Helm charts, and
SLSA provenance; per-peer federation scheduling; full STRIDE
threat model and section-by-section SPIFFE / AuthZEN conformance
matrices.

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
- `--ca-backend=step-ca` — second non-disk CA backend. omega
  forwards CSRs to Smallstep step-ca's `POST /1.0/sign` endpoint,
  authenticated with a one-time-token (OTT) signed by a JWK
  provisioner whose matching public JWK is configured in step-ca's
  `ca.json`. The OTT pins the SPIFFE ID via `sans`, the root via
  `sha`, and a 5-minute `exp` so a leaked OTT cannot be replayed
  long after the fact. Trust anchors come from `GET /roots.pem`
  (cached with the same Lock/check/Unlock/fetch/Lock/store pattern
  as the Vault backend) so a transient step-ca blip serves the
  stale bundle instead of breaking every workload's handshake. JWT
  signing stays local for the same ADR 0005 reason that Vault PKI
  does it that way. New flags: `--ca-step-ca-url`,
  `--ca-step-ca-provisioner`, `--ca-step-ca-provisioner-key-file`,
  `--ca-step-ca-ca-cert`. Validates the Plugin pattern on a second
  upstream signer.
- Federation pump runs each peer in its own goroutine, with an
  independent poll cadence derived from that peer's TDF
  `spiffe_refresh_hint`. A 10s-hint peer and a 1h-hint peer now
  sleep on their own rhythms instead of being forced into a single
  global tick driven by the smallest hint. Per-peer effective
  refresh is `min(operator-configured-refresh, peer-hint)` clamped
  to `[10s, 1h]`. The previously exported `EffectiveRefresh()`
  diagnostic is replaced by `PeerRefresh(trustDomain)`; no external
  callers in-tree.
- `POST /access/v1/search/{subject,resource,action}` — AuthZEN 1.0
  §5.3 Search APIs in a candidate-set variant. Each endpoint takes
  an explicit list of candidates for the dimension being searched
  (`subjects` / `resources` / `actions`) plus the two other
  fully-specified dimensions, runs every candidate through the same
  Cedar PDP path as `POST /access/v1/evaluation`, and returns those
  whose decision is `allow`. The spec's pattern shape
  (`subject: {type: "user"}` with no id) is rejected because Cedar
  has no global principal directory and §5.3.2 expressly tells PDPs
  to error when they cannot resolve the search space - a
  candidate-list refinement is the honest take on that contract.
  Pagination via offset/size with an `offset:N` continuation token,
  per-candidate cap of `MaxSearchCandidates = 100` (same rationale
  as the batch endpoint), audit row per evaluation tagged with the
  search dimension + index. The discovery document at
  `/.well-known/authzen-configuration` now advertises all three
  endpoints. Moves `docs/conformance-authzen.md` §4.3 from
  `deferred` to `partial`.
- Federation pump now consumes peers via `GET /v1/spiffe-bundle`
  (SPIFFE Trust Domain Format), falling back to `GET /v1/bundle`
  PEM when the peer returns 404 - so a freshly-built omega still
  federates with peers older than the spiffe-bundle PR. TDF
  responses are parsed through `go-spiffe v2`'s `spiffebundle.Read`
  (same parser a SPIRE agent would run), and the peer-supplied
  `spiffe_refresh_hint` drives the effective per-round poll
  interval as `min(operator-configured-refresh, min-peer-hint)`,
  clamped to `[10s, 1h]`. The legacy PEM path now also parses each
  returned CERTIFICATE block as defence-in-depth so a malformed
  upstream bundle is rejected instead of silently propagating to
  every workload's mTLS handshake.
- `examples/spiffe-bundle-tdf/` — runnable demo proving omega's
  `GET /v1/spiffe-bundle` response is consumed end-to-end by the
  upstream `go-spiffe v2` SDK. The tiny `cmd/consumer` binary
  HTTP-GETs the endpoint, hands the body to
  `spiffebundle.Read(td, body)` from
  `github.com/spiffe/go-spiffe/v2/bundle/spiffebundle`, and
  asserts the parsed bundle exposes both X.509 and JWT
  authorities plus the `SequenceNumber` and `RefreshHint`
  envelope fields. Closes the interop story for the SPIFFE TDF
  endpoint: any regression that breaks the on-the-wire shape
  trips the SDK parser instead of silently working against a
  permissive hand-rolled decoder. Added to the CI examples
  matrix.
- `examples/ca-step-ca/` — runnable demo of the step-ca backend.
  `mock-step-ca` Go binary stands up its own ECDSA Root CA and
  exposes the two endpoints omega calls (`GET /roots.pem`,
  `POST /1.0/sign`); a tiny inline `keygen.go` mints a fresh
  provisioner JWK pair per run; `run-demo.sh` boots omega with
  `--ca-backend=step-ca`, fetches the bundle (must equal the mock
  step-ca CA), submits a workload CSR through `POST /v1/svid`, and
  asserts the issued leaf chains to the bundle and carries the
  requested SPIFFE ID URI SAN. The mock verifies the OTT signature
  on every `/1.0/sign` so a regression that breaks omega's OTT
  minting trips the demo. Added to the CI examples matrix.
- `examples/k8s-attest/` — runnable kind-based demo of the K8s
  attestor. Boots a one-node kind cluster, mints a ServiceAccount
  projected token via `kubectl create token --audience=omega`,
  starts `omega server` out-of-cluster against the kind kubeconfig
  with `--k8s-attest`, and asserts that the correct-audience token
  yields an SVID whose SPIFFE ID is derived from
  `(namespace, serviceaccount)` and chains to `/v1/bundle`, while
  a wrong-audience token is rejected with `HTTP 401`. A new
  `kind-k8s-attest` CI job mirrors `kind-operator` so the demo
  runs on every PR.
- `GET /v1/spiffe-bundle` — SPIFFE Trust Domain Format (TDF)
  endpoint. Returns the [SPIFFE Trust Domain and Bundle 1.0 §4](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md)
  JSON document: X.509-SVID trust anchors (`use: x509-svid`, full
  DER in `x5c`) and JWT-SVID signing keys (`use: jwt-svid`) in one
  JWK set, with `spiffe_sequence` and `spiffe_refresh_hint` in the
  envelope. Peers consuming this endpoint replace the pair of
  `/v1/bundle` (PEM) + `/v1/jwt/bundle` (JWKS) with one fetch.
  `spiffe_refresh_hint` is configurable via the new
  `--spiffe-bundle-refresh-hint` flag (default `5m`).
  `spiffe_sequence` is fixed at `1` until runtime key rotation
  lands - omega does not rotate roots without a restart today, so
  the bundle is monotonic-at-one for the life of a server process.
  Closes `docs/conformance-spiffe.md` §4.1 (partial → implemented)
  and moves §6 from deferred → partial.
- `GET /.well-known/authzen-configuration` — OpenID AuthZEN 1.0 §8
  discovery document advertising the single-decision and batch
  evaluation endpoints. The PDP base URL is `--issuer-url`
  (canonical, validated `https`, no query/fragment) so a PEP
  consuming the document cannot be redirected to an
  attacker-controlled URL through a spoofed `Host` header. Returns
  `404` when `--issuer-url` is not set, mirroring the OIDC
  discovery handler. The three optional Search API endpoints are
  intentionally omitted - per §8 their absence signals "not
  implemented". Closes the last "deferred" row in
  `docs/conformance-authzen.md` §8.
- `examples/ca-vault-pki/` — runnable demo of the vault-pki
  backend. `mock-vault` Go binary stands up its own ECDSA Root CA
  and exposes the two endpoints omega calls; `run-demo.sh` boots
  omega with `--ca-backend=vault-pki`, fetches a bundle (must
  equal the mock CA), submits a workload CSR through
  `POST /v1/svid`, and asserts the issued leaf both chains to the
  bundle and carries the requested SPIFFE ID URI SAN. Added to
  the CI examples matrix.
- `--ca-backend=vault-pki` — first non-disk CA backend. omega
  forwards CSRs to a Vault PKI mount via `POST /v1/<mount>/sign/<role>`
  and serves the trust anchors via `GET /v1/<mount>/ca_chain`, so
  the X.509 root key never sits on the omega process's disk. JWT
  signing stays local (the disk-style JWT key under `--data-dir`);
  per-token Vault Transit signing would add a network hop to every
  JWT validation and the 5-minute JWT-SVID TTL makes the trade-off
  unattractive (ADR 0005). New flags: `--ca-backend`,
  `--ca-vault-pki-addr`, `--ca-vault-pki-token`,
  `--ca-vault-pki-mount`, `--ca-vault-pki-role`. A boot-time
  `ca_chain` probe surfaces misconfiguration at startup; a stale
  bundle is served if a later refresh fails, so a transient Vault
  blip does not break workload mTLS.
- `Authority.IssueSVID` signature changed from `(id, pub
  crypto.PublicKey)` to `(id, csr *x509.CertificateRequest)`.
  Pre-1.0 interface change, contained because no out-of-tree
  backends exist yet (ADR 0005 documents this). Backends that
  delegate to an upstream signer (Vault, AWS PCA) need the full
  CSR; the disk backend continues to use `csr.PublicKey`.
- `omega svid validate <jwt> --audience <aud>` subcommand. Reads the
  token from the positional argument (or `-` for stdin), dials the
  local agent's Workload API socket, calls `ValidateJWTSVID`, and
  prints the SPIFFE ID + audience + expiry + selected claims.
  `--json` switches to a single-line JSON shape for piping into
  `jq`. Operator-facing front-end for the RPC that has been
  available to gRPC clients since v0.0.1; no Go code needed to
  ask "is this token good".
- Agent-side JWKS cache. `internal/agent/workloadapi/server.go`
  now serves `/v1/jwt/bundle` from a 1-minute TTL'd cache shared
  between `FetchJWTBundles` (the streaming RPC) and
  `ValidateJWTSVID` (the unary RPC). Refresh is single-flight via
  an RWMutex double-check, so 100 concurrent validations after a
  workload restart cost one control-plane fetch, not 100.
  Conformance §4.4 entry tightened to match.
- [`docs/conformance-spiffe.md`](docs/conformance-spiffe.md) and
  [`docs/conformance-authzen.md`](docs/conformance-authzen.md) -
  section-by-section conformance matrices against the SPIFFE
  specifications (Workload API, X.509-SVID, JWT-SVID, Trust
  Bundle Format, Federation) and the AuthZEN 1.0 Final
  Specification. Status per spec section: implemented / partial /
  deferred / not applicable, with omega's source pointer and the
  deliberate non-implementations (CRL/OCSP, AuthZEN Search APIs,
  Workload-API `ValidateJWTSVID` RPC) called out at the end.
- [`docs/adr/0005-ca-plugin-architecture.md`](docs/adr/0005-ca-plugin-architecture.md)
  records the `identity.Authority` interface as the Plugin-layer
  seam for CA backends (HSM / KMS / external CAs). Codifies what
  was implicit in the existing code: new backends are one `Kind`
  constant + one struct that satisfies the interface + one
  `switch` case in `identity.New`. Disk backend stays as the
  zero-config default.
- [`docs/ca-plugin-guide.md`](docs/ca-plugin-guide.md) is the
  step-by-step companion - seven steps from picking a Kind name
  to README updates - including the env-var test-gating pattern
  for backends that require a real upstream (Vault, KMS, etc.).
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

[Unreleased]: https://github.com/0-draft/omega/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/0-draft/omega/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/0-draft/omega/releases/tag/v0.0.1
