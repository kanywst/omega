# Changelog

All notable changes to Omega are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and
versions follow [Semantic Versioning 2.0.0](https://semver.org/), with
the pre-1.0 caveat that minor version bumps may include breaking
changes (see [SECURITY.md](SECURITY.md)).

## [Unreleased]

### Changed

- **`omega policy delete` no longer deletes whatever version is stored by default.** It needs `--if-match` with the ETag `omega policy get` printed, or `--force` for the previous behaviour, so a policy someone changed since is not removed by mistake.

### Fixed

- **A policy bundle now replaces an engine's whole policy set.** Loading a bundle left the engine's file and stored policy sets from before it, so a later stored-policy update on the same engine would have dropped the bundle's policies. Node agents never do that today; the engine no longer allows it.
- **Policy validation no longer re-parses every `--policy-dir` file.** The file policy ids are collected when the files load, so `POST /v1/policies/validate` and writes check a stored policy against them without parsing the files on each call.

## [0.12.0] - 2026-10-18

Brings policy management into the control plane and tightens decisions: Cedar policies can be managed over `/v1/policies`, with every change recorded in the audit chain in the same transaction, and every AuthZEN decision carries the PEP's request id and an explanatory `context`.

A minor with a breaking change in decisions: a `forbid` that fails to evaluate (for example on a missing attribute) now denies instead of being skipped, so requests it used to let through are refused. See Changed. Before the first `/v1/policies` write, upgrade every server replica and node agent.

### Added

- **Cedar policies stored in the control plane.** `/v1/policies` lists, reads, creates, updates and deletes Cedar policies kept in the database (SQLite or Postgres), and `POST /v1/policies/validate` checks one without storing it; `omega policy list|get|apply|delete` is the CLI. The engine evaluates them together with the `--policy-dir` files, which the API lists as read-only. Writes are leader-only, need `--require-auth` and a `--domain-root-admin`, need `If-Match` to update or delete, and are written in one transaction with a `policy.create`, `policy.update` or `policy.delete` audit row carrying the old and new digests. An invalid policy is refused with `400`. Every replica reloads stored policies every five seconds and the bundle served to node agents carries them; a stored set that does not load, or that differs from what the audit chain records (a policy changed in the database behind the API), keeps the last one and fails evaluation closed at once (`omega_stored_policy_set_load_failures_total`). Every Cedar id a stored policy defines is prefixed with `api/<id>::`. See [ADR 0022](docs/adr/0022-stored-policies.md) and [docs/policies.md](docs/policies.md).
- **AuthZEN request identification and decision context.** Every `/access/v1/*` endpoint, on the server and on the agent's local PDP, echoes the `X-Request-ID` header unchanged (AuthZEN 1.0 §10.1.3) and records it as `request_id` in the audit row of each decision; it is also set on the server span. An id that is not 1 to 128 bytes of letters, digits and `-._~:/+=@;` is stored as `request_id_sha256` instead, so no oversized or log-unsafe caller string reaches the audit chain. Decisions, including each entry of a batch, now carry the optional response `context` (§5.5.1, §6.2): `reasons` lists the policies that determined the decision and `errors` the ids of the policies Cedar skipped because evaluating them failed; Cedar's error messages are recorded in the audit row only. The top-level `reasons` stays. See [docs/conformance-authzen.md](docs/conformance-authzen.md).

### Changed

- **Security: a `forbid` that fails to evaluate now denies.** Cedar skips a policy whose evaluation fails, for example on a missing attribute, so a `forbid` that errored left a matching `permit` to allow. omega now denies whenever a `forbid` errors, on the server (single, batch and search) and on the agent's local PDP, and names that policy in `reasons` and `context.errors`. A `permit` that errors still grants nothing. Requests that a failing `forbid` used to let through are now denied.

## [0.11.0] - 2026-10-16

Makes the upstream CA overlap durable: the CAs kept from a Vault PKI, step-ca or AWS Private CA rotation survive restarts and are shared by replicas, each stored row authenticated under the audit HMAC key, and `spiffe_sequence` never goes back after a restart for any backend. Adds an issuing-CA-only trust bundle for AWS Private CA.

No breaking changes. The overlap is stored only with `--audit-hmac-key-file`; without it the kept set stays in memory as before and the server warns at start when `--upstream-ca-grace` is set. The server now refuses to start if it cannot read the stored `spiffe_sequence`, rather than restarting it at 1.

### Added

- **Issuing-CA-only bundle for AWS Private CA.** `--ca-aws-pca-bundle=issuing` (Helm: `server.ca.awsPCA.bundle`) serves only the issuing CA as the trust anchor, instead of the issuing CA plus the chain to the root, so certificates from other subordinates of the same root no longer verify for the trust domain. Peers and federation partners must accept a CA that is not self-signed as an anchor. The default, `chain`, keeps the current behavior. See [docs/ca-aws-pca.md](docs/ca-aws-pca.md#trust-bundle).

### Fixed

- **The upstream CA overlap and `spiffe_sequence` survive restarts and are shared by replicas.** The CAs kept by `--upstream-ca-grace` from a Vault PKI, step-ca or AWS Private CA rotation were held in memory, so a restart ended their grace early and Postgres replicas could each serve a different kept set. With `--audit-hmac-key-file` they are now stored in the database (SQLite or Postgres) with their times, each row MAC'd under the audit HMAC key so a database writer without it cannot add a trust anchor, along with the issuer's last published CAs, so a restart restores them and also catches a rotation that happened while Omega was down. Replicas read the shared set on every bundle refresh; only the leader writes it. `spiffe_sequence` is now stored per trust domain for every backend and identity source, so it never goes back after a restart and matches across replicas serving the same bundle. A kept CA taken from the database rather than seen leaving the issuer is recorded in `ca.upstream` as `kept` with the reason `restored`; the other records and the distrust list are unchanged. See [docs/ca-rotation.md](docs/ca-rotation.md).

## [0.10.0] - 2026-10-15

Adds three cloud CA backends (AWS Private CA, Google Cloud CAS and Azure Key Vault), an agent-side Kubernetes workload attestor for the self-issued path, and holds every external issuer's certificates to the X.509-SVID profile.

No breaking changes for existing flags. A Vault PKI role or step-ca provisioner that adds SANs beyond the requested SPIFFE ID, or signs from a CA outside the served bundle, now fails issuance; see Fixed.

### Added

- **Agent-side Kubernetes workload attestor.** `omega agent --k8s-workload-attestor` (Linux) identifies a Workload API peer that runs in a pod on the node by its pod: the peer PID's cgroup names the pod and container, kube-apiserver names the namespace, service account and pod, and `--k8s-workload-svid-template` renders the SPIFFE ID with the server's `--k8s-svid-template` placeholders. Host processes keep the `--map` UID mapping; a pod process never falls back to it. Off by default and meant for the self-issued development and evaluation path, not as a production substitute for SPIRE. Helm: `agent.k8sWorkloadAttestor` (turns on `hostPID` and runs the agent under its own ServiceAccount with `list` on pods). See [ADR 0020](docs/adr/0020-agent-side-kubernetes-workload-attestor.md) and `examples/k8s-workload-attestor/`.
- **Google Cloud CAS backend.** `--ca-backend=gcp-cas` signs X.509-SVIDs through a Certificate Authority Service CA pool (`--ca-gcp-cas-pool`, plus optional `--ca-gcp-cas-endpoint`, `--ca-gcp-cas-issuing-ca` and `--ca-gcp-cas-certificate-template`), authenticating with Application Default Credentials; the bundle comes from the pool's CA certificates and JWT-SVIDs stay locally signed. The Helm chart gains `server.ca.backend` and `server.ca.gcpCas`. See [docs/ca-gcp-cas.md](docs/ca-gcp-cas.md).
- **CA key in Azure Key Vault.** `--ca-backend=azure-keyvault` (`--ca-azure-keyvault-url`, `-key`, `-key-version`, `-ca-cert`) keeps the CA private key in Azure Key Vault or Managed HSM: Omega builds X.509-SVIDs and JWT-SVIDs itself and signs both through the key's `sign` operation (EC P-256), one round trip per SVID. The CA certificate is self-signed through Key Vault at first start or supplied as a file; credentials come from a service principal, workload identity or a managed identity. The Helm chart gains `server.ca` and `server.podLabels`. See [ADR 0021](docs/adr/0021-azure-key-vault-remote-signer.md) and [docs/ca-azure-keyvault.md](docs/ca-azure-keyvault.md).
- **AWS Private CA backend.** `--ca-backend=aws-pca` signs X.509-SVIDs with an AWS Private CA (`--ca-aws-pca-arn`, plus optional `--ca-aws-pca-region`, `--ca-aws-pca-endpoint`, `--ca-aws-pca-template-arn` and `--ca-aws-pca-signing-algorithm`), so the CA key stays in AWS. The SPIFFE ID goes in as an API-passthrough URI SAN, issuance polls until the certificate is ready, and every leaf is checked against the requested ID, the CSR's key and the CA before it is returned. Credentials come from the standard AWS chain; JWT-SVID signing stays local. `--upstream-ca-grace` and `--upstream-ca-distrust` apply to it as to Vault PKI and step-ca. The Helm chart gains `server.ca.backend` and `server.ca.awsPCA`. See [docs/ca-aws-pca.md](docs/ca-aws-pca.md) and `examples/ca-aws-pca/`, which runs against a mock in CI.

### Fixed

- **Stricter checks on certificates from Vault PKI and step-ca.** An issued leaf must now carry exactly the requested SPIFFE ID as its only SAN, not be a CA, assert `digitalSignature` without `keyCertSign` or `cRLSign`, and chain to the bundle Omega serves, as the AWS Private CA and GCP CAS backends already require. A role or provisioner that adds other SANs now fails issuance instead of handing them to the workload.

## [0.9.0] - 2026-10-15

Rotates the built-in CA at runtime, carries trust across Vault PKI and step-ca rotations on request, adds the SPIFFE CSI driver to the Helm chart, and makes the local PDP verify policy bundle signatures by default.

A minor with breaking changes: an agent with a local PDP now needs `--policy-bundle-key` (or `--insecure-unsigned-policy-bundles`), and the chart constrains `agent.hostSocketPath`. See Changed.

### Added

- **Runtime rotation of the built-in CA.** `omega ca prepare`, `activate` and `retire` (plus `status`) rotate the `--ca-backend=disk` CA in place; the server picks up each step on `SIGHUP`, keeps the next and previous CAs in the bundle and JWKS around the switch, verifies JWT-SVIDs by `kid` across them, and advances `spiffe_sequence`. See [ADR 0019](docs/adr/0019-runtime-ca-rotation.md), [docs/ca-rotation.md](docs/ca-rotation.md) and `examples/ca-rotation/`.
- **Overlap across Vault PKI and step-ca rotations (opt-in).** With `--upstream-ca-grace` (for example `24h`; never past the CA's expiry), a CA the external issuer stops publishing stays in Omega's served bundle, locally and to federated peers, so SVIDs it signed keep verifying through the rotation, and `spiffe_sequence` advances when the issuer's bundle changes. It is off by default, since Omega cannot tell a rotation from a revocation. Every change to the kept set is recorded in the audit chain as `ca.upstream`, and `--upstream-ca-distrust` (a fingerprint list re-read on `SIGHUP`) drops a kept CA at once after a compromise. The served bundle now holds only the certificates Omega can parse, re-encoded; a chain member Go cannot parse is dropped with a warning instead of passed through. Federated peers now read the Vault PKI or step-ca bundle live, so an issuer rotation reaches them without a `SIGHUP`.
- **SPIFFE CSI driver in the Helm chart.** `csi.enabled` deploys the upstream SPIFFE CSI driver against the Omega agent's socket directory, so pods mount the Workload API with a `csi.spiffe.io` ephemeral volume instead of a hostPath. `examples/kind-csi` checks it end to end in kind, in CI.

### Changed

- **Breaking: the local PDP verifies bundle signatures by default.** `omega agent --local-pdp-addr` now refuses to start without `--policy-bundle-key`; pass `--insecure-unsigned-policy-bundles` to keep trusting bundles on TLS alone. In the Helm chart `agent.localPDP.verifyBundle` defaults to `true` and needs `server.policyBundleSigningKeySecret`; set it to `false` for the previous behaviour.
- **Breaking (Helm): stricter agent socket directory.** `agent.hostSocketPath` must be under `/run/omega*` or `/var/run/omega*`, because an init container changes its owner and mode on every node. That init container runs as uid 0 with only `CAP_CHOWN`, so a cluster that enforces `runAsNonRoot` on every container rejects the agent pod.

### Fixed

- **The chart's agent can create its socket on a fresh node.** It runs as uid 65532 while kubelet creates its hostPath directory root-owned, so it failed with `bind: permission denied`. An init container with only `CAP_CHOWN` (`omega agent prepare-socket-dir`) now hands the directory to the agent's user; the agent stays non-root.

## [0.8.0] - 2026-10-13

Hardens local policy decisions: the control plane can sign the policy bundle, the node agent refuses unsigned, replayed or stale bundles, decisions survive an agent crash through an on-disk spool, and each local decision is recorded once however often it is resent. Adds `examples/spire-authz`, Omega as the authorization and audit layer on top of a real SPIRE deployment, and builds the arm64 image natively.

A minor rather than a patch: `POST /v1/audit/decisions` now refuses decision and loss ids longer than 128 bytes, and a loss report must carry a digest for each dropped decision.

### Added

- **`examples/spire-authz`.** Real SPIRE issues every identity; Omega, on SPIRE's trust domain, authenticates callers by their SPIRE SVIDs, decides with Cedar by SPIRE path and by groups pushed over SCIM, decides locally on the node, and records it all in one audit chain.
- **Signed policy bundles.** `omega server --policy-bundle-signing-key` (ECDSA P-256, the same on every replica) signs every bundle; `omega agent --policy-bundle-key` refuses an unsigned or wrongly signed one, so a bundle's trust no longer rests on TLS alone. The Helm chart gains `server.policyBundleSigningKeySecret` and `agent.localPDP.verifyBundle`. See [ADR 0018](docs/adr/0018-signed-bundles-and-decision-spool.md).
- **Decision spool.** `omega agent --decision-spool FILE` writes and syncs each decision before answering and requeues the file at start, so an agent crash loses no answered decision. Helm: `agent.localPDP.spool` (an emptyDir, kept across container restarts).
- **Local decisions are recorded once.** `POST /v1/audit/decisions` keys each decision by agent and `decision_id`, and each loss report by `loss_id`, in the same transaction as the audit row, so a batch resent after a lost response or replayed from the spool is not recorded twice.

### Changed

- **`omega agent` runs without `--map` when `--local-pdp-addr` is set**, serving only the local PDP. That is how it runs beside a SPIRE agent, which issues the identities.
- **The container image cross-compiles instead of emulating arm64.** The Dockerfile's builder stage runs on the build platform (`--platform=$BUILDPLATFORM`), so the linux/arm64 image builds in about the time of the amd64 one, and CI now builds both architectures on every pull request instead of only at release.

## [0.7.0] - 2026-10-12

Adds delegated administration of the namespace and the identity data
policies decide on: a domain tree with per-domain admins, domain-owned
groups with expiring membership, SCIM 2.0 provisioning from an identity
provider, and local policy decisions on the node agent with central
audit. Also adds the ID-JAG authorization grant for AI agents, with
DPoP.

A minor rather than a patch: `POST /v1/domains` now requires a domain's
parent to exist and accepts only dot-separated lowercase labels, and
under `--require-auth` domain writes need an admin of the parent (or a
`--domain-root-admin`). `POST /v1/token/exchange` now enforces a token's
`cnf` binding.

### Added

- **SCIM 2.0 provisioning.** `--scim-idp name=,domain=,token-file=[,template=]` lets an identity provider push users and groups to `/scim/v2/<name>/` with a bearer token. Users map to SPIFFE IDs through the template (default `spiffe://<trust-domain>/humans/{idp}/{externalId}`, matching the ID-JAG grant), and each SCIM group becomes the Omega group `<domain>:<slug>` whose members are its active users. Deactivating or deleting a user removes it from every group at once. Each change commits in one transaction with its `scim.*` audit row, and groups a provider owns are read-only through the Omega group API. See [ADR 0017](docs/adr/0017-scim-provisioning.md), [docs/scim.md](docs/scim.md) and `examples/scim/`.
- **Local policy decisions.** `omega agent --local-pdp-addr` serves AuthZEN evaluations on the node from a copy of the control plane's policy, synced from the new `GET /v1/policy/bundle` (content-hashed revision, ETag), and ships every decision to the new `POST /v1/audit/decisions`, where it joins the audit chain as `access.evaluate.local` under the agent's SPIFFE ID. The server serves the bundle and accepts decisions only under `--require-auth` for callers named with the new `--decision-recorder`, and reports how many rows of a failed batch it recorded so they are not resent. The local PDP fails closed before its first sync, after `--policy-max-age` without one, and while `--decision-buffer` decisions are unrecorded; it needs an `https` control plane, a pinned `--server-ca` and a client SVID, loads bundles only for its SVID's trust domain, and binds loopback unless `--local-pdp-allow-remote`. The server now reloads `--policy-dir` on `SIGHUP`, and the agent gains `--server-ca`, `--client-cert` and `--client-key` for TLS to the control plane. See [ADR 0016](docs/adr/0016-local-policy-decisions.md), [docs/local-pdp.md](docs/local-pdp.md) and `examples/local-pdp/`.
- **Groups with expiring membership.** A domain's admins create groups in it (`Group::"<domain>:<name>"` in Cedar) and add SPIFFE IDs as members, optionally until an `expires_at` that is checked at evaluation time. New `/v1/domains/{name}/groups` endpoints and `omega group` commands; a domain that owns groups cannot be deleted. See [ADR 0015](docs/adr/0015-groups-with-expiring-membership.md) and [docs/groups.md](docs/groups.md).
- **Domain hierarchy with delegated administration.** Each domain carries admin SPIFFE IDs that administer it and everything below it; `--domain-root-admin` principals create top-level domains. New `DELETE /v1/domains/{name}`, `POST` and `DELETE /v1/domains/{name}/admins`, matching `omega domain delete` and `omega domain admins add|remove`, and `OmegaDomain.spec.admins`. `omega operator` gains `--server-ca`, `--client-cert` and `--client-key` so it can act under `--require-auth`, and the `omega_domains_unprojected` gauge counts stored domains left out of policy evaluation. Every domain is a Cedar entity `Domain::"<name>"` and every `Spiffe` principal or resource sits in the deepest domain its path names, so policies can use `principal in Domain::"media"`. See [ADR 0014](docs/adr/0014-domain-hierarchy-and-delegation.md) and [docs/domains.md](docs/domains.md).
- **DPoP (RFC 9449) on the ID-JAG grant.** An ID-JAG bound with `cnf.jkt` is redeemed with a DPoP proof for that key, and any valid proof binds the issued JWT-SVID to its key (`cnf.jkt`, `token_type: DPoP`). Proofs are checked for compact serialization, `typ`, signature, `htm`, `htu`, a one-minute `iat` window and `jti` replay (hashed, bounded cache). The metadata lists `dpop_signing_alg_values_supported`. See [ADR 0013](docs/adr/0013-dpop-sender-constrained-tokens.md).
- **`--client-cert-optional`.** With `--client-ca` and `--require-auth` (it is refused without them), the TLS listener verifies a client certificate when one is presented instead of requiring it on every connection. Routes gated by `--require-auth` still require a verified SPIFFE client certificate, so JWT-SVID clients can use the `spiffe_jwt` method of the ID-JAG grant under `--require-auth` (each client assertion is single use), and workloads without an SVID can reach the enrollment paths. Ungated routes such as `/metrics` become reachable without a certificate in this mode. See [ADR 0012](docs/adr/0012-optional-client-certificates.md).
- **ID-JAG authorization grant on `POST /oauth2/token`.** Omega now accepts an Identity Assertion JWT Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant) from an IdP trusted with `--id-jag-idp`, presented as an RFC 7523 jwt-bearer assertion. The client authenticates with its SPIFFE ID, either an mTLS X.509-SVID or a JWT-SVID `client_assertion` of type `jwt-spiffe` (draft-ietf-oauth-spiffe-client-auth), and must match the ID-JAG's `client_id`. `--id-jag-idp` requires `--require-auth` (mTLS only), unless `--id-jag-insecure-client-binding` opts in to an unbound development mode. The response is a JWT-SVID for the client whose `act` names the user, capped at the ID-JAG's lifetime and usable as the subject token of `POST /v1/token/exchange`. Every grant is evaluated by Cedar as its own action, `token.id_jag`, regardless of `--enforce-token-exchange-policy`, so nothing is issued until a permit is written and no existing `token.exchange` permit applies. Grants and authenticated clients' refusals are audited as `token.id_jag`, and a token is withheld if its grant cannot be recorded. `GET /.well-known/oauth-authorization-server` advertises the endpoint. See [ADR 0011](docs/adr/0011-id-jag-authorization-grant.md).
- `--id-jag-max-assertion-ttl` (default 5m) rejects ID-JAGs and JWT-SVID client assertions with a longer lifetime.
- `--id-jag-insecure-client-binding` lets `--id-jag-idp` run without `--require-auth`, for development.
- [docs/id-jag.md](docs/id-jag.md) and `examples/id-jag/` walk through the flow end to end.

### Changed

- **A domain's parent must exist.** `POST /v1/domains` now rejects `media.news` until `media` exists, rejects names that are not dot-separated lowercase labels, and rejects an explicit `parent` that disagrees with the name. Under `--require-auth` the caller must administer the parent (or be a `--domain-root-admin` for a top-level domain). Create parents first.

### Security

- **`POST /v1/token/exchange` honours `cnf`.** A subject or actor token bound to a DPoP key or a client certificate was accepted as a bearer token. It now needs a DPoP proof for `cnf.jkt` or the matching client certificate for `cnf.x5t#S256`; any other `cnf` is refused. The output keeps the actor's binding (or the subject's, when the actor is the subject's own principal), so a key holder cannot unbind its token by exchanging it with itself.

## [0.6.0] - 2026-10-07

Adds the AuthZEN 1.0 evaluation semantics (§7.1.2) to batch
evaluation, so a PEP can ask for `&&` / `||` short-circuiting instead
of always receiving every decision.

A minor rather than a patch: a batch carrying an unrecognised
`options.evaluations_semantic` now gets a 400 where it previously got
200, and a malformed entry anywhere in a batch fails it before any
entry is evaluated or audited. Callers that never sent `options` and
send well-formed batches are unaffected.

### Added

- **AuthZEN evaluation semantics on `POST /access/v1/evaluations`
  (§7.1.2).** `options.evaluations_semantic` now accepts
  `deny_on_first_deny` and `permit_on_first_permit` alongside the
  default `execute_all`. Under a short-circuit semantic evaluation stops
  at the first deny (or permit), the response array ends with that
  decision as in the specification's examples, and the entries after
  it are neither evaluated nor written to the audit chain. Each audit
  row's `batch` object now carries `semantic`, so a batch of size N with
  fewer than N rows reads as a short circuit rather than as lost events.
  Through 0.5.0 the `options` object was silently ignored, so a PEP
  asking for `&&` semantics got every decision back.

  An unrecognised semantic is a 400 rather than a fallback to
  `execute_all`, for the same reason: a PEP that asked to stop early
  must not act on decisions it never asked to have made. Other keys in
  `options` are accepted and ignored, as §7.1.2 describes the object as
  open-ended.

### Changed

- **A batch is validated in full before anything is evaluated.** A
  malformed entry — one still missing `subject`, `action` or `resource`
  after the top-level defaults are applied, an entity without a `type`
  or `id`, or a `context` Cedar cannot represent — was already a 400,
  but it was reported only when the loop reached it, after the entries
  ahead of it had been evaluated and audited. The checks now run through
  the same `policy.Validate` that `Evaluate` uses. All entries are now merged first, so a
  malformed batch leaves no audit rows, and whether it fails does not
  depend on where a short-circuit semantic would have stopped.

### Dependencies

- `modernc.org/sqlite` 1.58.0 → 1.59.0 and
  `sigs.k8s.io/controller-runtime` 0.25.0 → 0.25.1, both of which ship
  in the binary, plus `modernc.org/libc` 1.75.6 → 1.75.7 pulled in
  behind the former. Six npm packages under `ui/` and two GitHub
  Actions (`anthropics/claude-code-action`, `github/codeql-action`
  4.38.0 → 4.38.1) moved too, neither of which affects what a consumer
  installs.

- **`google.golang.org/grpc` stays on 1.83.2.** The grouped minor bump
  proposed 1.84.0, which is inside the vulnerable range of
  GHSA-2v4p-qf9q-27wj / GO-2026-6443 — a server panic reachable through
  a missing `:authority` or `Host` header. The advisory is fixed on the
  1.82.x and 1.83.x lines but has no fixed 1.84.x release, only an
  unreleased 1.85.0-dev pseudo-version, so taking the bump would have
  moved the binary off a patched version onto an unpatched one.
  Dependabot now carries an `ignore` entry for 1.84.x, to be dropped
  once a fixed release ships.

## [0.5.0] - 2026-09-16

Brings the AuthZEN Search surface to the 1.0 Final Specification, and
turns `golangci-lint` back into a gate that can actually fail.

A minor rather than a patch: the Search `page` object and three
discovery parameter names change shape. Both are corrections toward the
specification rather than preferences, and callers that never sent a
`page` object and never read the discovery document are unaffected.

### Added

- **AuthZEN entity-store mode for Search (`--authzen-search-entity-store`).**
  `POST /access/v1/search/{subject,resource,action}` now accept the
  spec's own request shape — the searched dimension carrying only a
  type, or omitted entirely in the case of Action Search (§8.6.1) — and
  resolve the search space from the Cedar entity store loaded out of
  `--policy-dir/entities.json`. Through 0.4.0 the endpoints required a
  caller-supplied candidate list, which kept them useful but meant a PEP
  written against the spec got a 400.

  Off by default, because switching it on makes `entities.json` the
  definition of who exists: an identity it does not declare is invisible
  to enumeration. That is a claim about a deployment's directory that
  the operator should make deliberately rather than inherit. For the
  same reason, enumerating a type the store has no entities of is a 400
  rather than an empty `results` — the spec permits an empty result set,
  but "no such type here" and "nothing you may touch" are different
  answers and a PEP cannot tell them apart from `[]`.

  Paging applies to the search space rather than to the matches, so each
  request evaluates at most `MaxSearchCandidates` candidates no matter
  how large the store is. The consequence a caller has to know about is
  that a page may come back empty while later pages still hold results,
  which is the loop `next_token` is specified to drive.

  The candidate-list form is unchanged and still works with the flag
  off.

### Fixed

- **Discovery advertised the Search endpoints under non-registered
  names.** `/.well-known/authzen-configuration` emitted
  `subject_search_endpoint` / `resource_search_endpoint` /
  `action_search_endpoint`, where AuthZEN §9.1.1 registers
  `search_subject_endpoint` / `search_resource_endpoint` /
  `search_action_endpoint`. The spec notes that an absent parameter is
  sufficient for a PEP to conclude the PDP cannot serve that API, so any
  client that discovered its endpoints instead of hard-coding them saw a
  PDP with no Search support at all.

- **An explicitly empty candidate list enumerated everything.** With
  entity-store mode on, `"actions": []` was indistinguishable from
  omitting the key, and §8.6.1's pattern *is* the absence of the key —
  so a caller that asked about no actions was answered with every one of
  them. All three dimensions now reject an empty list with a 400 and
  read omission as the pattern shape. `subjects: []` already returned
  400 before this release; the bug was that the new mode quietly changed
  that answer.

- **`page.limit: 0` fell through to the default.** §8.2.1 defines
  `limit` as a non-negative integer, so zero is legal and is how a PEP
  asks whether a search space is non-empty without paying for a single
  PDP evaluation. It is now honoured as written rather than collapsing
  into "no limit" and evaluating up to 100 candidates.

- **`make docker-demo` could not build.** `ui/Dockerfile` copies
  `/app/public` into the runtime image, but `ui/public` has never
  existed in the tree, so the compose build failed at that step — from
  the UI's first commit through v0.4.0. Nothing caught it: no CI job ran
  the compose stack, despite `CLAUDE.md` describing the target as the CI
  smoke test and `RELEASING.md` listing it as a pre-release check. The
  directory is now tracked, and a `docker-demo` job builds the stack on
  every PR so the only thing that exercises `ui/Dockerfile` is no longer
  a command someone has to remember to run.

  That job then failed on its first run against a commit that had a
  second break: `ui/package-lock.json` was missing the
  `@next/swc-win32-x64-msvc` entry `next@16.3.5` declares, which makes
  `npm ci` refuse the lockfile. The `ui` job runs `npm ci` and passed
  anyway, because it pins node 22 whose npm does not check optional
  platform entries; the compose build's node 26 does. Both are fixed.

- **Enumeration walked the whole entity store on every page.**
  `MaxSearchCandidates` bounded how many candidates a request evaluated
  but not how much of the store was scanned and sorted to build that
  window, so a full paginated walk cost O(N²·log N) in store size. The
  per-type index is now built once per policy load: on a 50k-entity
  store one lookup went from 176ms to 21ns.

### Changed

- **A Search request may name its search space only once.** Sending both
  the candidate list and the type-only pattern previously let the
  candidate list win silently; it is now a 400. Action Search is
  unaffected — §8.6.1 omits the `action` key entirely, so there is no
  second way to name the space.

- **Search pagination now uses the spec's shape (BREAKING).** The `page`
  object on a request is `{token, limit}` rather than `{size, offset}`,
  and on a response `{next_token, count}` rather than
  `{size, offset, next_token}`. `next_token` is always present and is
  the empty string on the last page, per §8.2.2. Tokens are opaque and
  carry a fingerprint of the request that minted them: §8.2 requires
  every other field to be identical across a paginated sequence, and a
  token replayed against a changed request is now a 400. The
  fingerprint travels inside the token rather than in server-side state,
  so any replica can serve the next page.

  Callers that never sent a `page` object are unaffected.

- **`total` is not emitted on Search responses.** Paging happens before
  evaluation, so the number of matches across all pages is unknown when
  a page is built; reporting the size of the search space under a key
  the spec defines as the number of matching results would be a figure a
  PEP renders in a progress bar and is wrong.

### Documentation

- [`docs/conformance-authzen.md`](docs/conformance-authzen.md) is
  re-audited against the Final Specification's own section numbering.
  The previous revision numbered against a pre-Final draft (Search was
  cited as §5.3 where the Final text has §8), listed the three Search
  endpoints as `deferred` and "404" in one table while another table on
  the same page described them as shipped, and twice attributed to
  "§5.3.2" a requirement that PDPs error when they cannot resolve a
  search space — text that does not appear in the specification.
  [`api/openapi.yaml`](api/openapi.yaml) carried the same pre-Final
  numbering, plus a discovery description claiming the three Search
  endpoints were "omitted on purpose" while the handler had always
  advertised them.

### Dependencies

- `github.com/cert-manager/cert-manager` 1.21.1 → 1.21.2 and
  `golang.org/x/sys` 0.47.0 → 0.48.0, both of which ship in the binary.
  Nine npm packages under `ui/` and two GitHub Actions
  (`anthropics/claude-code-action`, `github/codeql-action`, across five
  pinned `uses:` lines in three workflows) moved too, neither of which
  affects what a consumer installs.

### Internal

- **`golangci-lint` is a blocking CI step again.** It had carried
  `continue-on-error: true` since the Go 1.26 bump, citing
  golangci/golangci-lint#6272 — closed upstream on 2026-02-10. In the
  meantime the step was silently swallowing 18 findings, all fixed
  here. One of them was substantive: three JWK decode sites built an
  `ecdsa.PublicKey` from raw coordinates, which Go 1.26 deprecated
  because it can yield an invalid key. They now go through
  `ecdsa.ParseUncompressedPublicKey`, which performs the on-curve and
  point-at-infinity checks that the agent's `parseJWKS` and the
  `mcp-a2a-delegation` example never did at all.

## [0.4.0] - 2026-08-23

Finishes the thought 0.3.0 started. That release made a `spire-upstream`
deployment able to *accept* new trust material at runtime; this one
gives it somewhere to get that material from, so following an upstream
SPIRE CA or signing-key rotation stops being an operator's errand.

A minor rather than a patch: two `feat` commits, one new flag pair, no
change to any existing default.

### Added

- **Live upstream trust material over the SPIFFE Workload API
  (`spire-upstream`).** `--identity-source-workload-api` points Omega at
  the upstream's Workload API endpoint (for example a SPIRE agent's
  socket) instead of at files on disk, so a CA or JWT signing-key
  rotation is followed with no operator in the loop and no `SIGHUP`.
  0.3.0 made the source rotatable but left the operator to supply the
  new bytes, which in practice means a per-deployment sidecar that
  watches SPIRE, writes two files, and signals Omega — and reintroduces
  the same silent staleness when it stops running.

  The file transport stays the default and unchanged; the two are
  mutually exclusive and exactly one is required, so a rotation cannot
  be applied to a transport that is being shadowed. Fetched material
  goes through the same reload path, so validation, atomic generation
  swap, `spiffe_sequence`, and the fail-closed rule are shared. Omega
  consumes bundles only (`FetchX509Bundles` / `FetchJWTBundles`), never
  an SVID of its own, and must be an attested workload of the endpoint.
  `--identity-source-workload-api-jwt` opts into following the upstream
  JWKS as well; it is off by default because Omega consumes only EC
  P-256 (ES256) signing keys.

  The address must be `unix://`. go-spiffe will dial `tcp://` at any
  address with no transport security and no server authentication, and
  what arrives over that channel becomes Omega's entire root of trust —
  a weaker boundary than the file transport, which at least needs local
  write access. Recorded in
  [ADR 0010](docs/adr/0010-live-upstream-trust-material.md), demonstrated
  in [`examples/spire-upstream-live`](examples/spire-upstream-live/).

### Documentation

- [`examples/spire-interop`](examples/spire-interop/) runs the live
  transport against upstream `spire-server` and `spire-agent` images —
  join-token node attestation, a registration entry for Omega, and
  SPIRE's own `localauthority` command rotating first the X.509 CA and
  then the JWT signing key, with Omega following both unprompted. It
  pins the three things a deployment has to get right and a mock cannot
  teach: `jwt_key_type = "ec-p256"` on the SPIRE server, a registration
  entry for the control plane, and a workload attestor that can resolve
  the caller. [`examples/spire-upstream-live`](examples/spire-upstream-live/)
  stays as the hermetic one that catches a Workload API client
  regression in seconds. Both run in the CI examples matrix.

## [0.3.1] - 2026-08-18

A maintenance release. Omega's own code is unchanged since 0.3.0; the
reason to upgrade is the Go toolchain bump, which rebuilds the published
image against a patched standard library.

### Security

- **Raised the Go requirement to 1.26.6** for
  [GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218) (`net/url`),
  [GO-2026-6091](https://pkg.go.dev/vuln/GO-2026-6091)
  (`html/template`),
  [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090) (`crypto/tls`),
  [GO-2026-6089](https://pkg.go.dev/vuln/GO-2026-6089) and
  [GO-2026-5026](https://pkg.go.dev/vuln/GO-2026-5026) (`net/http`), and
  [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972)
  (`encoding/asn1`). All six were reachable by symbol trace from Omega
  code — TLS handshakes, the HTTP surface, and CSR parsing in the
  cert-manager issuer — under the 1.26.5 toolchain that CI resolves from
  `go.mod`. No Omega source change was needed.
- **Pinned the builder image to `golang:1.26.6-alpine`.** Every
  `Dockerfile` built from `golang:1.26-alpine`, a floating minor, so the
  standard library baked into a published image was whatever that tag
  resolved to at build time — never pinned and never verified, which
  0.2.1 called out and did not fix. `go.mod` constrains what the
  toolchain must be *at least*; it does not make the image reproducible.
  Pinning the exact patch makes "which standard library is in this
  binary" answerable from the tree. Dependabot already watches all four
  Docker directories, so the pin stays current.

## [0.3.0] - 2026-08-03

Makes upstream consumption correct over time rather than only at boot.
`spire-upstream` deployments can now follow an upstream SPIRE / Istio
CA or signing-key rotation with a signal instead of a restart, which
closes a failure that was silent, delayed, and fanned out to every
agent.

### Added

- **Runtime reload of upstream trust material (`spire-upstream`).**
  `SIGHUP` now re-reads `--identity-source-bundle` and
  `--identity-source-jwt-bundle` and installs them atomically, so an
  upstream SPIRE / Istio CA or JWT signing-key rotation can be followed
  without restarting the control plane. Reload runs the same validation
  as boot and is fail-closed: a file that does not validate leaves the
  previous anchors serving, because stale trust material beats none.
  Recorded in
  [ADR 0009](docs/adr/0009-upstream-trust-material-reload.md).

### Fixed

- **Upstream trust material no longer goes stale until restart.**
  Previously both upstream bundles were read once at boot and held for
  the process lifetime, while the upstream rotates on its own schedule.
  Once the upstream root rolled, Omega served a bundle missing the new
  anchor — and agents, which re-fetch from the control plane, cached that
  staleness — so freshly-issued upstream SVIDs failed to verify and
  rotated JWT keys produced "unknown kid". Nothing surfaced at boot or in
  a health check.
- `spiffe_sequence` in `GET /v1/spiffe-bundle` tracks the identity
  source's trust-material generation instead of being hard-coded to `1`,
  so federation peers can tell a rotated bundle from a re-served one. A
  built-in issuing source still reports `1`, which is accurate for a
  source that cannot rotate mid-process.
- An empty `--identity-source-jwt-bundle` no longer parses as
  "X.509-only". A truncated or emptied JWKS file used to load cleanly
  and leave the source with no signing keys, contradicting the
  `jwt=<path>` startup line at boot and silently downgrading an
  established JWT deployment on reload.
- The startup open-CA warning and the `--require-auth` help pointed at
  a design document that is not in the repo. They now reference
  [`docs/threat-model.md`](docs/threat-model.md) S3.

### Documentation

- `docs/threat-model.md` reflects the mitigations that shipped in
  0.1.0. S2 (control-plane TLS / mTLS), T1 (HMAC-keyed audit chain),
  and T3 (federation bundle-endpoint verification) had all been
  described as unmitigated or as the deployment's responsibility, which
  under-claimed the posture by a release. Adds S3 for the open-CA
  threat, which had no entry despite being what the startup warning is
  about. Every entry keeps a residual-risk line, because the three
  mitigations are opt-in and default to off.
- `examples/spire-upstream/` covers the consuming path end to end and
  runs in the CI examples matrix: non-issuing posture (501), JWKS
  service, a fail-closed rejected reload, and a real rotation.

## [0.2.1] - 2026-08-01

A maintenance release. Omega's own code is unchanged since 0.2.0; the
reason to upgrade is the Go toolchain bump, which rebuilds the published
image against a patched standard library.

### Security

- **Rebuilt against Go 1.26.5 for
  [GO-2026-5856](https://pkg.go.dev/vuln/GO-2026-5856) (`crypto/tls`).**
  0.2.0 required `go 1.26.4` in `go.mod` with no `toolchain` directive, so
  CI — which resolves the toolchain via `go-version-file: go.mod` —
  built and scanned on exactly 1.26.4, and the vulnerability was
  **reachable by symbol trace** rather than merely present in a required
  module. The release image builds `FROM golang:1.26-alpine`, a floating
  minor, so the standard library baked into `ghcr.io/kanywst/omega:0.2.0`
  is whatever that tag resolved to at build time and was never pinned or
  verified. Raising the requirement to 1.26.5 removes the ambiguity for
  both. No Omega source change was needed.

### Changed

- Routine dependency updates across Go modules, the `ui/` npm tree, and
  GitHub Actions.

## [0.2.0] - 2026-07-01

Repositions Omega as the authorization and audit layer over SPIFFE.
The headline change is the **identity-source seam**: Omega can now
consume identities minted by an upstream SPIRE / Istio trust domain
instead of running its own CA, so an operator who already has SPIFFE
gets the Cedar PDP and the audit chain without a second issuer. The
built-in disk CA remains the default and is now labelled dev/eval-only
at startup.

### Added

- **`--identity-source` seam** selecting where SPIFFE identities come
  from: `built-in` (default, Omega issues via `--ca-backend`) or
  `spire-upstream`. Recorded in
  [ADR 0007](docs/adr/0007-pluggable-identity-source.md).
- **`spire-upstream` identity source — non-issuing, validation-only.**
  Omega consumes the upstream X.509 trust bundle from
  `--identity-source-bundle` (a PEM file, no boot-time network
  dependency), serves it at `/v1/bundle` and to federation peers, and
  applies authorization + audit over upstream-issued SVIDs. It runs no
  CA: every issuance / token-exchange route returns **501**.
  `--trust-domain` must be set explicitly to the upstream domain rather
  than defaulting.
- **Upstream JWT-SVID validation.** The optional
  `--identity-source-jwt-bundle` points at the upstream trust domain's
  RFC 7517 JWKS; its signing keys are served at `/v1/jwt/bundle` so
  agents validate upstream JWT-SVIDs locally, completing the SPIFFE
  credential set under `spire-upstream`. EC P-256 (ES256) only, matching
  Omega's existing JWT path and the SPIRE / Istio defaults. Omitting the
  flag keeps upstream consumption X.509-only and returns a distinct
  `ErrUpstreamJWTNotConfigured` instead of the issuance error. Recorded
  in [ADR 0008](docs/adr/0008-upstream-jwt-svid-validation.md).
- [ADR 0006](docs/adr/0006-policy-engine-plurality-at-the-portfolio-line.md)
  recording that Omega stays Cedar-first with a single in-process engine,
  and that policy-engine plurality lives at the portfolio line rather
  than inside Omega.

### Changed

- README repositioned around the wedge — SPIFFE IDs as native AuthZEN
  subjects with service / human / agent audit — instead of a
  replace-everything framing, and notes that Omega can consume an
  upstream SPIRE / Istio identity source.
- `--ca-backend=disk` now prints a startup **WARNING** that a
  self-signed root is for dev / eval only, pointing at `vault-pki`,
  `step-ca`, or `--identity-source`.

### Fixed

- **`cnf` confirmation bindings fail closed.** A present-but-unenforceable
  `cnf` is rejected in the built-in path rather than silently ignored, as
  is a `cnf` that is malformed, non-string, empty, or missing
  `x5t#S256` (RFC 8705).
- **JWKS consumption hygiene.** Keys that are structurally foreign
  (other `kty` / `crv`, `use` other than `sig`, `alg` other than ES256,
  `key_ops` without `verify`) are skipped per RFC 7517 §5, while a
  *recognised* EC P-256 signing key that is corrupt — bad or off-curve
  coordinates, a missing `kid`, a duplicate `kid` — fails closed at boot
  as a corrupt trust anchor. `exp` is required on presented tokens
  (`iat` stays optional) and kid-less tokens are rejected.
- **Upstream bundle validation.** The bundle must contain at least one CA
  certificate, a malformed `CERTIFICATE` block fails closed at boot
  instead of being silently dropped, and `BundlePEM` returns a defensive
  copy so callers cannot mutate stored trust material.
- `--issuer-url` is honoured in `spire-upstream` mode, so OIDC discovery
  works when Omega is not the issuer.

### Performance

- Reading a `cnf` binding no longer re-verifies the signature that the
  caller already checked.

## [0.1.0] - 2026-06-28

First release under the `kanywst` org. Closes the three highest-severity
trust-model gaps from a fresh-context security review — the control-plane
API was an open CA, the audit chain was forgeable, and federation bundle
fetch was unauthenticated — each shipped opt-in so existing deployments
are unaffected on upgrade.

### Added

- **Control-plane API authentication (opt-in).** `--tls-cert` /
  `--tls-key` serve TLS; `--client-ca` requires & verifies client certs
  (mTLS); `--require-auth` binds every write / PDP / issuance endpoint to
  the caller's verified SPIFFE client SVID and refuses to mint an SVID for
  a different identity (self-renewal only). Audit reads are gated too.
  Default off preserves the previous behaviour.
- **Tamper-resistant audit log (opt-in).** `--audit-hmac-key-file` keys
  the hash chain with HMAC-SHA-256 from a rotatable keyring (`SIGHUP`
  reload), records a per-row `key_id`, and detects forged downgrades and
  tail truncation against an optional `(expected_head, expected_count)`
  anchor on `GET /v1/audit/verify`. Default (no key) keeps the legacy
  unkeyed chain.
- **Authenticated SPIFFE federation.** `--federate-with` peers are fetched
  over HTTPS with bundle-endpoint verification — `profile=https_web`
  (web-PKI) or `profile=https_spiffe` (pinned `endpoint_spiffe_id` seeded
  from `endpoint_bundle`). Plaintext requires the explicit
  `--federation-allow-insecure` escape hatch.
- CI: a `ui` job (typecheck / lint / build) and `concurrency`
  cancellation.

### Changed

- **Transferred to `github.com/kanywst/omega`.** Go module path, the
  `ghcr.io/kanywst/omega` image, the Helm repo
  (<https://kanywst.github.io/omega/>), and the Kubernetes CRD API group
  `omega.kanywst.github.io` all moved off `0-draft`. The API-group change
  is **breaking** for existing `OmegaDomain` / `OmegaIssuer` resources
  (re-apply under the new group).

### Fixed

- Security quick-wins: OIDC IdP federation now requires a non-empty
  audience; JSON request bodies are size-bounded; `--k8s-attest` requires
  a token audience; Cedar context rejects fractional / out-of-range
  numbers; OIDC-claim-derived SPIFFE IDs reject path/control characters.
- UI builds again: biome v2 config migration and the deprecated tsconfig
  `baseUrl` removed.

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
- Helm chart published at <https://kanywst.github.io/omega/> via
  `chart-releaser`.
- CI matrix: build, race tests, cross-compile, end-to-end demo,
  example demos, helm lint, kind-based operator smoke test,
  govulncheck, gosec, markdownlint.

[Unreleased]: https://github.com/kanywst/omega/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/kanywst/omega/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/kanywst/omega/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/kanywst/omega/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kanywst/omega/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kanywst/omega/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kanywst/omega/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kanywst/omega/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/kanywst/omega/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kanywst/omega/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/kanywst/omega/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/kanywst/omega/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/kanywst/omega/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/kanywst/omega/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kanywst/omega/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/kanywst/omega/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/kanywst/omega/releases/tag/v0.0.1
