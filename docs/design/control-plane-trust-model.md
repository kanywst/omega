# Design: control-plane trust model (authn, audit integrity, federation trust)

## Status

Proposed. This is a design document for review, **not** an
implementation. It proposes fixes for the three highest-severity
trust-model findings from a security review. No Go code changes ship
in this PR. Once the recommended approach is agreed, each phase lands
as its own implementation PR (and, where a wire format or
control-plane decision changes, its own ADR under
[`docs/adr/`](../adr/)).

The page is meant to be read alongside
[`docs/threat-model.md`](../threat-model.md) (which already enumerates
S2, T1, T3 as *out of scope / deployment's responsibility*),
[`docs/design-philosophy.md`](../design-philosophy.md) (Core / Plugin /
Out-of-tree layering), and [`docs/scope.md`](../scope.md).

The thesis of this document is that three of those "deployment's
responsibility" lines are no longer defensible for an identity control
plane that issues credentials, and that Omega should own them in Core.

## Summary of findings

| ID | Severity | Finding | Code location |
| --- | --- | --- | --- |
| C1 | Critical | Control-plane HTTP API is unauthenticated and plaintext; `POST /v1/svid` is an open CA | `internal/cli/server.go`, `internal/server/api/http.go` |
| H1 | High | Audit "hash chain" is an unkeyed SHA-256 chain; forgeable and tail-truncatable | `internal/server/storage/audit.go` |
| H3 | High | SPIFFE federation bundle fetch is unauthenticated and accepts `http://` | `internal/server/federation/registry.go` |

## C1 — Unauthenticated, plaintext control-plane API (Critical)

### C1 problem statement

`internal/cli/server.go` builds a bare `http.Server` and serves it
with `ListenAndServe` (plaintext) on the `--http-addr` listener
(default `127.0.0.1:8080`):

```go
srv := &http.Server{
    Addr:              httpAddr,
    Handler:           apiServer.Handler(),
    ReadHeaderTimeout: 5 * time.Second,
}
// ...
if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
```

There is no `TLSConfig`, no `ListenAndServeTLS`, and no caller
authentication anywhere in the request path. The only gate any route
carries is `leaderOnly` in `internal/server/api/http.go`, which checks
`s.store.IsLeader()` — an HA write-routing check, **not** an
authentication check. It returns 503 on a follower and otherwise lets
every caller through.

Concretely, anyone who can reach the listener can:

- `POST /v1/svid` (`issueSVID`, `http.go`) and obtain a valid
  X.509-SVID for **any** identity in the trust domain. The handler
  parses the caller-supplied `spiffe_id`, decodes the CSR, calls
  `csr.CheckSignature()` — which only proves the caller holds the key
  in the CSR, not that the caller *is* the asserted identity — and
  signs `s.ca.IssueSVID(id, csr)` for whatever `spiffe_id` the body
  claimed. The CSR signature is verified; the **identity assertion is
  not**. This is an open CA for the entire trust domain.
- `POST /v1/svid/jwt` (`issueJWTSVID`) and mint a JWT-SVID for any
  `spiffe_id` / audience.
- `POST /access/v1/evaluation` and the batch / search PDP endpoints,
  reaching the authorization decision point as an anonymous caller and
  forging `subject.id` (the threat model already flags this as R1).
- `GET /v1/audit` (`listAudit`) and read the full tamper-evident audit
  log, including decision payloads (resource identifiers, contextual
  attributes — see I2 in the threat model).

The agent→server and operator→server links use the **same** listener
(threat model boundaries 1 and 3) and inherit the same property: both
are plaintext and unauthenticated. The admin CLI (`omega domain`,
`omega svid`, `omega policy`) speaks the same HTTP API.

The threat model currently calls this "Network-layer auth is delegated
to the deployment" (boundary 1) and lists "Caller authentication on
`omega server`" as out of scope, with "terminate auth at the ingress"
as the answer. For a control plane whose entire job is issuing
identity, an unauthenticated issuance endpoint is a critical defect,
not a deployment footnote: the open `POST /v1/svid` defeats the purpose
of every downstream mTLS check Omega's own SVIDs are supposed to
protect.

### C1 design goals

1. A caller cannot obtain an SVID for an identity it has not been
   authenticated and attested as.
2. The generic, unauthenticated `POST /v1/svid` issuance path is
   closed by default (or gated behind explicit, audited authorization).
3. Transport is TLS by default for every external link
   (operator→server, agent→server, server↔peer).
4. There is a bootstrap story for the first caller (chicken-and-egg:
   you need an identity to authenticate, but you call the API to get
   an identity).
5. A migration path exists so existing deployments are not broken on
   upgrade.

### C1 — (a) authentication model: options

The core problem is **enrollment**: how does a caller that does not yet
hold an Omega SVID prove it deserves one? This is exactly the problem
SPIRE solves with *node attestation*. SPIRE's model is:

1. An agent presents a platform-rooted proof (a Kubernetes projected
   ServiceAccount token, an AWS IMDSv2 instance-identity document, a
   join token, etc.) to the server.
2. The server runs a *node attestor* plugin that validates that proof
   against the platform's authority (TokenReview against the
   kube-apiserver, the AWS signature, the one-time join token), and
   derives a SPIFFE ID from the validated claims — the caller does not
   get to name itself.
3. Only then does the server issue an SVID, and only for the derived
   identity.

Omega already has the right shape for this: `POST /v1/attest/k8s`
(`attestK8s` in `http.go`). That handler does **not** trust a
caller-supplied SPIFFE ID. It validates a projected ServiceAccount
token via `s.k8sAttestor.Attest`, renders the SPIFFE ID from the
*validated* `(namespace, serviceaccount[, podname])` claims via
`attest.RenderSPIFFEID`, checks `id.MemberOf(s.ca.TrustDomain())`, and
only then signs the CSR. The identity is **derived from an attested
platform proof**, not asserted by the caller. This is the secure
pattern; `POST /v1/svid` is the insecure one.

Options for the authentication model:

| Option | Mechanism | Pros | Cons |
| --- | --- | --- | --- |
| A | mTLS with Omega SVIDs as client certs; attestation-gated enrollment for the first credential | SPIFFE-native, no new secret type, identity is the cert | needs the bootstrap/join-token path for first contact |
| B | Static bearer token / API key per caller | trivial to implement | shared secret, no per-identity binding, no rotation story, replays |
| C | External OIDC IdP bearer tokens on every call | reuses corporate IdP | couples every call to an IdP round trip; Omega already has `--oidc-idp` for *humans*, not workloads |
| D | Terminate auth at the ingress only (status quo) | zero code | the issuance endpoint itself stays open to anything inside the mesh; defense-in-depth absent |

### C1 — (a) recommendation

Adopt **Option A** as the Core model, with attestation as the
enrollment gate:

1. **Promote attestation to the generic issuance gate.** Make the
   attested path (`POST /v1/attest/k8s`, and future attestors — EC2,
   GCP IAM, Docker, Unix-UID, and a SPIRE-style **join token**) the
   *only* way to obtain a first SVID. The attestor validates a
   platform proof and **derives** the SPIFFE ID; the caller never names
   itself. This generalizes the existing `attest.K8sAttestor` seam into
   an `Attestor` interface (Plugin layer; see
   [`design-philosophy.md`](../design-philosophy.md) rule 3, "workload
   attestor" is already listed as a Plugin example).

2. **Add a join-token attestor for the first agent.** Mirror SPIRE's
   `join_token`: an operator runs `omega token generate` (one-time,
   short-TTL, single-use, recorded in the DB), hands it to the new
   node out-of-band, and the agent presents it to a new
   `POST /v1/attest/join-token` endpoint. The server validates and
   burns the token, derives the agent's SPIFFE ID from the token's
   registration entry, and issues the SVID. This is the root of the
   enrollment chain when no platform attestor is available.

3. **Require an authenticated + attested caller for every write and
   PDP endpoint.** Once a caller holds an SVID, subsequent calls
   authenticate with that SVID over mTLS (Option A). Authorization of
   *what* an authenticated caller may do is then a Cedar decision
   (Omega already owns the PDP), not an all-or-nothing gate.

### C1 — (b) bind issuance to the authenticated + attested caller

The defect in `issueSVID` is that the `spiffe_id` is caller-asserted.
Two layers fix this:

- **Attested issuance (enrollment):** the SPIFFE ID is *derived* from
  the validated attestation, exactly as `attestK8s` already does. The
  request body carries the platform proof + CSR, never a free-text
  `spiffe_id` the server trusts.
- **Authenticated re-issuance / rotation:** when an authenticated mTLS
  caller already holding SVID `X` requests a new SVID, the server
  binds the request to the mTLS client identity. The caller may renew
  `X` (CSR public key may rotate) but may not request `Y != X` unless
  a Cedar policy explicitly permits that delegation (this is the same
  machinery as the RFC 8693 token-exchange guard in
  `token_exchange.go`, which already enforces
  `requested_spiffe_id == actor_token.sub`).

The generic, unauthenticated `POST /v1/svid` that trusts a
caller-asserted `spiffe_id` **must be gated**. Recommended end state:
it is disabled by default and, when explicitly enabled for
backward-compat, requires an authenticated mTLS caller plus a Cedar
`svid.issue` permit for the requested ID. Treat the current behavior
as the open-CA bug it is.

### C1 — (c) TLS for transport

- `omega server` serves TLS on the API listener. New flags:
  `--tls-cert` / `--tls-key` (PEM), `--tls-client-ca` (the trust
  bundle used to verify client SVIDs for mTLS), and
  `--tls-client-auth=off|request|require` (maps to Go's
  `tls.ClientAuthType`). Default in a new major: `require` once
  bootstrap exists.
- The server can serve its own listener TLS from an Omega-issued
  X.509-SVID for its own SPIFFE ID (it holds the CA), so the cert
  material is self-bootstrapping after first boot.
- Agents verify the server against the trust bundle they already pull
  (`/v1/bundle` / `/v1/spiffe-bundle`); this closes S2 at the
  application layer rather than delegating it.

### C1 — (d) migration / compat path and config flags

Because flipping auth on by default is a breaking change, gate it
behind explicit configuration and a deprecation window:

- **Phase 0 (compat):** add `--require-auth=false` (default `false`).
  When `false`, behavior is unchanged (status quo, with a startup
  `WARN` log naming the open-CA risk). When `true`, the server
  requires mTLS + attested/authenticated issuance and disables the
  unauthenticated `POST /v1/svid`.
- **Phase 1:** ship the join-token attestor and the `Attestor`
  interface; document the enrollment chain.
- **Phase 2 (next major):** flip `--require-auth` default to `true`;
  `POST /v1/svid` (caller-asserted) defaults off behind
  `--allow-unauthenticated-svid=false`.

New / changed flags (all additive in Phase 0):

| Flag | Default | Purpose |
| --- | --- | --- |
| `--tls-cert` / `--tls-key` | empty | server listener TLS material; empty keeps plaintext (compat) |
| `--tls-client-ca` | empty | trust anchors used to verify client SVIDs (mTLS) |
| `--tls-client-auth` | `off` | `off` / `request` / `require` |
| `--require-auth` | `false` | require an authenticated + attested caller on writes / PDP |
| `--allow-unauthenticated-svid` | `true` | keep the legacy open `POST /v1/svid`; flips to `false` in next major |
| `--join-token-ttl` | `15m` | TTL for one-time enrollment tokens |

## H1 — Audit hash chain is unkeyed and tail-truncatable (High)

### H1 problem statement

`internal/server/storage/audit.go` computes each row's hash with a
plain, unkeyed SHA-256 over the row fields:

```go
func hashAuditEvent(ev AuditEvent) string {
    h := sha256.New()
    fmt.Fprintf(h, "%d|%d|%s|%s|%s|%s|", ev.Seq, ev.Ts.UnixNano(), ev.Kind, ev.Actor, ev.Subject, ev.Decision)
    h.Write([]byte(ev.Payload))
    h.Write([]byte("|"))
    h.Write([]byte(ev.PrevHash))
    return hex.EncodeToString(h.Sum(nil))
}
```

`VerifyAudit` walks from `genesisHash` and recomputes each hash with
the same function. Because the hash is **unkeyed**, the construction
provides integrity only against an attacker who *cannot* recompute the
hash — but anyone with DB write access has the exact same
`hashAuditEvent` the verifier uses. They can edit any row (or a whole
range) and recompute every subsequent `prev_hash` / `hash` so
`VerifyAudit` returns `firstBadSeq == 0` ("valid"). The chain is
*tamper-evident only against an actor who lacks the algorithm*, which
is nobody — the algorithm is public and deterministic.

Worse, **tail truncation is undetectable**. `lastAuditHash` selects
`ORDER BY seq DESC LIMIT 1`; `VerifyAudit` walks whatever rows exist.
Nothing records the expected head hash or the expected row count, so
deleting the newest N rows leaves a perfectly valid shorter chain. An
attacker who issues themselves an SVID and then deletes the trailing
audit rows erases the evidence with no detectable gap.

The threat model's T1 already concedes the chain is "tamper-evident,
not tamper-resistant" and leans on "any external verifier with a
previously-published hash anchor will detect the rewrite" — but Omega
**publishes no such anchor today**, so that mitigation is theoretical.

### H1 design goals

1. An attacker with DB write access cannot forge a chain that passes
   verification.
2. Tail truncation (deleting the newest N rows) is detectable.
3. The verifying key is not co-located with the data it protects.

### H1 recommendation

Two complementary changes:

1. **Key the chain with HMAC-SHA-256.** Replace `sha256.New()` with
   `hmac.New(sha256.New, key)` over the same serialized fields. The
   key lives **outside** the DB: a `--audit-hmac-key-file` (or a KMS
   ref reusing the CA-backend plumbing), never in `audit_log` and
   never under `--data-dir` alongside `omega.db`. Now a DB-only
   attacker cannot recompute valid row MACs. Optionally, sign each row
   (or periodic checkpoints) with the CA/JWT signing key for public
   verifiability without distributing the HMAC secret — at higher CPU
   cost; HMAC is the baseline, row-signing is an upgrade.

2. **External anchoring of (head hash, max seq).** Periodically emit a
   signed checkpoint `{max_seq, head_hash, count, ts}` to an external,
   append-only sink and/or expose it for an external watcher to pin.
   The existing `audit.Pump` webhook / OTLP forwarders
   (`internal/server/audit/`, wired in `server.go`) are the natural
   carrier — extend them to forward signed checkpoints, not just raw
   events. `VerifyAudit` then takes an optional expected
   `(head_hash, count)` and reports truncation when the live tail is
   shorter than the last anchored checkpoint. Truncation below an
   anchored checkpoint becomes detectable; truncation above it is
   bounded by the checkpoint interval.

### H1 key management and verify-side changes

- **Key management:** the HMAC key is operator-supplied and rotatable.
  On rotation, record a key epoch in each row (a small `key_id`
  column) so `VerifyAudit` selects the right key per row; old rows stay
  verifiable under the old key. The key file is mounted read-only and
  excluded from any DB backup path.
- **Verify-side:** `VerifyAudit` gains (a) HMAC recomputation with the
  per-row key epoch, (b) an optional `expectedHead` / `expectedCount`
  parameter sourced from the latest external checkpoint, and (c) a
  distinct return for "valid but truncated below anchor" vs "row hash
  mismatch at seq N". `GET /v1/audit/verify` surfaces both.
- **Migration:** existing unkeyed rows cannot be retrofitted to HMAC
  without the original inputs (which we have — the rows themselves), so
  a one-time re-MAC under a freshly minted key epoch is possible at
  upgrade, with a recorded "genesis re-key" checkpoint. Document that
  rows created before keying carry only the legacy guarantee.

## H3 — Unauthenticated federation bundle fetch (High)

### H3 problem statement

`internal/server/federation/registry.go` fetches peer trust bundles
with a default `http.Client` and no transport authentication:

```go
httpClient: &http.Client{Timeout: 10 * time.Second},
```

`fetchPeer` → `fetchTDF` / `fetchPEM` build the request straight from
the operator-supplied `peer.URL` (`--federate-with name=...,url=...`)
and do a plain `r.httpClient.Do(req)`. The URL scheme is whatever the
operator passed; `http://` is accepted (the threat-model diagram and
`server.go` flag help both show `url=http://...`). There is:

- no TLS requirement (plaintext `http://` peers are fetched as-is);
- no server-certificate / endpoint-identity verification beyond Go's
  default (and none at all over `http://`);
- no pinning of the peer's expected endpoint SPIFFE ID.

The bytes returned are parsed through `spiffebundle.Read`
(`fetchTDF`) or PEM-validated (`fetchPEM`) and then **installed as a
trusted X.509 anchor for the peer trust domain** (`refreshOne` stores
them in `peerBundles`, served from `/v1/federation/bundles` and fed to
every workload's `FetchX509Bundles` stream). A network attacker who can
MITM the fetch (trivial over `http://`, or via a forged/misissued cert
the default client would accept) injects their **own CA as a trusted
anchor for the peer domain**. Every workload in this trust domain then
accepts attacker-issued SVIDs that claim the peer's identity. This is
T3 in the threat model, currently parked as "the deployment is
responsible for authenticating the peer at the transport layer."

### H3 design goals

1. Federation fetches use authenticated HTTPS; `http://` is rejected.
2. The peer endpoint's identity is verified, not just "some valid
   web-PKI cert".
3. The verification surface is explicit configuration, not an implicit
   default.

### H3 recommendation

Follow the SPIFFE Federation spec's bundle-endpoint authentication
profiles:

1. **Require HTTPS; reject `http://`.** `parseFederatePeers` (in
   `server.go`) rejects any non-`https` URL at startup with a clear
   error. Provide a single explicit escape hatch
   (`--federation-allow-insecure`, default `false`) for the local
   demo / loopback test loops only, logged loudly.

2. **Verify the bundle endpoint identity.** Support both SPIFFE
   Federation profiles:
   - **`https_web`:** the endpoint presents a normal web-PKI cert;
     verify it against the system (or a configured) root store with
     hostname verification. Configure via a per-peer
     `endpoint_ca=<file>` or rely on system roots.
   - **`https_spiffe`:** the endpoint presents an X.509-SVID; verify
     it against the peer's *already-known* bundle and pin the expected
     endpoint **SPIFFE ID** (`endpoint_spiffe_id=spiffe://peer/...`).
     This is the SPIFFE-native profile and the recommended default for
     omega↔omega federation, because it does not depend on web-PKI for
     the control-plane link. Use go-spiffe's `tlsconfig` to build the
     verifying `http.Client` instead of the bare default client.

3. **Config surface (per peer):** extend the `--federate-with` grammar
   with `profile=https_web|https_spiffe`, `endpoint_spiffe_id=...`,
   and `endpoint_ca=...` keys (the parser in `parseFederatePeers`
   already splits comma-separated `key=value`). `NewRegistry` takes a
   per-peer verifier and constructs the `http.Client` accordingly,
   replacing the single shared default client.

## Phased rollout and design-layer mapping

Each finding maps to a layer per
[`design-philosophy.md`](../design-philosophy.md):

| Finding | Change | Layer | Rule that fires |
| --- | --- | --- | --- |
| C1 | issuance gated on attestation / authenticated caller; "should this CSR be signed?" | Core | rule 2 (control-plane decision Omega owns) |
| C1 | the `Attestor` interface + join-token / k8s / cloud attestors | Plugin | rule 3 (attestor is an upstream Omega depends on) |
| C1 | listener TLS / mTLS transport | Core | rule 2 (Omega owns the link to its own API) |
| H1 | HMAC keying + external anchoring of the audit chain | Core | rule 1 (audit-log hash-chain format is an Omega wire format) |
| H3 | HTTPS-only + endpoint-identity-verified federation fetch | Core | rule 1 (SPIFFE Federation bundle exchange is a wire format Omega consumes) |

Suggested phasing:

1. **Phase 1 — transport + federation (lower blast radius).**
   Add listener TLS flags (compat default plaintext) and HTTPS-only
   federation with endpoint-identity verification (H3). H3 has the
   smallest compatibility surface (federation is opt-in via
   `--federate-with`) and closes a High on its own.

2. **Phase 2 — audit integrity (H1).** HMAC-key the chain behind
   `--audit-hmac-key-file`, add the `key_id` column and migration,
   extend `audit.Pump` to forward signed checkpoints, and teach
   `VerifyAudit` / `GET /v1/audit/verify` about truncation. Independent
   of C1, can land in parallel.

3. **Phase 3 — enrollment + authn (C1).** Land the `Attestor`
   interface and the join-token attestor, then mTLS auth and the
   `--require-auth` gate (compat default off). This is the largest
   change; it depends on Phase 1's TLS plumbing.

4. **Phase 4 — flip defaults (next major).** `--require-auth=true`,
   `--allow-unauthenticated-svid=false`. Breaking; gated on a major
   version and the migration guide below.

## Backward-compatibility and breaking-change notes

- **All Phase 1–3 changes are additive and default-off**, so existing
  deployments keep working on upgrade (with new startup `WARN` logs
  naming each open risk). Nothing in this proposal changes default
  behavior until Phase 4.
- **Phase 4 is a breaking change** and must land on a major version
  bump with a migration guide: operators must (a) provision listener
  TLS material, (b) enroll agents via attestation or join tokens
  before flipping `--require-auth`, and (c) stop relying on the
  caller-asserted `POST /v1/svid`.
- **Audit migration (H1):** rows created before keying carry only the
  legacy (unkeyed) guarantee; a recorded "genesis re-key" checkpoint
  marks the boundary. `VerifyAudit` reports the epoch so operators know
  which rows are HMAC-protected.
- **Federation (H3):** deployments that today federate over `http://`
  must switch to `https://` (or set `--federation-allow-insecure` for
  loopback demos). The example federation demos under `examples/` will
  need their peer URLs updated to `https` or the insecure flag.

## Threat-model updates this proposal implies

When implemented, these entries in
[`docs/threat-model.md`](../threat-model.md) move from "deployment's
responsibility / out of scope" to "mitigated in Core":

- **S2 / boundary 1 + 3:** caller authentication and TLS become an
  in-Core capability (C1).
- **T1:** the audit chain becomes forgery-resistant (HMAC) and
  truncation-detectable (anchoring) without relying on an external
  write-once store (H1).
- **T3 / boundary 4:** federation bundle exchange authenticates the
  peer endpoint at the application layer (H3).

## Suggested follow-up issues

1. Define the `Attestor` plugin interface (generalize
   `attest.K8sAttestor`) and add a join-token attestor — `omega token
   generate` + `POST /v1/attest/join-token`. (C1, Phase 3)
2. Add listener TLS / mTLS flags to `omega server` and verify
   agent→server against the pulled trust bundle. (C1, Phase 1/3)
3. Gate / disable the caller-asserted `POST /v1/svid` behind
   `--allow-unauthenticated-svid`; bind authenticated re-issuance to
   the mTLS client identity. (C1, Phase 3/4)
4. HMAC-key the audit chain (`--audit-hmac-key-file`, `key_id` column,
   migration). (H1, Phase 2)
5. Emit signed audit checkpoints through `audit.Pump`; teach
   `VerifyAudit` truncation detection. (H1, Phase 2)
6. HTTPS-only federation with `https_web` / `https_spiffe`
   endpoint-identity verification and per-peer config keys. (H3,
   Phase 1)
7. Update `examples/` federation demos and the threat model in the
   same PRs that land each change.

## References

- SPIRE node attestation and join-token enrollment model.
- SPIFFE Federation specification — bundle endpoint profiles
  (`https_web`, `https_spiffe`).
- RFC 8693 (OAuth 2.0 Token Exchange) — already implemented in
  `internal/server/api/token_exchange.go`; its actor-binding guard is
  the template for C1's authenticated re-issuance binding.
- RFC 2104 (HMAC) — keyed hashing for the audit chain (H1).
