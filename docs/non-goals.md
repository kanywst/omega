# Omega is not X

A scope statement, written negatively. The five design principles
([07. Design principles](https://github.com/kanywst/omega/blob/main/docs/scope.md))
say what Omega *is*; this page says what it deliberately is not, so
operators evaluating the project and contributors proposing features
share the same map of the territory.

The headline rule: **Omega is the workload + agent identity and
authorization control plane.** Issuing identities, evaluating
authorization, federating with external IdPs, and writing the audit
trail. Anything outside that loop - secrets, end-user login UX, data
plane traffic, SIEM analytics - is intentionally somebody else's job,
and Omega is built to integrate with that somebody else rather than
replace them.

## Quick map

| You want                               | Use Omega? | Use this instead                          |
| -------------------------------------- | ---------- | ----------------------------------------- |
| Workload identity (X.509 / JWT-SVID)   | yes        |                                           |
| AuthZEN PDP (Cedar default, swappable) | yes        |                                           |
| OIDC federation hub for workloads      | yes        |                                           |
| AI agent identity + delegation chain   | yes        |                                           |
| End-user login (social, MFA, passkey)  | no         | Keycloak, Auth0, Dex, Authentik           |
| Secrets storage (KV, dynamic creds)    | no         | Vault, OpenBao, AWS Secrets Manager       |
| Cert delivery to K8s pods              | partial    | cert-manager (with Omega as Issuer)       |
| L7 proxy / mTLS data plane             | no         | Istio, Linkerd, Envoy ext\_authz          |
| Log analytics, alerting, SIEM          | no         | Splunk, Elastic, Grafana Loki, Sentry     |
| Agent runtime (LLM tool exec)          | no         | MCP servers, LangChain, A2A SDK           |
| CRL / OCSP / OCSP Stapling             | no         | Short-lived SVIDs (rotation = revocation) |

The rest of this page expands each "no" with the reasoning, and points
at the integration surface where Omega meets the other tool.

## Omega is not Keycloak / Dex / Auth0

Those projects own the **end-user authentication** experience: login
forms, social providers, MFA prompts, passkey enrollment, password
reset flows, account recovery, branded consent screens. Omega has no
login form and never will.

What Omega *does* with humans is consume an existing OIDC IdP - bring
your Keycloak, Okta, Entra ID, Google Workspace - and map its claims
to the same RBAC + ABAC + ReBAC policy surface that workloads and
agents use. The federation seam is OIDC + SCIM 2.0 in, AuthZEN out.

If you have no IdP yet, deploy Keycloak (or a hosted equivalent) and
point Omega at it. If you have an IdP and want a unified
authorization-plus-workload-identity story on top, that is the gap
Omega fills.

## Omega is not Vault / OpenBao

Vault and OpenBao are **secrets engines**: encrypted KV, dynamic
database credentials, PKI as a side feature, transit encryption,
SSH CA. Omega stores no secrets except the CA private key it generates
on first boot, and that key only because it has to sign SVIDs.

Concretely, Omega does not provide a KV store for application secrets,
dynamic database or cloud credential issuance, transit
(encrypt-as-a-service) endpoints, an SSH CA or one-time tokens, or
Vault-style response-wrapping / cubbyhole envelopes.

If your workload needs database credentials, fetch its SVID from Omega
and use it to authenticate to your secrets engine. The two systems are
complementary, not competitive - Omega answers "who is this workload",
and the secrets engine answers "what credentials does this workload
get to use."

## Omega is not OPA / Cedar / OpenFGA / SpiceDB (standalone)

Those are **policy decision engines**. Omega ships Cedar as the
default in-process PDP because Cedar covers RBAC + ABAC + limited
ReBAC and is formally analyzable, but Omega itself is the *control
plane* that surfaces a PDP behind the AuthZEN 1.0 wire protocol,
not the decision engine.

You can replace Omega's bundled Cedar with any AuthZEN-speaking PDP:
OPA, OpenFGA, SpiceDB, Cerbos, Aserto. Heavy ReBAC graphs in
particular belong in OpenFGA or SpiceDB; Omega's job is to route the
AuthZEN evaluation request to the right engine, attach the workload's
SVID-derived subject claims, and write the decision into the audit
log.

If you only need a PDP and have no workload-identity story, run OPA
or Cedar directly. If you have multiple PDPs across the org and want
one place to attach identity context and policy-aware audit, that's
Omega.

## Omega is not SPIRE (but is SPIFFE-compatible)

The honest comparison. Omega's Workload API is wire-compatible with
SPIRE's: an existing `go-spiffe` workload talks to `omega agent`
without code changes. The differences are scope and packaging.

| Dimension             | SPIRE                                | Omega                                              |
| --------------------- | ------------------------------------ | -------------------------------------------------- |
| Workload identity     | yes (defining implementation)        | yes (compatible)                                   |
| Authorization         | explicitly out of scope              | first class: AuthZEN 1.0 PDP, Cedar default        |
| Human / SCIM identity | out of scope                         | first class: same policy surface as workloads      |
| AI agent identity     | out of scope                         | first class: MCP / A2A delegation chain            |
| Federation hub        | partial (TrustDomain federation)     | OIDC federation + RFC 8693 token exchange          |
| Admin UI              | none                                 | first class (Next.js dashboard)                    |
| Operator / CRDs       | community (spire-controller-manager) | in-tree                                            |
| Audit log             | external                             | tamper-evident, in-process, AuthZEN-decision-aware |
| Single binary         | server + agent + ctl separate        | one `omega` binary with subcommands                |

If you already run SPIRE and just need authorization, mount Cedar/OPA
behind AuthZEN and keep SPIRE - that is a perfectly valid stack.
Omega is the bet that wrapping all of these into one binary with one
admin UI removes more pain than the integration costs save.

## Omega is not a service mesh

Istio, Linkerd, Cilium service mesh, Consul Connect: those are
**data-plane** projects. They terminate mTLS, route L7 traffic, do
retries, enforce policy at the proxy.

Omega is the **identity and policy control plane** that meshes consume.
A service mesh asks Omega "who is this workload" (via the SPIFFE
Workload API) and "is this call allowed" (via AuthZEN) - Omega never
sees the actual application byte stream.

The integration seams:

| Mesh    | Integration                                                                          |
| ------- | ------------------------------------------------------------------------------------ |
| Envoy   | `ext_authz` → AuthZEN bridge (planned reference YAML, see roadmap)                   |
| Istio   | SPIFFE trust bundle exchange; `omega agent` as the SPIRE-style identity for sidecars |
| Linkerd | same SPIFFE-Workload-API compatibility surface as Istio                              |

## Omega is not a SIEM

Omega writes a tamper-evident audit log: every authorization decision,
SVID issuance, and admin mutation, hash-chained so post-hoc tampering
is detectable. That is the *production* of audit signal.

The *consumption* - alerting on unusual patterns, correlating across
applications, retaining for compliance windows, investigating
incidents - is Splunk, Elastic, Loki, Sentry, your cloud's logging
service. Omega exports OTLP traces today and will ship audit-event
forwarding (OTLP / webhook) so the audit log lands in whatever
existing pipeline you have.

## Omega is not a CA-only product

cert-manager and step-ca focus on **certificate issuance and
delivery**, especially in Kubernetes. Omega includes a CA because
SVID issuance requires one, but the CA is a means to an identity
claim, not the product.

Omega ships a `cert-manager` external Issuer that proxies certificate
requests through Omega so the same SPIFFE ID ends up in the cluster's
`Secret` resources without bypassing the audit log. If you want bare
TLS certificates with no identity model behind them, cert-manager +
Let's Encrypt is the right tool.

## Omega is not a CRL / OCSP responder

The same logic that drives short-lived SVIDs in SPIFFE drives this
"no" - and it's a "no" the rest of PKI is converging on, too.

Omega's defaults are X.509-SVID at 30 minutes and JWT-SVID at 5 minutes,
both auto-rotated at the validity midpoint. The maximum residual
exposure of a compromised credential is therefore bounded by *one
rotation window*, not by how fast a CRL or OCSP response propagates. A
deny list whose `nextUpdate` is hours away cannot improve on a leaf
that has already expired by the time the list ships.

SPIRE made the same call explicitly: leaf-SVID revocation, CRLs, and
JTI deny lists are scoped *out* of SPIFFE
([spire#1934](https://github.com/spiffe/spire/issues/1934)). The
operator response to compromise is "rotate away" - re-key the signing
authority and let the bundle propagate. Distributing a list of
distrusted keys to every consumer adds a parallel, fragile delivery
path that must always be working; rotation already exercises the
identity issuance path that always *is* working.

The wider WebPKI ecosystem reached the same conclusion:

| Year | Decision                                                               |
| ---- | ---------------------------------------------------------------------- |
| 2023 | CA/B Forum SC-063 made OCSP optional, CRL mandatory                    |
| 2024 | Apple, Microsoft, Mozilla rolling out CRLite-style local revocation    |
| 2025 | Let's Encrypt shut down its OCSP service (340B requests/month retired) |

The reasons cited - privacy leakage of the subject's browsing pattern
to the CA, operational cost of a separate distribution plane, and the
weak threat model fail-open of soft-fail OCSP - apply at least as much
to a workload-identity control plane as to public web PKI.

What Omega *does* support, and what fills the slot people reach for
CRL/OCSP to fill:

| Compromise type | Response                                                          |
| --------------- | ----------------------------------------------------------------- |
| Leaf SVID       | Stop renewing; the cert expires within one TTL (≤30 min default)  |
| Workload key    | Re-attest the workload; the agent issues a new SVID on next poll  |
| Signing CA      | Bundle rotation: prepare new CA → propagate via bundle → activate |
| Trust domain    | Federation peer removal propagates through `/v1/bundle`           |

If a future deployment genuinely needs longer-lived (multi-day) SVIDs
and a deny-list mechanism on top, the right place to add it is **the
external PDP layer**: include a `revoked` attribute in the AuthZEN
context and let Cedar policy gate on it. This keeps revocation in
policy, where it can be audited and reasoned about, rather than in a
separate signing channel.

## Omega is not an MCP gateway or agent runtime

MCP servers, A2A SDKs, LangChain, AutoGen, etc. own **agent execution**:
the loop that calls tools, manages context, decides next actions.

Omega issues the **identity** an agent presents to the world (a
JWT-SVID with sender-constraint binding via RFC 8705) and evaluates
the **authorization** for each tool call (AuthZEN PDP), and records
the **delegation chain** (which human authorized which agent to do
what on whose behalf) in the audit log. Agent execution is upstream;
Omega is the policy gate.

Concretely, Omega will not ship an LLM client, a tool registry, or a
prompt template system.

## Out of scope, full stop

A few categories that won't appear no matter how often someone files
the issue:

| Won't ship                             | What to use instead                                                                          |
| -------------------------------------- | -------------------------------------------------------------------------------------------- |
| Application secrets storage            | Vault / OpenBao / cloud secrets managers - Omega's DB holds policy, not secrets              |
| End-user login UX                      | Federate an OIDC IdP. Omega will never render a login form                                   |
| L7 proxy / data plane                  | A service mesh or API gateway. Omega is control plane only                                   |
| Bring-your-own (proprietary) protocols | Every Omega surface is an open standard or pluggable engine. Omega-only clients are rejected |

## How to use this page in PR review

When a PR (or feature request) lands that arguably falls outside the
core, link the relevant section here in the review. If a contributor
disagrees with a "no" listed above, the right venue is a GitHub
Discussion proposing a scope amendment - design principles 1–5 are
revisable, but the bar is explicit.
