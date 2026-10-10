# ADR 0016: Local policy decisions on the node, audited centrally

## Status

Accepted.

## Context

Every authorization decision was a network call from the policy enforcement point to the control plane's AuthZEN endpoint. That puts the control plane on the request path of every protected call: its latency is added to each one, and when it is unreachable (network partition, leader failover, maintenance) nothing can be decided at all. The usual answer, and a well-tried one, is to manage policy centrally and evaluate it next to the workload, as long as two properties survive: the local decision must be the decision the control plane would make, and every decision must still reach one audit trail.

## Decision

1. **A policy bundle.** `GET /v1/policy/bundle` returns everything the control plane evaluates against: the Cedar sources, the static `entities.json`, and the projected domain and group directory (ADRs 0014 and 0015). Its revision is a hash of that content and doubles as the ETag, so an unchanged bundle costs a `304`. It needs the same caller authentication as audit reads and is served by followers. `--policy-dir` is reloaded on `SIGHUP`, so a policy change produces a new revision without a restart.
2. **A local PDP in the agent.** `omega agent --local-pdp-addr 127.0.0.1:8181` serves `POST /access/v1/evaluation` on the node. It syncs the bundle every `--policy-sync-interval`, loads it into the same policy engine the server uses (so domain placement, group membership and evaluation-time expiry behave identically), and refuses a bundle whose content does not match its revision.
3. **Fail closed.** The local PDP answers `503` until its first sync, once its last successful sync is older than `--policy-max-age`, and while `--decision-buffer` decisions are waiting to be recorded. It never decides from a policy it cannot vouch for, or without being able to record the decision.
4. **One audit trail.** Each local decision is queued with an id, its time and the bundle revision, and shipped in batches to `POST /v1/audit/decisions`, which appends it to the chain as `access.evaluate` with `source: local` and the agent's SPIFFE ID as actor. A batch that fails is kept and retried; the decision id lets a reader recognise a row written twice by such a retry.
5. **Transport.** The agent reaches the control plane with `--server-ca`, `--client-cert` and `--client-key` for both SVID issuance and the local PDP, so it works against a `--require-auth` server.

## Consequences

Easier:

- Decisions on the node cost a local call, and they keep working through a control-plane outage for up to `--policy-max-age`.
- Policy stays managed in one place, and every decision, local or central, lands in one audit chain.

Harder:

- A policy change reaches a node within one sync interval rather than at once; group expiry is still exact, since it is checked at evaluation time.
- Local decisions reach the audit chain a flush interval late, and are lost if the agent dies with them queued. The buffer bound limits how many.
- The bundle exposes every policy and group membership to each authenticated agent.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Where and how Omega's own policy is evaluated, and how those decisions are recorded, are Omega's decisions. The local PDP lives in the existing agent role (ADR 0004), not a new binary.
