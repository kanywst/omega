# ADR 0014: Domain hierarchy with delegated administration

## Status

Accepted.

## Context

Domains (`media`, `media.news`) were the namespace for SPIFFE IDs, but only in name. The store kept a `parent` column derived from the last dot, and nothing else used it: a child could exist without its parent, any caller that passed `--require-auth` could create or rename any domain, and policies could not refer to a domain at all. A multi-team deployment had no way to let the media team run `media.*` without also letting it touch `payments.*`, and no way to write one policy for every workload a team owns.

## Decision

1. **A real tree.** A domain name is dot-separated lowercase labels (`[a-z0-9]`, inner `-` and `_`). Its parent is the name minus the last label and must exist when the child is created. A domain with children cannot be deleted.
2. **Admins per domain, inherited downward.** Each domain carries a set of admin SPIFFE IDs. A principal administers a domain if it is an admin of that domain or of any ancestor, or if it is a `--domain-root-admin`. Administering a domain means it may create domains directly under it, grant and revoke admins on it, and delete its leaf children. Root admins create top-level domains. When a domain is created without explicit admins, the authenticated caller becomes its admin.
3. **Grants are per domain.** Revoking a principal on `media` removes that grant only. A grant it holds on `media.news` (for example because it created that domain) is a separate grant and stays until revoked there. This keeps revocation a single, predictable row change; walking the subtree to revoke everything would surprise the admins of those subdomains.
4. **The tree reaches policy.** Every domain becomes a Cedar entity `Domain::"<name>"` whose parent is its parent domain. A `Spiffe` principal or resource in the local trust domain is placed in the deepest domain whose labels prefix its SPIFFE ID path, so `spiffe://td/media/news/web` is `in Domain::"media.news"` and, transitively, `in Domain::"media"`. A federated peer's SPIFFE ID is never placed in a domain, whatever its path, and neither is a non-canonical ID or one whose path segment contains a dot. Rows an earlier version stored with an invalid name are not projected, and a domain's parent is always derived from its name, as authorization does. Policies can write `principal in Domain::"media"` instead of listing workloads.
5. **Enforcement follows `--require-auth`.** Without it, domain writes stay open, as every other write does. Every create, delete and admin change, and every refused attempt, is audited with the caller as actor. Under `--require-auth` the `admins` lists are returned only to authenticated callers, since they name the identities worth targeting.
6. **Consistency.** Creating a domain locks its parent row and deleting one locks the row before counting children (Postgres `FOR SHARE` / `FOR UPDATE`; SQLite serialises write transactions), so a child can never outlive its parent. A grant is added only while its domain exists, and creating a domain clears any grants left under its name, so a re-created name starts with only the admins it is given.
7. **Freshness.** The server loads the tree into the policy engine before it starts serving, reloads it after each domain write and every five seconds, so no request is evaluated without the tree and a replica that becomes leader sees domains created through another. If reloads keep failing for three intervals (fifteen seconds), policy-evaluating routes answer `503` instead of deciding against a stale tree, since a `forbid` on a newer domain would otherwise not apply.
8. **Recorded or reverted.** A domain create, delete or admin change whose audit row cannot be written is reverted and answered with `500`, so no change to who administers what goes unrecorded. The revert is itself recorded (best effort) as a `reverted` row, in case the failed append had in fact committed. If the revert fails, the response says so instead of claiming it succeeded.

## Consequences

Easier:

- Teams administer their own subtree without a platform-wide admin in the loop.
- One policy covers every workload in a domain, including domains created later.

Harder:

- Membership is derived from the SPIFFE ID path, and domain admins do not control who may obtain an ID under their path: that is decided by issuance and attestation (`--require-auth`, the attestation templates, the OIDC and ID-JAG templates). `principal in Domain::"media"` trusts whatever may mint `/media/...` IDs.
- A domain created on one replica can be missing on another for up to the five-second reload interval.
- Creating `media.news` now needs `media` first. Scripts that created dotted names directly must create the parents (a breaking change, listed under Changed in the CHANGELOG).
- Under `--require-auth`, nobody can create a top-level domain until a `--domain-root-admin` is configured; the server says so at startup.
- A policy decision on a replica can lag a domain write on another replica by up to five seconds.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Who may administer which part of the namespace, and how the namespace appears to policy, are Omega's own control-plane decisions. They belong in Core.
