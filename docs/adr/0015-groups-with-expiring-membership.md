# ADR 0015: Domain-owned groups with expiring membership

## Status

Accepted.

## Context

Policies could name a principal or, since ADR 0014, a domain. They could not name a set of principals that cuts across the SPIFFE path tree, such as "the media on-call rotation" or "the agents allowed to page". The only option was a static `entities.json` with Cedar parents, which needs a file edit and a restart per change and has no notion of who may change it. Temporary access (an engineer joining on-call for a week, an agent granted a capability for an hour) had no representation at all, so it was either granted permanently or not at all.

## Decision

1. **Groups belong to a domain.** A group has a name (lowercase labels, as for domains) and lives in one domain; its policy identity is `Group::"<domain>:<name>"`. The admins of that domain, through the same inherited admin chain as ADR 0014, create and delete its groups and manage their members. A domain that still owns groups cannot be deleted.
2. **Members are SPIFFE IDs.** Any SPIFFE ID may be a member, a federated peer's included, because an admin named it explicitly. Group entities have no parents: being in `media:oncall` does not put a principal in `Domain::"media"`.
3. **Memberships can expire.** A membership may carry `expires_at`. The expiry is checked when a request is evaluated, not when the tree is reloaded, so access ends at that instant on every replica without waiting for a refresh. Re-adding a member replaces its expiry. An expiry may be at most 366 days ahead. If a change's audit row cannot be written, the change is undone only if the row still holds what this request wrote, so a concurrent, recorded change is never overwritten; a deleted group is restored with its members in one transaction.
4. **The same projection.** Groups and memberships are loaded into the policy engine with the domain tree (ADR 0014): before serving, after each write, and every five seconds. A `Spiffe` principal gets each group it is an active member of as a Cedar parent.
5. **Audit and visibility.** Every create, delete and membership change, and every refused attempt, is audited with the caller as actor. Under `--require-auth` member lists are returned only to authenticated callers.

## Consequences

Easier:

- Policies can say `principal in Group::"media:oncall"`, and a domain's admins change who that is without touching policy files or restarting.
- Time-bound access is a membership with an expiry instead of a grant someone has to remember to revoke.

Harder:

- A membership added on one replica reaches the others within five seconds, the reload interval. Expiry is immediate everywhere.
- Groups do not nest. A group of groups needs a policy that names each group.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Who belongs to which named set, for how long, and who may change it, are control-plane decisions the policy engine depends on. They belong in Core.
