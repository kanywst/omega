# ADR 0014: Domain hierarchy with delegated administration

## Status

Accepted.

## Context

Domains (`media`, `media.news`) were the namespace for SPIFFE IDs, but only in name. The store kept a `parent` column derived from the last dot, and nothing else used it: a child could exist without its parent, any caller that passed `--require-auth` could create or rename any domain, and policies could not refer to a domain at all. A multi-team deployment had no way to let the media team run `media.*` without also letting it touch `payments.*`, and no way to write one policy for every workload a team owns.

## Decision

1. **A real tree.** A domain name is dot-separated lowercase labels (`[a-z0-9]`, inner `-` and `_`). Its parent is the name minus the last label and must exist when the child is created. A domain with children cannot be deleted.
2. **Admins per domain, inherited downward.** Each domain carries a set of admin SPIFFE IDs. A principal administers a domain if it is an admin of that domain or of any ancestor, or if it is a `--domain-root-admin`. Administering a domain means it may create domains directly under it, grant and revoke admins on it, and delete its leaf children. Root admins create top-level domains. When a domain is created without explicit admins, the authenticated caller becomes its admin.
3. **Grants are per domain.** Revoking a principal on `media` removes that grant only. A grant it holds on `media.news` (for example because it created that domain) is a separate grant and stays until revoked there. This keeps revocation a single, predictable row change; walking the subtree to revoke everything would surprise the admins of those subdomains.
4. **The tree reaches policy.** Every domain becomes a Cedar entity `Domain::"<name>"` whose parent is its parent domain. A `Spiffe` principal or resource is placed in the deepest domain whose labels prefix its SPIFFE ID path, so `spiffe://td/media/news/web` is `in Domain::"media.news"` and, transitively, `in Domain::"media"`. A path segment containing a dot is never treated as labels. Policies can write `principal in Domain::"media"` instead of listing workloads.
5. **Enforcement follows `--require-auth`.** Without it, domain writes stay open, as every other write does. Every create, delete and admin change is audited with the caller as actor.
6. **Freshness.** The server reloads the tree into the policy engine after each domain write and every five seconds, so a replica that becomes leader sees domains created through another.

## Consequences

Easier:

- Teams administer their own subtree without a platform-wide admin in the loop.
- One policy covers every workload in a domain, including domains created later.

Harder:

- Creating `media.news` now needs `media` first. Scripts that created dotted names directly must create the parents (a breaking change, listed under Changed in the CHANGELOG).
- Under `--require-auth`, nobody can create a top-level domain until a `--domain-root-admin` is configured; the server says so at startup.
- A policy decision on a replica can lag a domain write on another replica by up to five seconds.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Who may administer which part of the namespace, and how the namespace appears to policy, are Omega's own control-plane decisions. They belong in Core.
