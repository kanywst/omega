# ADR 0017: Provisioning users and groups over SCIM 2.0

## Status

Accepted.

## Context

People already live in an identity provider: who joined, who moved team, who left. Since ADR 0015, Omega groups can grant those people access, but someone had to copy each membership change into Omega by hand, and a departure only took effect when someone remembered to remove the person. The industry interface for pushing that state out of an identity provider is SCIM 2.0 (RFC 7643, RFC 7644), which every major provider speaks. The ID-JAG grant (ADR 0011) already gives a person a SPIFFE ID derived from the provider's subject, so a provisioned membership only needs to land on that same ID.

## Decision

1. **One endpoint per provider.** `--scim-idp name=<name>,domain=<domain>,token-file=<path>[,template=...]` serves SCIM at `/scim/v2/<name>/`: `Users`, `Groups`, and the discovery resources. The provider authenticates with a static bearer token, stored as a SHA-256 hash and compared in constant time, because that is what providers support. The routes are leader-gated and do not take an SVID.
2. **Users map to SPIFFE IDs.** A user's SPIFFE ID comes from the provider's template, `spiffe://<trust-domain>/humans/{idp}/{externalId}` by default, which is the shape the ID-JAG grant gives the same person when the provider's subject is the SCIM `externalId`. Each substituted value must be exactly one path segment, and the template must start with a fixed segment and put `{idp}` ahead of the user's attributes, so providers' users stay in distinct subtrees. The ID must be valid and in the local trust domain. A change to the attributes the template uses moves the user's memberships to the new ID.
3. **Groups are Omega groups the provider owns.** A SCIM group creates the group `<domain>:<slug of displayName>` in the provider's domain. Its members are the SPIFFE IDs of its active SCIM members; a rename renames the Omega group. Such a group can only be changed over SCIM, and the Omega group API answers `409` for it, so the two views cannot drift. That check runs inside each group write's own transaction.
4. **Deactivation revokes at once.** A user with `active: false`, or a deleted user, is removed from every Omega group in the same transaction, so the next policy evaluation no longer counts the memberships. Reactivation restores them.
5. **Change and record commit together.** Each SCIM write and its audit row (`scim.user.*`, `scim.group.*`, actor `scim:<name>`) are written in one database transaction. Either both are kept or neither is, so no provisioning change goes unrecorded and nothing has to be undone after the fact.

## Consequences

Easier:

- Joiners, movers and leavers in the identity provider reach Omega's policy decisions without anyone touching Omega, and a departure ends access on the next evaluation.
- The same person has one SPIFFE ID whether they act through an ID-JAG grant or are referenced by a provisioned group.

Harder:

- SCIM groups do not nest, like Omega groups. Group-in-group pushes from a provider are not expanded.
- Filters support `<attribute> eq "<value>"` only, and bulk, sorting and ETags are not offered. Providers that need more must page through lists.
- The provider's bearer token is a long-lived secret. It belongs in a file readable only by Omega, and rotating it means replacing the file and restarting.
- A provider must reach a listener that does not demand a client certificate, so a deployment that requires mTLS on every connection needs `--client-cert-optional` or a separate ingress for `/scim/`.

## Scope fit

Rule 2 in [design-philosophy.md](../design-philosophy.md): *"Is it a control-plane decision Omega owns?"*

Yes. Who is in which group is state Omega's policy engine decides on (ADR 0015). Accepting that state from where it is mastered, over the standard interface, keeps Omega the place where it is enforced and audited without making it the place where people are managed.
