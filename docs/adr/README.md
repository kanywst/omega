# Architecture Decision Records

This directory holds the project's Architecture Decision Records
(ADRs): short, immutable notes that capture the *why* behind a
specific technical choice and the alternatives that were considered.

The intent is that someone arriving at the project later can read
the ADR list and understand why the code looks the way it does
without having to reconstruct the conversation from `git log`,
GitHub issues, or maintainer memory.

## When to write one

Open an ADR when a change does at least one of:

- Selects between technologies that look interchangeable on the
  surface (e.g. Postgres advisory lock vs. Raft for HA).
- Bakes in a default that downstream operators inherit (e.g.
  Cedar as the default PDP, 30-minute X.509-SVID lifetime).
- Records a conscious *non*-decision (e.g. "we will not implement
  Raft in-process") so it does not get re-litigated.
- Crosses a trust boundary or changes one - those should also be
  reflected in [`../threat-model.md`](../threat-model.md).

Routine refactors, dependency bumps, and obvious bug fixes do not
need an ADR. Conventional Commits + a clear PR description is
enough.

## Format

ADRs in this repo follow the
[Michael Nygard format](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
with a short scope-fit section appended. Each file has the
sections:

- **Status** - Proposed / Accepted / Superseded by ADR-N /
  Deprecated.
- **Context** - the forces and constraints that motivated the
  decision.
- **Decision** - the change being made, in one or two paragraphs.
- **Consequences** - what becomes easier, what becomes harder,
  what new obligations the project takes on.
- **Scope fit** - which of the four "when in doubt" rules in
  [`../design-philosophy.md`](../design-philosophy.md) places
  this in Core, Plugin, or Out-of-tree.

ADRs are immutable once accepted. To change a decision, write a
new ADR that supersedes the old one and update the old ADR's
Status to `Superseded by ADR-N`.

## File naming

`NNNN-kebab-case-title.md`, monotonically increasing. The number
is allocated at PR open time. Reserve the slot in this README's
index to avoid collisions.

## Index

| Number | Title | Status |
| --- | --- | --- |
| [0001](0001-cedar-as-default-pdp.md) | Cedar as the default PDP | Accepted |
| [0002](0002-postgres-advisory-lock-ha.md) | Postgres advisory-lock leader election over in-process Raft | Accepted |
| [0003](0003-short-lived-svids-no-revocation.md) | Short-lived SVIDs instead of CRL / OCSP | Accepted |
| [0004](0004-single-binary-three-roles.md) | Single binary with three runtime roles | Accepted |
| [0005](0005-ca-plugin-architecture.md) | Authority interface as the CA backend plugin seam | Accepted |
| [0006](0006-policy-engine-plurality-at-the-portfolio-line.md) | Policy-engine plurality lives at the portfolio line, not in-process | Accepted |
