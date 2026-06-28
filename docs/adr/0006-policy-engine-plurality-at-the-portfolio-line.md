# ADR 0006: Policy-engine plurality lives at the portfolio line, not in-process

## Status

Accepted.

## Context

[ADR 0001](0001-cedar-as-default-pdp.md) picked Cedar as the
default in-process PDP and noted that any other AuthZEN-speaking
engine (OPA, OpenFGA, SpiceDB, Cerbos, Topaz, …) can be swapped in
later through an AuthZEN bridge. It did not settle a separate
question: should the `omega` binary itself embed *more than one*
policy engine - shipping, say, both Cedar and OPA/Rego so a single
install can run either?

The pull toward engine-plurality is real. Sibling projects in the
same author's portfolio already cover the other sides of this space:

- `opa-authzen-plugin` - in-process OPA/Rego behind the AuthZEN
  wire, aimed at teams that already run a Rego policy estate.
- `spiffe-compliance-checker` - conformance / lint for the
  "SPIFFE × AuthZEN" line.

Bundling a second engine into `omega` would let the README claim
"runs Cedar *or* Rego in one binary", which reads well as a flex.

The cost is not symmetric with the engine *library* cost, though.
Embedding one engine library is cheap relative to, say,
reimplementing a CA. But a *second* embedded engine is not free: it
is a second AuthZEN conformance suite to keep green, a second policy
language to document, test, and exemplify, and a second upstream to
track for breaking changes - paid continuously, by a deliberately
minimal, solo-maintained control plane. The cost scales with the
number of in-process engines, not with the decision to support more
than one.

There is a cleaner place to put plurality: the portfolio, reached
over the AuthZEN wire, rather than the binary.

## Decision

`omega` embeds exactly one policy engine in-process - Cedar, per
ADR 0001 - and will not embed a second. Plurality of policy engines
is a property of the AuthZEN ecosystem and the surrounding
portfolio, realized across separate components that interoperate
over the AuthZEN wire, not inside the `omega` binary:

- `omega` - the greenfield, SPIFFE-native Cedar stack; Cedar
  in-process by default.
- `opa-authzen-plugin` - the retrofit path: AuthZEN for an existing
  OPA/Rego estate, as a separate component.
- `spiffe-compliance-checker` - the conformance/lint layer that
  proves the pieces of the line actually speak AuthZEN.

External AuthZEN-speaking PDPs remain swappable per ADR 0001, but as
out-of-process peers behind the bridge - not as engines compiled
into `omega`.

## Consequences

Easier:

- `omega` carries exactly one AuthZEN conformance suite and one
  policy language across its docs, tests, and `examples/`.
- The single-binary footprint stays minimal; there is one engine to
  track upstream, not N.
- The "SPIFFE × AuthZEN" line still gets plurality - it just comes
  from composing components, so no single component pays the
  second-engine tax.

Harder:

- An operator who wants Cedar *and* Rego inside one process cannot
  get that from `omega` alone. They run `omega` plus an external
  Rego PDP behind the AuthZEN bridge, or adopt `opa-authzen-plugin`
  as a separate component. The "any engine, one binary" flex is
  explicitly out of scope.

New obligations:

- Keep the AuthZEN wire contract stable enough that out-of-process
  engines and the sibling components interoperate cleanly.
- Keep the role split documented (greenfield / retrofit /
  conformance) so the portfolio reads as one coherent line rather
  than three look-alike AuthZEN PDPs.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md):
*"Is it an upstream system Omega depends on but does not own?"*

Yes - the PDP engine is a Plugin-layer concern. This ADR refines how
that Plugin seam is realized: one default engine in-process,
additional engines out-of-process via the AuthZEN bridge. It also
records a conscious *non*-decision - `omega` will not become
engine-plural in-process - so the question does not get
re-litigated.
