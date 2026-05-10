<!-- Thanks for contributing to Omega. Please fill in the sections
below. The scope check is mandatory for new surfaces; routine fixes
and chores can drop everything except "Summary" and "Tests". -->

## Summary

<!-- One paragraph: what this changes and why. Link the issue or
discussion that motivates it. -->

## Scope check

This change is:

- [ ] Core (in-tree, mandatory) - Omega owns the wire format or the
      control-plane decision
- [ ] Plugin (in-tree interface + default) - upstream system Omega
      depends on
- [ ] Out-of-tree (integration only, never shipped) - downstream
      consumer or adjacent product
- [ ] Documentation, CI, or chore (no scope impact)

If Core or Plugin, which of the four "when in doubt" rules in
[`docs/design-philosophy.md`](../docs/design-philosophy.md) applies,
and why?

<!-- e.g. "Rule 1 fires: AuthZEN 1.0 batch evaluation is a wire format
Omega exposes." -->

## Tests

- [ ] `go test -race ./...` passes
- [ ] `make demo` passes (if touching `internal/` or `cmd/`)
- [ ] Touched example's `make demo` passes (if touching `examples/<x>/`)
- [ ] `golangci-lint run` clean (advisory; see `.golangci.yml`)
- [ ] `markdownlint-cli2 "**/*.md"` clean (if touching `*.md`)

## Breaking changes

<!-- API, storage layout, config flags, or CLI surface that this
breaks. Pre-1.0 these are allowed in minor versions; list them under
"Changed" in `CHANGELOG.md` and call them out here. Leave blank if
there are no breaks. -->

## Issue / discussion

<!-- Closes #N, refs #N, or "discussed in #N". Required for new
surfaces; see CONTRIBUTING.md. -->
