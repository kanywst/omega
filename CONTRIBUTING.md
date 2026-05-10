# Contributing to Omega

Thanks for your interest in Omega. This document describes how to
contribute code, documentation, and other improvements.

## Before you start

- Read the [README](README.md) and the
  [scope document](docs/scope.md) to understand the current
  shape of the project.
- Read [GOVERNANCE.md](GOVERNANCE.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- For non-trivial changes (new features, breaking changes, new
  endpoints), open an issue first to discuss the approach. This avoids
  wasted work.

## Scope

Omega is a deliberately bounded project. Before opening a feature
request or a PR for a new surface, please check that the work fits
the charter - most of the friction in OSS projects this size comes
from rebuilding scope arguments in every review.

The charter, in two sentences: Omega is the **workload + agent
identity and authorization control plane**. Issuing identities
(SPIFFE-compatible X.509 / JWT-SVID, OIDC for humans), evaluating
authorization (AuthZEN 1.0 PDP, Cedar by default), federating with
external IdPs (OIDC / RFC 8693), and writing the tamper-evident audit
log of every decision.

Things that fall *outside* the charter - secrets management,
end-user login UX, service-mesh data plane, SIEM analytics, agent
runtime - are documented in [docs/non-goals.md](docs/non-goals.md)
along with the recommended replacement for each. PR reviewers will
link to that page when declining feature requests; if you disagree
with a specific "no" listed there, the right venue is a GitHub
Discussion proposing a scope amendment, not a stealth PR.

Five design principles drive everything in scope: UI / DX as a first
deliverable, RBAC + ABAC + ReBAC unified, open-standards alignment,
three-subject coverage (service / human / agent), and SPIRE / OPA
style modularity. New code that violates one of those should explain
in the PR description which principle it relaxes and why.

For features that fall in a gray area between in-tree and out-of-tree,
the four "when in doubt" rules in
[docs/design-philosophy.md](docs/design-philosophy.md) are how
reviewers decide whether the feature is Core, Plugin (in-tree
interface plus default), or Out-of-tree (integrate, never ship). PR
descriptions for new surfaces should name the layer and the rule that
placed them there.

## Development setup

Requirements:

- Go 1.25 or later.
- `make` and a POSIX shell (Linux or macOS).
- Optional: `golangci-lint` 2.x for local lint runs.

Clone and bootstrap:

```bash
git clone https://github.com/0-draft/omega
cd omega
make build
make test
make demo
```

`make demo` starts the full control plane, two agents, and the
`hello-svid` demo. It exits 0 if the mTLS handshake between SVID-bearing
workloads succeeds.

## Repository layout

```text
cmd/omega/            entry point (cobra root command)
internal/cli/         subcommand implementations (server, agent, svid, ...)
internal/server/      control plane: api, ca, store, policy
internal/agent/       node agent: workloadapi, attestor, cache
examples/hello-svid/  end-to-end demo
docs/                 design notes and project scope
scripts/              demo and release helpers
```

`api/openapi.yaml` is the OpenAPI 3.1 specification of every HTTP
endpoint the control plane serves. New endpoints, request/response
shape changes, and status-code changes must update it in the same
pull request that changes the handler. CI runs `redocly lint` against
the spec on every push. Generated code, if any, lives under
`internal/`.

## Pull request guidelines

- One logical change per pull request. Refactors and behaviour changes
  go in separate PRs.
- Add tests for new behaviour. `go test -race ./...` must stay green.
- Run `golangci-lint run` and `make demo` locally before opening the PR.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(scope): ...`, `fix: ...`, `chore: ...`, `docs: ...`.
- Sign-off is not required (Apache-2.0 grants are sufficient and there
  is no DCO bot).
- Keep the README quickstart fitting on one screen.

## Style

- Go: standard `gofmt` + `goimports` with local prefix
  `github.com/0-draft/omega`. Enforced by `golangci-lint`.
- Markdown: must lint clean under `markdownlint-cli2`. Headings,
  lists, tables, and fenced code blocks need surrounding blank lines;
  every code fence needs a language tag (use `text` for plain output).
- Comments: write them only when the *why* is non-obvious. Do not
  narrate the code.

## Reporting bugs

Open a GitHub issue with:

- Omega version (`omega --version` once that lands; until then, the
  commit SHA).
- Operating system and Go version.
- Steps to reproduce, expected behaviour, and actual behaviour.
- Logs from `omega server` and `omega agent` if relevant.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for
vulnerabilities.

## License

By contributing, you agree that your contributions are licensed under
the Apache License 2.0, the same license that covers the project.
