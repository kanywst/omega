# ADR 0004: Single binary with three runtime roles

## Status

Accepted (project inception).

## Context

The project ships three logically distinct runtimes:

- A **control plane** (`omega server`) holding the CA, policy
  set, audit log, and federation state.
- A **node agent** (`omega agent`) serving the SPIFFE Workload
  API over a Unix socket and attesting workloads by UID.
- An **admin CLI** (`omega domain`, `omega policy`, `omega svid`)
  for operator workflows.

There is also a Kubernetes operator (`omega operator`) reconciling
`OmegaDomain` and `OmegaIssuer` CRDs.

Two natural packagings exist:

1. **Multiple binaries** (e.g. `omega-server`, `omega-agent`,
   `omegactl`, `omega-operator`). SPIRE chose this; so did
   Vault (`vault server` and `vault` CLI as separate concerns
   even though they share a binary).
2. **One binary with subcommands** (e.g. `omega server`,
   `omega agent`, `omega domain`). Caddy, Linkerd's `linkerd`,
   and the Kubernetes `kubectl`+`kubelet` pattern (one ELF, many
   modes) are reference points.

Constraints:

- Operators evaluating the project should be able to download
  one binary, run `omega --help`, and understand the surface in
  one sitting. Project marketing leads with "Ω - the last
  identity platform you'll need to deploy"; that promise is
  weaker if the install instructions list four downloads.
- The control plane and the node agent share types, audit
  emission, and metric definitions. Splitting them into
  separate binaries would force those types into a `pkg/` API
  contract earlier than the project is ready to commit to one.
- Container images for `omega server`, `omega agent`, and the
  operator can all share the same base layer if they share the
  same binary, which keeps registry pull volume small.

## Decision

One binary, `omega`, with subcommands `server`, `agent`,
`operator`, `domain`, `policy`, `svid`. The Cobra root command
in `internal/cli` dispatches by subcommand. The container image
has the same binary as its `ENTRYPOINT` and selects the role at
deploy time via the command line.

Components remain independently runnable - the server can run
without the agent (and vice versa), and the operator runs
out-of-cluster against any reachable server.

## Consequences

Easier:

- One install, one upgrade, one set of release artefacts. The
  Helm chart picks the role per Deployment.
- Shared types stay internal (`internal/server/...`,
  `internal/agent/...`) without forcing a stable public Go API.
- Container image deduplication: the multi-arch tag at
  `ghcr.io/kanywst/omega` covers every role.
- Operator UX: `omega --help` enumerates everything the
  project does.

Harder:

- The binary's surface area is larger than any single role
  needs. A Linux audit reviewer looking at `omega agent` sees
  symbols from `omega server` linked in.
- Subcommand naming has to remain stable across releases. The
  pre-1.0 phase allows breaking changes, but post-1.0 the
  subcommand surface joins the public API.
- Cross-compilation and release size: the binary links Cedar, the
  Kubernetes controller-runtime, and the SPIFFE Go libraries even
  for the agent role. Splitting by role would meaningfully cut the
  agent's footprint; we accept the size for the operational
  simplicity. The current size on each platform is visible in the
  `cross` CI job output.

New obligations:

- `internal/cli/root.go` is the single entry point and must
  remain navigable. Subcommand registration belongs there;
  per-subcommand logic belongs under `internal/<role>/...`.
- The Dockerfile is a single multi-stage build that produces
  the same binary regardless of intended role.

## Scope fit

This is an internal architectural choice, not a layer
classification. None of the four "when in doubt" rules in
[design-philosophy.md](../design-philosophy.md) directly fires;
the choice is recorded here so future contributors do not
re-litigate the packaging.

If a future deployment proves the bundled binary too coarse for
its threat model (e.g. signed-build constraints that want the
agent's binary as a separate artefact), the right move is a
new ADR splitting the roles, not a stealth refactor.
