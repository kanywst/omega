---
name: Omega project guide
description: Repo-level guidance for Claude Code working in the Omega control plane.
---

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common commands

Go side (run from repo root):

| Command | What it does |
| --- | --- |
| `make build` | Build the single binary into `bin/omega`. Embeds version via `-ldflags`. |
| `make test` | `go test -race -count=1 ./...`. Postgres-backed tests skip unless `OMEGA_TEST_POSTGRES_DSN` is set. |
| `make demo` | Local Go build + `scripts/demo.sh`: runs the full hello-svid mTLS loop without Docker. Used as a smoke test. |
| `make docker-up` / `make docker-down` | Compose stack (control plane + 2 agents + hello-svid + UI) on `:8080` / `:3000` / `:9443`. |
| `make docker-demo` | Same compose stack but exits when the hello-svid client succeeds. CI smoke test. |
| `make observability-up` | Self-contained Prometheus + Grafana on `:13001` / `:19090` / `:18080/metrics`. Uses non-default ports so it can run alongside `docker-up`. |
| `make cross` | Cross-compile to `dist/omega-{linux,darwin}-{amd64,arm64}`. |
| `make lint` | `golangci-lint run`. See "Lint" below. |

Run a single Go test:

```bash
go test -race -run TestPumpRetriesOnForwarderError ./internal/server/audit/...
```

Stress an individual package for races (used when chasing flakes):

```bash
go test -race -count=20 ./internal/server/audit/...
```

UI side (run from `ui/`):

```text
npm run dev        # next dev --turbopack, hot reload, proxies to OMEGA_API (default http://127.0.0.1:8080)
npm run build      # next build
npm run typecheck  # tsc --noEmit
npm run lint       # biome check .
npm run format     # biome format --write .
```

The UI is **not** embedded in the Go binary. `make docker-up` builds it as a separate container.

## Architecture (the parts that span files)

`cmd/omega/main.go` is a thin shim into `internal/cli`, which builds a Cobra root with subcommands `server`, `agent`, `operator`, `domain`, `policy`, `svid`. One binary, three runtime roles:

- `omega server` — control plane. HTTP API at `:8080`, CA + SVID issuance, AuthZEN PDP (Cedar), SPIFFE federation, audit log. Backed by SQLite by default; pass `--db postgres://...` for HA.
- `omega agent` — node agent. Speaks the SPIFFE Workload API on a Unix domain socket, attests workloads by UID via `peercred`, pulls SVIDs and trust bundles from the server.
- `omega <CRUD>` — admin CLI (domains / policies / SVIDs).

Server packages (`internal/server/`):

- `api/` — HTTP routing. Read endpoints (`/healthz`, `/v1/leader`, `GET /v1/domains`, `GET /v1/bundle`) are not gated. Every write endpoint and `/access/v1/evaluation` is wrapped in a `leaderOnly` helper that returns 503 + `Retry-After: 1` when the Postgres advisory lock is held by another replica. **When you add a new write or PDP endpoint, wrap it.**
- `storage/` — SQLite + Postgres drivers behind one `Store`. Postgres mode runs `pg_try_advisory_lock` leader election (`leader.go`, key `0x0e6a3a0001`). `IsLeader()` is what gates writes; `ErrNotLeader` is what bubbles up.
- `audit/` — tamper-evident hash chain plus a `Pump` that forwards events to external sinks. `audit.go` `AppendAudit` is serialized through one mutex so the prev-hash lookup and INSERT cannot interleave; `Verify` walks the chain and reports the first mismatched `seq`.
- `federation/` — `--federate-with name=...,url=...` peers. Bundle exchange is a one-way GET against the peer's `/v1/bundle`; `Run()` uses an initial backoff sequence so concurrent peer boot does not race.
- `attest/` — node/workload attestation. `k8s.go` verifies a service-account token via the Kubernetes `TokenReview` API (fake clientset in tests, no live apiserver needed).
- `oidc/` — external OIDC IdP federation. `registry.go` validates third-party OIDC tokens against discovery + JWKS so human/agent identities from an IdP can be consumed; omega never calls `/token` or `/authorize`.
- `policy/`, `identity/`, `metrics/`, `tracing/` — Cedar PDP, CA / SVID issuance, Prometheus, OTel.

Agent (`internal/agent/`) is structured around a Workload API server, a peercred attestor, and an SVID cache.

Operator (`internal/operator/`) reconciles `OmegaDomain` and `OmegaIssuer` CRDs. The cert-manager `Issuer` reconciler resolves `cert-manager.io/v1` types at boot — install cert-manager CRDs first or it exits before reaching the OmegaDomain controller.

## Examples are first-class

Every directory under `examples/` has a `Makefile` with a `make demo` target and a `run-demo.sh` that boots the stack, drives a few API calls, asserts the result, and tears down. The `examples` matrix in `.github/workflows/ci.yml` runs all of them on every PR — a broken example fails CI just like a broken test. When fixing an example, mirror existing patterns:

- Postgres readiness must probe **the host port plus a `SELECT 1` through psql**, not just `pg_isready` inside the container — host port forwarding can lag readiness and trip "connection reset by peer" on first connect (see `examples/postgres-ha/run-demo.sh`).
- For Postgres-backed servers, poll `GET /v1/leader` for `"is_leader":true` before driving writes; `/healthz` returns 200 before the advisory lock is acquired and writes will 503.

## Lint

`golangci-lint` (config `.golangci.yml`, v2 schema) is run in CI but `continue-on-error: true` at the step level: upstream is built with Go 1.25 and refuses to load when `go.mod` targets Go 1.26 (see `golangci/golangci-lint#6272`). The CI `lint` job's pass signal is `go vet ./...`, which runs as a separate step. Remove the workaround once upstream ships a Go 1.26 build.

Locally, `golangci-lint run` works if your toolchain matches `go.mod`.

## Releases

Tagged `v*` pushes (e.g. `v0.0.2`) trigger:

1. `image` job builds and pushes the multi-arch container to `ghcr.io/0-draft/omega:<tag>`.
2. `chart-release` job (gated on `test` + `helm` passing) packages `charts/omega`, appends to `index.yaml`, and pushes both to the `gh-pages` branch via `helm/chart-releaser-action`.

The Helm chart repo is served at `https://0-draft.github.io/omega/` (GitHub Pages → `gh-pages` / root). Consumers use:

```bash
helm repo add omega https://0-draft.github.io/omega
helm repo update
helm install omega omega/omega --version <tag>
```

**Don't hand-edit the `gh-pages` branch.** It's owned by chart-releaser; the only manual touch was the bootstrap orphan commit so the action could find an existing branch on first run. The site root returns 404 by design (no `index.html`); only `/index.yaml` and the `.tgz` URLs in it are meant to be hit.

If a tag's `chart-release` job fails the typical cause is a missing or stale `gh-pages` branch — check that the branch exists and has a valid `index.yaml` before re-running the job.

## Style

- Go: `gofmt` + `goimports` with local prefix `github.com/0-draft/omega`.
- Markdown: must lint clean under `markdownlint-cli2` (`.markdownlint-cli2.jsonc`). Headings, lists, tables, and fenced code blocks need surrounding blank lines; every code fence needs a language tag (use `text` for plain output).
- Comments: only when the *why* is non-obvious. Don't narrate the code.
- Commit messages: Conventional Commits (`feat(scope): ...`, `fix: ...`, `chore: ...`, `docs: ...`).

## Scope discipline

Omega is bounded — workload + agent identity and authorization control plane. Charter is in `README.md`; in/out rules in `docs/design-philosophy.md`; non-goals (with recommended alternatives) in `docs/non-goals.md`. New surfaces should name which design layer (Core / Plugin / Out-of-tree) they land in. Don't add features outside the charter without a Discussion first.
