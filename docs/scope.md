# Omega - Minimum demo scope

> What ships in the current source tree as the "default" demo path. The
> [GitHub issues](https://github.com/kanywst/omega/issues) sketches what comes next.

## Goal

> `omega server` (control plane) + `omega agent` (Workload API) + `omega svid fetch` (CLI).
> A demo client picks up an X.509-SVID, calls a protected HTTP endpoint, and the request is
> allowed or denied by a Cedar policy. End-to-end demo in 30 seconds.

## In-scope today

- Single binary `omega` with subcommands: `server`, `agent`, `domain`, `policy`, `svid`.
- Self-signed CA on first boot. X.509-SVID and JWT-SVID; 30-minute X.509 validity.
  SPIFFE ID format `spiffe://omega.local/<domain-path>/<service>`.
- SPIFFE Workload API on `/tmp/omega-agent.sock`, UID-based attestation.
- Cedar engine embedded. OpenID AuthZEN 1.0 PDP API at `POST /access/v1/evaluation`.
- Storage: SQLite (`<data-dir>/omega.db`) by default; Postgres backend behind `--db postgres://...`.
- Optional HA: Postgres advisory-lock leader election (`--ha-leader-key`).
- Audit log with tamper-evident hash chain and webhook forwarding.
- SPIFFE federation via the `--federate-with` flag.
- `examples/hello-svid/` demo (server + client), wired up by `make demo`.

## Out-of-scope today

K8s CRDs / Operator wiring (separate manifests), CSI driver, OIDC federation
hub, PQC (ML-DSA), HSM / KMS Authority plugins, AI agent delegation reference
implementation. See the [GitHub issues](https://github.com/kanywst/omega/issues) for what is
queued next.

## Definition of Done for the demo

1. `make build` cross-compiles for darwin/arm64 and linux/amd64.
2. `make demo` brings up server, agent, demo client and shows allow/deny.
3. `go test ./...` is green with `-race`.
4. README has a quickstart that fits on one screen.
