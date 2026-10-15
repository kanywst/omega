# Omega - Minimum demo scope

> What ships in the current source tree as the "default" demo path. The
> [GitHub issues](https://github.com/kanywst/omega/issues) sketches what comes next.

## Goal

> `omega server` (control plane) + `omega agent` (Workload API) + `omega svid fetch` (CLI).
> A demo client picks up an X.509-SVID, calls a protected HTTP endpoint, and the request is
> allowed or denied by a Cedar policy. End-to-end demo in 30 seconds.

## In-scope today

- Single binary `omega` with subcommands: `server`, `agent`, `operator`, `domain`, `group`, `policy`, `svid`.
- Self-signed CA on first boot, or Vault PKI / step-ca / AWS Private CA / Google Cloud CAS / Azure Key Vault, or identities consumed from an upstream SPIRE / Istio trust domain. X.509-SVID and JWT-SVID; 30-minute X.509 validity.
  SPIFFE ID format `spiffe://omega.local/<domain-path>/<service>`.
- SPIFFE Workload API on `/tmp/omega-agent.sock`, UID-based attestation, and an opt-in Kubernetes workload attestor in the agent for development and evaluation; Kubernetes ServiceAccount attestation on the server.
- Cedar engine embedded. OpenID AuthZEN 1.0 PDP API at `POST /access/v1/evaluation`, also served by the agent from a synced policy bundle.
- Domain tree with delegated admins, and domain-owned groups with expiring membership.
- People: OIDC IdP federation and SCIM 2.0 provisioning. Agents: RFC 8693 token exchange and the ID-JAG grant.
- Storage: SQLite (`<data-dir>/omega.db`) by default; Postgres backend behind `--db postgres://...`.
- Optional HA: Postgres advisory-lock leader election (`--ha-leader-key`).
- Audit log with tamper-evident hash chain and webhook / OTLP forwarding.
- SPIFFE federation via the `--federate-with` flag.
- Kubernetes: Helm chart, `OmegaDomain` CRD, cert-manager issuer.
- `examples/hello-svid/` demo (server + client), wired up by `make demo`.

## Out-of-scope today

PQC (ML-DSA). See [ROADMAP.md](../ROADMAP.md) for what is queued next.

## Definition of Done for the demo

1. `make build` cross-compiles for darwin/arm64 and linux/amd64.
2. `make demo` brings up server, agent, demo client and shows allow/deny.
3. `go test ./...` is green with `-race`.
4. README has a quickstart that fits on one screen.
