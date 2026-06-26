# Omega Helm Chart

> Status: pre-alpha. Do not use in production.

This chart deploys Omega's control-plane server as a `StatefulSet` and the
node agent as a `DaemonSet`. The agent exposes the SPIFFE Workload API
over a Unix socket on a `hostPath` so workload pods can mount it.

## Install

```bash
helm install omega ./charts/omega \
  --set server.trustDomain=example.com
```

## Values

See [`values.yaml`](values.yaml) for the full schema. Notable knobs:

| Key                       | Default                  | Notes                                |
| ------------------------- | ------------------------ | ------------------------------------ |
| `image.repository`        | `ghcr.io/kanywst/omega`  | Container image                      |
| `server.trustDomain`      | `omega.local`            | SPIFFE trust domain                  |
| `server.policyDir`        | `""`                     | Mount Cedar policies into this path  |
| `policy.inline`           | `{}`                     | Inline `*.cedar` files via ConfigMap |
| `agent.uidMap`            | `[]`                     | `uid=N,id=spiffe://...` mappings     |
| `agent.hostSocketPath`    | `/run/omega`             | hostPath for the workload socket     |
| `server.persistence.size` | `1Gi`                    | PVC for SQLite data dir              |

## Verify

```bash
kubectl port-forward svc/omega-server 8080:8080
curl -s http://127.0.0.1:8080/healthz
```

Then issue an AuthZEN evaluation as shown in the post-install notes.

## Known limitations

- Single-replica server out of the box (SQLite). Postgres-backed HA is available behind `--db postgres://...` plus the leader-election flags; the chart ships the SQLite default.
- Agent uses UID-based attestation. K8s SAT projection is a planned follow-up.
- No CRDs / Operator wiring in this chart. CSI driver is a planned follow-up.
