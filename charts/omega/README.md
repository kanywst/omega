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

| Key                                       | Default                 | Notes                                                                                                                 |
| ----------------------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `image.repository`                        | `ghcr.io/kanywst/omega` | Container image                                                                                                       |
| `server.trustDomain`                      | `omega.local`           | SPIFFE trust domain                                                                                                   |
| `server.policyDir`                        | `""`                    | Mount Cedar policies into this path                                                                                   |
| `server.domainRootAdmins`                 | `[]`                    | `--domain-root-admin` SPIFFE IDs                                                                                      |
| `server.decisionRecorders`                | `[]`                    | Node agents that may read the policy bundle and record local decisions                                                |
| `server.scimProviders`                    | `[]`                    | SCIM providers: `name`, `domain`, `tokenSecret` (Secret with a `token` key), optional `template`                      |
| `policy.inline`                           | `{}`                    | Inline `*.cedar` files via ConfigMap                                                                                  |
| `agent.uidMap`                            | `[]`                    | `uid=N,id=spiffe://...` mappings                                                                                      |
| `agent.hostSocketPath`                    | `/run/omega`            | hostPath for the workload socket; must be under `/run/omega*` or `/var/run/omega*`                                    |
| `agent.localPDP.enabled`                  | `false`                 | Decide on the node (`--local-pdp-addr`)                                                                               |
| `agent.localPDP.tlsSecret`                | `""`                    | Secret with `ca.crt`, `tls.crt`, `tls.key` for the agent's SVID                                                       |
| `server.policyBundleSigningKeySecret`     | `""`                    | Secret with `bundle.key` (ECDSA P-256) that signs policy bundles                                                      |
| `agent.localPDP.verifyBundle`             | `true`                 | Verify bundle signatures with `bundle.pub` from `agent.localPDP.tlsSecret`                                            |
| `agent.localPDP.spool`                    | `false`                 | Spool decisions to an emptyDir                                                                                        |
| `server.persistence.size`                 | `1Gi`                   | PVC for SQLite data dir                                                                                               |
| `csi.enabled`                             | `false`                 | Deploy the SPIFFE CSI driver so pods mount the Workload API with `csi.spiffe.io` (privileged, cluster-wide CSIDriver) |
| `agent.nodeSelector`, `agent.tolerations` | `{}`, `[]`              | Where the agent runs; the CSI driver follows                                                                          |

## Verify

```bash
kubectl port-forward svc/omega-server 8080:8080
curl -s http://127.0.0.1:8080/healthz
```

Then issue an AuthZEN evaluation as shown in the post-install notes.

## Known limitations

- Single-replica server out of the box (SQLite). Postgres-backed HA is available behind `--db postgres://...` plus the leader-election flags; the chart ships the SQLite default.
- Agent uses UID-based attestation. K8s SAT projection is a planned follow-up.
- No CRDs / Operator wiring in this chart.

## SPIFFE CSI driver

With `csi.enabled`, any pod that may use a `csi.spiffe.io` ephemeral volume can reach the Workload API, and the agent attests a caller by the UID it connects with alone. A pod in any namespace that runs as a UID in `agent.uidMap` therefore receives that identity. Keep each mapped UID unique to one workload (not 65532, the default of most distroless images), and restrict `csi.spiffe.io` volumes with admission policy. The driver container runs privileged with bidirectional mount propagation on `/var/lib/kubelet/pods`; its images are pinned by digest.
