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
| `agent.localPDP.verifyBundle`             | `false`                 | Verify bundle signatures with `bundle.pub` from `agent.localPDP.tlsSecret`                                            |
| `agent.localPDP.spool`                    | `false`                 | Spool decisions to an emptyDir                                                                                        |
| `server.persistence.size`                 | `1Gi`                   | PVC for SQLite data dir                                                                                               |
| `server.ca.backend`                       | `disk`                  | `--ca-backend`; `aws-pca` is configured below, other backends through `server.extraArgs`                              |
| `server.ca.awsPCA.arn`                    | `""`                    | AWS Private CA ARN (required for `aws-pca`); see [AWS Private CA](#aws-private-ca)                                    |
| `server.ca.awsPCA.region`                 | `""`                    | Region of the API endpoint; empty takes it from the ARN                                                               |
| `server.ca.awsPCA.endpoint`               | `""`                    | Endpoint override, e.g. a VPC interface endpoint (https)                                                              |
| `server.ca.awsPCA.templateArn`            | `""`                    | Certificate template; empty uses `EndEntityCertificate_APIPassthrough/V1`                                             |
| `server.ca.awsPCA.signingAlgorithm`       | `""`                    | Signing algorithm; empty infers it from the CA key                                                                    |
| `csi.enabled`                             | `false`                 | Deploy the SPIFFE CSI driver so pods mount the Workload API with `csi.spiffe.io` (privileged, cluster-wide CSIDriver) |
| `agent.nodeSelector`, `agent.tolerations` | `{}`, `[]`              | Where the agent runs; the CSI driver follows                                                                          |

## AWS Private CA

With `server.ca.backend=aws-pca`, the server signs X.509-SVIDs with an AWS Private CA and the CA key never leaves AWS. JWT-SVIDs are still signed by a key under `server.dataDir`, so keep persistence enabled. The server authenticates with the pod's AWS identity, so no credentials go into values. With IRSA, annotate the service account with a role that may call `acm-pca:IssueCertificate`, `acm-pca:GetCertificate` and `acm-pca:GetCertificateAuthorityCertificate` on the CA:

```bash
helm install omega ./charts/omega \
  --set server.trustDomain=example.com \
  --set server.ca.backend=aws-pca \
  --set server.ca.awsPCA.arn=arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/EXAMPLE \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::111122223333:role/omega-pca
```

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
