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
| `server.ca.backend` | `disk` | `--ca-backend`: `disk` (evaluation), `aws-pca`, `gcp-cas` or `azure-keyvault`, each configured by its block below; other backends through `server.extraArgs` |
| `server.ca.gcpCas.pool`                   | `""`                    | CAS CA pool `projects/<p>/locations/<l>/caPools/<pool>`; required for `gcp-cas`                                       |
| `server.ca.gcpCas.endpoint` / `.issuingCA` / `.certificateTemplate` | `""` | API endpoint override (https), a CA id that pins issuance inside the pool, and a certificate template |
| `server.ca.gcpCas.credentialsSecret`      | `""`                    | Secret with `credentials.json`; leave empty to use GKE Workload Identity                                              |
| `policy.inline`                           | `{}`                    | Inline `*.cedar` files via ConfigMap                                                                                  |
| `agent.uidMap`                            | `[]`                    | `uid=N,id=spiffe://...` mappings                                                                                      |
| `agent.hostSocketPath`                    | `/run/omega`            | hostPath for the workload socket; must be under `/run/omega*` or `/var/run/omega*`                                    |
| `agent.k8sWorkloadAttestor.enabled`       | `false`                 | Identify pod workloads by their pod (dev / eval); `hostPID`, own ServiceAccount with `list` on pods                   |
| `agent.localPDP.enabled`                  | `false`                 | Decide on the node (`--local-pdp-addr`)                                                                               |
| `agent.localPDP.tlsSecret`                | `""`                    | Secret with `ca.crt`, `tls.crt`, `tls.key` for the agent's SVID                                                       |
| `server.policyBundleSigningKeySecret`     | `""`                    | Secret with `bundle.key` (ECDSA P-256) that signs policy bundles                                                      |
| `agent.localPDP.verifyBundle`             | `true`                  | Verify bundle signatures with `bundle.pub` from `agent.localPDP.tlsSecret`                                            |
| `agent.localPDP.spool`                    | `false`                 | Spool decisions to an emptyDir                                                                                        |
| `server.persistence.size`                 | `1Gi`                   | PVC for SQLite data dir                                                                                               |
| `server.ca.awsPCA.arn`                    | `""`                    | AWS Private CA ARN (required for `aws-pca`); see [AWS Private CA](#aws-private-ca)                                    |
| `server.ca.awsPCA.region`                 | `""`                    | Region of the API endpoint; empty takes it from the ARN                                                               |
| `server.ca.awsPCA.endpoint`               | `""`                    | Endpoint override, e.g. a VPC interface endpoint (https)                                                              |
| `server.ca.awsPCA.templateArn`            | `""`                    | Certificate template; empty uses `EndEntityCertificate_APIPassthrough/V1`                                             |
| `server.ca.awsPCA.signingAlgorithm`       | `""`                    | Signing algorithm; empty infers it from the CA key                                                                    |
| `server.ca.awsPCA.bundle`                 | `chain`                 | Served trust bundle: `chain` (issuing CA and its chain to the root) or `issuing` (issuing CA alone); see [AWS Private CA](#aws-private-ca) |
| `csi.enabled`                             | `false`                 | Deploy the SPIFFE CSI driver so pods mount the Workload API with `csi.spiffe.io` (privileged, cluster-wide CSIDriver) |
| `agent.nodeSelector`, `agent.tolerations` | `{}`, `[]`              | Where the agent runs; the CSI driver follows                                                                          |
| `server.podLabels` | `{}` | Extra server pod labels, e.g. `azure.workload.identity/use: "true"` |
| `server.ca.azureKeyVault.url` / `.key` / `.keyVersion` | `""` | Key Vault or Managed HSM URL and the EC P-256 key that signs as the CA (`backend: azure-keyvault`) |
| `server.ca.azureKeyVault.caCertSecret` | `""` | Secret with `ca.crt`, the CA certificate for the key; set it with more than one replica |
| `server.ca.azureKeyVault.credentialsSecret` | `""` | Secret loaded as `AZURE_*` environment variables for a service principal; leave empty for workload or managed identity, since a client secret takes precedence over both |

## CA in Azure Key Vault

With `server.ca.backend: azure-keyvault` the CA private key stays in Azure Key Vault (or Managed HSM) and the server signs every X.509-SVID and JWT-SVID through it. Create an EC P-256 key and give the server's identity the `sign` and `get` key permissions (the `Key Vault Crypto User` role):

```bash
az keyvault key create --vault-name myvault --name omega-ca --kty EC --curve P-256 --ops sign verify
```

On AKS with workload identity, annotate the service account and label the pod:

```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: "<client id>"
server:
  podLabels:
    azure.workload.identity/use: "true"
  ca:
    backend: azure-keyvault
    azureKeyVault:
      url: https://myvault.vault.azure.net
      key: omega-ca
```

Without `caCertSecret` the server self-signs a CA certificate through Key Vault on first start and keeps it in its data volume (`ca/azure-keyvault-ca.crt`). With more than one replica, copy that file into a Secret and set `caCertSecret`, and pin `keyVersion`, so every replica serves the same CA and signs with the same key version; the chart refuses to render otherwise. See [docs/ca-azure-keyvault.md](../../docs/ca-azure-keyvault.md).

## AWS Private CA

With `server.ca.backend=aws-pca`, the server signs X.509-SVIDs with an AWS Private CA and the CA key never leaves AWS. JWT-SVIDs are still signed by a key under `server.dataDir`, so keep persistence enabled. The server authenticates with the pod's AWS identity, so no credentials go into values. With IRSA, annotate the service account with a role that may call `acm-pca:IssueCertificate`, `acm-pca:GetCertificate` and `acm-pca:GetCertificateAuthorityCertificate` on the CA:

```bash
helm install omega ./charts/omega \
  --set server.trustDomain=example.com \
  --set server.ca.backend=aws-pca \
  --set server.ca.awsPCA.arn=arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/EXAMPLE \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::111122223333:role/omega-pca
```

When the CA is a subordinate under a root that also has other subordinates, set `server.ca.awsPCA.bundle=issuing` so only the issuing CA is served as a trust anchor and certificates from the other subordinates are not trusted for the trust domain. Peers and federation partners must then accept that CA as an anchor even though it is not self-signed; see [docs/ca-aws-pca.md](../../docs/ca-aws-pca.md#trust-bundle).

## Verify

```bash
kubectl port-forward svc/omega-server 8080:8080
curl -s http://127.0.0.1:8080/healthz
```

Then issue an AuthZEN evaluation as shown in the post-install notes.

## Known limitations

- Single-replica server out of the box (SQLite). Postgres-backed HA is available behind `--db postgres://...` plus the leader-election flags; the chart ships the SQLite default.
- Agent uses UID-based attestation by default. `agent.k8sWorkloadAttestor.enabled` identifies pod workloads by their pod instead, for development and evaluation; it needs a server without `--require-auth` and is not a production substitute for SPIRE ([ADR 0020](../../docs/adr/0020-agent-side-kubernetes-workload-attestor.md)).
- No CRDs / Operator wiring in this chart.

## SPIFFE CSI driver

With `csi.enabled`, any pod that may use a `csi.spiffe.io` ephemeral volume can reach the Workload API, and the agent attests a caller by the UID it connects with alone. A pod in any namespace that runs as a UID in `agent.uidMap` therefore receives that identity. Keep each mapped UID unique to one workload (not 65532, the default of most distroless images), and restrict `csi.spiffe.io` volumes with admission policy. The driver container runs privileged with bidirectional mount propagation on `/var/lib/kubelet/pods`; its images are pinned by digest.
