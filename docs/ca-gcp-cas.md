# Google Cloud CAS backend

`--ca-backend=gcp-cas` hands X.509-SVID signing to a [Google Cloud Certificate Authority Service](https://cloud.google.com/certificate-authority-service) (CAS) CA pool. The CA keys stay in Google-managed HSMs and never sit on Omega's disk. JWT-SVIDs are still signed by a local key under `--data-dir`, as with the Vault PKI and step-ca backends; [ADR 0005](adr/0005-ca-plugin-architecture.md) explains why.

## How it works

Omega calls two methods of the CAS v1 REST API with an OAuth 2.0 access token from Application Default Credentials (ADC):

| Call | Used for |
| --- | --- |
| `POST /v1/<pool>:fetchCaCerts` | The trust bundle. Every certificate of every CA chain in the pool, deduplicated, is served as the X.509 bundle. It is fetched once at startup (a failure stops the server) and refreshed every five minutes; if a refresh fails, the last good bundle keeps being served. |
| `POST /v1/<pool>/certificates` | One call per X.509-SVID, with a 30-minute `lifetime`. |

Workload CSRs carry no SANs, so Omega does not forward them as `pemCsr`. It sends a `CertificateConfig` instead: the CSR's public key, an empty subject, the SPIFFE ID as the only URI SAN, `digitalSignature`, `keyEncipherment` and `keyAgreement` key usages, `serverAuth` and `clientAuth` extended key usages, and `isCa: false`. Before the certificate reaches the workload, Omega checks that it binds the CSR's public key, carries the requested SPIFFE ID as a URI SAN, and is not a CA certificate; a pool or template that changes any of those makes issuance fail instead of handing out a wrong SVID.

Workloads receive the leaf alone. When the pool's CAs are subordinate CAs, the issuing CA is in the bundle (fetchCaCerts returns it with the root), so the leaf still verifies against the bundle.

## Setting up the pool

Create a pool and a CA in it. The DevOps tier does not store issued certificates, which suits SVIDs that live for 30 minutes and are never revoked ([ADR 0003](adr/0003-short-lived-svids-no-revocation.md)); an Enterprise-tier pool also works, since Omega always sends a `certificateId`, but it keeps a record of every SVID.

```bash
gcloud privateca pools create omega-pool --location=us-central1 --tier=devops
gcloud privateca roots create omega-root --pool=omega-pool --location=us-central1 \
  --subject="CN=Omega SPIFFE root" --auto-enable
```

The pool's issuance policy must let the requested SAN through. With no `identityConstraints` CAS adds no restriction; if the policy sets them, `allowSubjectAltNamesPassthrough` must be `true`, or CAS drops the SPIFFE ID and Omega rejects the certificate. Limiting the pool to your trust domain with a CEL expression keeps a leaked credential from minting anything else:

```yaml
identityConstraints:
  allowSubjectPassthrough: true
  allowSubjectAltNamesPassthrough: true
  celExpression:
    expression: 'subject_alt_names.all(san, san.type == URI && san.value.startsWith("spiffe://example.org/"))'
maximumLifetime: 3600s
```

```bash
gcloud privateca pools update omega-pool --location=us-central1 --issuance-policy=policy.yaml
```

Set `maximumLifetime` to at least 30 minutes; CAS shortens a certificate that would outlive the policy or its issuing CA.

## Credentials and IAM

Omega finds credentials the way every Google client does: `GOOGLE_APPLICATION_CREDENTIALS`, then the file `gcloud auth application-default login` writes, then the metadata server (GKE Workload Identity, Compute Engine, Cloud Run). The identity it runs as needs `roles/privateca.certificateRequester` on the pool to create certificates and a role with `privateca.caPools.get`, such as `roles/privateca.poolReader`, for fetchCaCerts:

```bash
gcloud privateca pools add-iam-policy-binding omega-pool --location=us-central1 \
  --member=serviceAccount:omega@PROJECT.iam.gserviceaccount.com --role=roles/privateca.certificateRequester
gcloud privateca pools add-iam-policy-binding omega-pool --location=us-central1 \
  --member=serviceAccount:omega@PROJECT.iam.gserviceaccount.com --role=roles/privateca.poolReader
```

Access tokens are sent only over HTTPS (plain HTTP is accepted only for a loopback endpoint such as a local fake) and never appear in Omega's logs or errors.

## Flags

```bash
omega server --trust-domain=example.org --data-dir=/var/lib/omega \
  --ca-backend=gcp-cas \
  --ca-gcp-cas-pool=projects/PROJECT/locations/us-central1/caPools/omega-pool
```

| Flag | Meaning |
| --- | --- |
| `--ca-gcp-cas-pool` | Required. The pool, as `projects/<project>/locations/<location>/caPools/<pool>`. |
| `--ca-gcp-cas-endpoint` | API base URL. Empty means `https://privateca.googleapis.com`; set it for a Private Service Connect endpoint. |
| `--ca-gcp-cas-issuing-ca` | Optional CA id in the pool that signs every SVID, instead of the pool's load balancing across its CAs. |
| `--ca-gcp-cas-certificate-template` | Optional template applied to every SVID, as `projects/<project>/locations/<location>/certificateTemplates/<template>`. It must not drop the URI SAN or change the key. |

## Helm

```yaml
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: omega@PROJECT.iam.gserviceaccount.com
server:
  trustDomain: example.org
  ca:
    backend: gcp-cas
    gcpCas:
      pool: projects/PROJECT/locations/us-central1/caPools/omega-pool
```

On GKE, bind the chart's Kubernetes ServiceAccount to the Google service account with Workload Identity as above. Outside GKE, put a credentials file in a Secret under the key `credentials.json` and set `server.ca.gcpCas.credentialsSecret`; the chart mounts it and points `GOOGLE_APPLICATION_CREDENTIALS` at it.

## Rotation

`omega ca prepare / activate / retire` rotate the disk backend only. With CAS, add a new CA to the pool, let fetchCaCerts publish it (Omega's bundle includes it within five minutes), then disable the old one once SVIDs and federated peers have caught up. Omega does not orchestrate this.
