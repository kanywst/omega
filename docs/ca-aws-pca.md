# AWS Private CA backend

`--ca-backend=aws-pca` signs X.509-SVIDs with an [AWS Private CA](https://docs.aws.amazon.com/privateca/latest/userguide/PcaWelcome.html) certificate authority. The CA key is held by AWS and never sits on omega's disk. JWT-SVIDs are still signed by a local key under `--data-dir`, as with the Vault PKI and step-ca backends; [ADR 0005](adr/0005-ca-plugin-architecture.md) explains why JWT signing is not delegated.

## Configuration

```bash
omega server \
  --trust-domain example.com \
  --ca-backend aws-pca \
  --ca-aws-pca-arn arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/EXAMPLE
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--ca-aws-pca-arn` | required | ARN of the certificate authority that signs SVIDs |
| `--ca-aws-pca-region` | region in the ARN | Region of the API endpoint |
| `--ca-aws-pca-endpoint` | SDK default | Endpoint override, for example a VPC interface endpoint; must be https (plain http is accepted only for a loopback host); an endpoint set through `AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_ACM_PCA` or `endpoint_url` is held to the same rule |
| `--ca-aws-pca-template-arn` | `EndEntityCertificate_APIPassthrough/V1` | Certificate template; must be an API-passthrough end-entity template |
| `--ca-aws-pca-signing-algorithm` | inferred from the CA key | `SHA256WITHECDSA` for P-256, `SHA384WITHECDSA` for P-384, `SHA512WITHECDSA` for P-521, `SHA256WITHRSA` for RSA |

Credentials come from the standard AWS SDK chain: environment variables, the shared config and credentials files, web identity (IRSA), EKS Pod Identity and ECS container credentials, and instance metadata. omega has no flag for an access key, so a secret never appears in argv or in Helm values. The Helm chart exposes the same settings under `server.ca.awsPCA`; see the [chart README](../charts/omega/README.md#aws-private-ca). [`examples/ca-aws-pca`](../examples/ca-aws-pca/README.md) runs the whole flow against a mock, with no AWS account.

The IAM principal omega runs as needs three actions on the CA:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "acm-pca:IssueCertificate",
        "acm-pca:GetCertificate",
        "acm-pca:GetCertificateAuthorityCertificate"
      ],
      "Resource": "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/EXAMPLE"
    }
  ]
}
```

To keep omega from issuing anything but SVIDs, add a condition `"StringEquals": {"acm-pca:TemplateArn": "arn:aws:acm-pca:::template/EndEntityCertificate_APIPassthrough/V1"}` to the `IssueCertificate` statement.

## How an SVID is issued

omega calls `IssueCertificate` with the workload's CSR, the configured template, a 30-minute absolute validity, and an `ApiPassthrough` structure that carries the SPIFFE ID as the only URI SAN, the subject, and the SVID key usage (`digitalSignature`, `keyEncipherment`) and EKUs (server and client authentication). The subject is a single common name: the SPIFFE ID when it fits AWS's 64-character limit, otherwise the hex SHA-256 of the ID. AWS gives API passthrough values priority over the CSR's, so the subject and names a caller writes into its CSR never reach the leaf; template values take priority over both, so the default template keeps its own key usage while a `BlankEndEntityCertificate_APIPassthrough` override still gets the SVID profile. Each request carries a random idempotency token, so a retry by the SDK returns the same certificate instead of minting a second one.

AWS issues asynchronously: `IssueCertificate` returns a certificate ARN, and `GetCertificate` answers `RequestInProgressException` until the certificate is ready. omega polls with a backoff from 100 ms to 2 s, bounded by a 20-second deadline per issuance, which stays under the API server's 30-second write timeout.

Before returning the SVID, omega checks that the leaf has basic constraints with CA:FALSE, has exactly the subject omega sent (one common name, nothing else), asserts `digitalSignature` but not `keyCertSign` or `cRLSign`, carries both the server and client authentication EKUs when it carries any, is valid now and does not outlive the requested 30 minutes (with five minutes of skew allowed), carries the requested SPIFFE ID as its only SAN (no other URI, DNS, email or IP names), holds the CSR's public key, and is signed by the configured CA. A leaf that fails any check is refused, which catches a template override that changes the leaf's shape or a misdirected CA.

## Trust bundle

`GET /v1/bundle` serves the CA certificate followed by its chain, from `GetCertificateAuthorityCertificate`. For a subordinate CA the bundle therefore holds the issuing CA and the root above it; the SVID itself is the leaf alone. Every certificate in the answer must parse and be a CA, and the chain must link from the issuing CA to the root, or the refresh is rejected. The bundle is fetched at startup, so a wrong ARN, region, endpoint or missing permission stops the server before it serves traffic, and is cached for five minutes afterwards. While one request refreshes the bundle, others are served the cached copy instead of waiting on AWS. If a refresh fails, the previous bundle is served rather than none, so an AWS API outage does not break workloads' mTLS; the failure is logged and the next attempt waits 30 seconds (or the cache lifetime, if shorter). Issuance itself has no such fallback: while AWS is unreachable, new SVIDs fail and workloads keep the SVIDs they hold until those expire.

Publishing the chain up to the root means consumers trust that root, so any other subordinate CA under the same root, in your account or another, can issue certificates they accept, including ones with SPIFFE IDs in your trust domain. Give omega a CA hierarchy of its own, a root used only for this trust domain, rather than a subordinate of an organisation-wide root.

## Operational notes

Every SVID is one `IssueCertificate` call, which AWS bills per certificate and rate-limits per account and region. An SVID is valid from one minute before issuance to 30 minutes after, and the agent renews it at the midpoint of that window, so each workload costs about 99 certificates a day. AWS caps a CA at 100,000,000 certificates over its lifetime, or 1,000,000 with complete CRLs enabled, and neither limit can be raised; at 1,000,000 that is about 10,000 workload-days (100 workloads for about 100 days), so do not enable complete CRLs on this CA; check the [AWS Private CA quotas](https://docs.aws.amazon.com/privateca/latest/userguide/PcaLimits.html) and pricing against your workload count before you switch. A CA in AWS Private CA's short-lived certificate mode (validity of seven days or less) is the lower-priced fit for this pattern.

A renewed CA certificate, or a change in the chain above it, is picked up on the next bundle refresh. With `--upstream-ca-grace`, a certificate AWS stops returning stays in the served bundle for that long, with the same `ca.upstream` audit records and `--upstream-ca-distrust` handling as for Vault PKI and step-ca ([docs/ca-rotation.md](ca-rotation.md)). That kept set lives in memory, so moving to a different CA, which means a new ARN and a restart, gets no overlap: after the restart the bundle holds only the new CA, and SVIDs from the old one stop verifying unless consumers trust the old CA by other means until those SVIDs expire. The `omega ca` rotation commands apply only to the disk backend ([docs/ca-rotation.md](ca-rotation.md)).
