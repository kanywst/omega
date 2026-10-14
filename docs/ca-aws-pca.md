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
| `--ca-aws-pca-endpoint` | SDK default | Endpoint override, for example a VPC interface endpoint |
| `--ca-aws-pca-template-arn` | `EndEntityCertificate_APIPassthrough/V1` | Certificate template; must be an API-passthrough end-entity template |
| `--ca-aws-pca-signing-algorithm` | inferred from the CA key | `SHA256WITHECDSA` for P-256, `SHA384WITHECDSA` for P-384, `SHA512WITHECDSA` for P-521, `SHA256WITHRSA` for RSA |

Credentials come from the standard AWS SDK chain: environment variables, the shared config and credentials files, web identity (IRSA), EKS Pod Identity and ECS container credentials, and instance metadata. omega has no flag for an access key, so a secret never appears in argv or in Helm values. The Helm chart exposes the same settings under `server.ca.awsPCA`; see the [chart README](../charts/omega/README.md#aws-private-ca).

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

omega calls `IssueCertificate` with the workload's CSR, the configured template, a 30-minute absolute validity, and an `ApiPassthrough` structure that carries the SPIFFE ID as the only URI SAN (and as the subject common name when it fits AWS's 64-character limit). The SAN is passed through the API rather than read from the CSR because the CSRs omega's agents send carry no SANs, and because an API-supplied SAN takes precedence over whatever a CSR carries, so a workload cannot add names of its own. Each request carries a random idempotency token, so a retry by the SDK returns the same certificate instead of minting a second one.

AWS issues asynchronously: `IssueCertificate` returns a certificate ARN, and `GetCertificate` answers `RequestInProgressException` until the certificate is ready. omega polls with a backoff from 100 ms to 2 s, bounded by a 30-second deadline per issuance.

Before returning the SVID, omega checks that the leaf is not a CA certificate, asserts `digitalSignature` but not `keyCertSign` or `cRLSign`, carries both the server and client authentication EKUs when it carries any, is valid now and does not outlive the requested 30 minutes (with five minutes of skew allowed), carries exactly the requested SPIFFE ID as its URI SAN, holds the CSR's public key, and is signed by the configured CA. A leaf that fails any check is refused, which catches a template override that changes the leaf's shape or a misdirected CA.

## Trust bundle

`GET /v1/bundle` serves the CA certificate followed by its chain, from `GetCertificateAuthorityCertificate`. For a subordinate CA the bundle therefore holds the issuing CA and the root above it; the SVID itself is the leaf alone. The bundle is fetched at startup, so a wrong ARN, region, endpoint or missing permission stops the server before it serves traffic, and is cached for five minutes afterwards. If a refresh fails, the previous bundle is served rather than none, so an AWS API outage does not break workloads' mTLS; the failure is logged and the next attempt waits 30 seconds (or the cache lifetime, if shorter). Issuance itself has no such fallback: while AWS is unreachable, new SVIDs fail and workloads keep the SVIDs they hold until those expire.

## Operational notes

Every SVID is one `IssueCertificate` call, which AWS bills per certificate and rate-limits per account and region. With 30-minute SVIDs renewed at half-life, each workload costs roughly 48 certificates a day; check the [AWS Private CA quotas](https://docs.aws.amazon.com/privateca/latest/userguide/PcaLimits.html) and pricing against your workload count before you switch. A CA in AWS Private CA's short-lived certificate mode (validity of seven days or less) is the lower-priced fit for this pattern.

A renewed CA certificate (same CA, same key) is picked up on the next bundle refresh. Moving to a different CA means a new ARN and a restart, after which the bundle holds only the new CA, so SVIDs from the old one stop verifying at once; there is no overlap window like the disk backend's rotation. The `omega ca` rotation commands apply only to the disk backend ([docs/ca-rotation.md](ca-rotation.md)).
