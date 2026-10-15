# examples/ca-aws-pca

End-to-end demo of `omega server --ca-backend=aws-pca`: omega delegates X.509-SVID signing to an AWS Private CA instead of self-signing with a local CA. The demo runs against a small mock, so it needs no AWS account.

`make demo` boots `mock-pca`, a Go binary that holds a root CA and an issuing CA under it and answers the three ACM PCA operations omega calls (`GetCertificateAuthorityCertificate`, `IssueCertificate`, `GetCertificate`) over the same awsJson1_1 protocol the AWS SDK speaks. Its first `GetCertificate` answer for each certificate is `RequestInProgressException`, as AWS's often is. It then starts `omega server` with `--ca-backend=aws-pca --ca-aws-pca-endpoint=http://127.0.0.1:...` and static demo credentials in the environment, and checks four things:

| Check | Proves |
| --- | --- |
| `/v1/bundle` holds the issuing CA followed by its root | the bundle comes from `GetCertificateAuthorityCertificate` |
| the issued leaf verifies against that bundle | the SVID was signed by the private CA |
| the leaf carries the requested SPIFFE ID as a URI SAN | the ID went through `ApiPassthrough` (the CSR carries none) |
| the mock saw at least two `GetCertificate` calls | omega polled past the in-progress answer |

The mock does not verify SigV4 signatures; it only requires a SigV4 `Authorization` header. Plain http to the mock is allowed because it is on loopback; omega refuses http to any other host.

## Run

```bash
make demo
```

The script tears itself down on exit; force a manual cleanup:

```bash
make down
```

## Adapt to a real AWS Private CA

Drop `--ca-aws-pca-endpoint` and let omega pick up credentials from its environment (an instance profile, IRSA, EKS Pod Identity, or a profile):

```bash
omega server \
  --trust-domain omega.local \
  --ca-backend aws-pca \
  --ca-aws-pca-arn arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/EXAMPLE
```

The IAM policy omega needs, the template it uses, and the cost and rotation notes are in [docs/ca-aws-pca.md](../../docs/ca-aws-pca.md).
