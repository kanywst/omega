# ADR 0021: Azure Key Vault as a remote signer, not a hosted CA

## Status

Accepted.

## Context

[ADR 0005](0005-ca-plugin-architecture.md) makes `identity.Authority` the seam for CA backends and lists Azure Key Vault among them. The two non-disk backends shipped so far, Vault PKI and step-ca, are hosted CAs: Omega sends a CSR and gets a certificate back, and JWT-SVIDs stay signed by a local key, because neither upstream signs arbitrary JWTs.

Azure has no hosted private CA comparable to AWS Private CA or Google CAS. What it has is Key Vault (and Managed HSM): a key store whose `sign` operation signs a digest with a key that cannot be exported. The Key Vault certificates feature can create a self-signed certificate or a CSR for a key it holds, but it does not sign other parties' certificates, so it cannot issue SVIDs.

Three questions follow: who builds and signs the certificates, where the CA certificate comes from, and how Omega authenticates to Azure.

## Decision

1. **Remote signer.** Omega builds every X.509-SVID and JWT-SVID itself, exactly as the disk CA does, and signs it through a `crypto.Signer` whose `Sign` sends the SHA-256 digest to `keys/{name}/{version}/sign` (ES256). The disk authority's issuance code is reused unchanged with this signer in place of the private key; JWT-SVIDs reach the same signer through go-jose's `OpaqueSigner`. Both kinds of SVID are therefore signed by the Key Vault key, unlike the hosted-CA backends, and the JWKS `kid` is derived from the public key the same way as for the disk CA. Each returned signature is verified against the public key fetched at startup before use.
2. **One pinned key version, EC P-256 only.** The key version is resolved once at startup (or named by a flag) and pinned for the process, so a new version created in the vault never changes the signing key underneath a running server. Only EC P-256 is supported, since the JWKS, `kid` derivation and JWT validation are ES256 throughout; RSA would add a second signature path for no current user.
3. **CA certificate: self-signed through Key Vault, or supplied.** Without a certificate file, Omega self-signs a CA certificate through the same signer at first start and keeps it next to the disk CA's files, reusing it later and refusing to start if it no longer matches the key. A supplied PEM file instead names the CA certificate (the one matching the key) plus any other certificates to trust; that is how replicas share one CA and how a rotation keeps the previous and next CA trusted across restarts. Only self-signed roots are accepted: serving a chain would change what every backend's `BundlePEM` means.
4. **No runtime rotation.** The backend does not implement `CAReloader`; rotation is a sequence of restarts driven by the pinned version and the certificate file, as [docs/ca-azure-keyvault.md](../ca-azure-keyvault.md) describes. The disk CA's `prepare|activate|retire` steps ([ADR 0019](0019-runtime-ca-rotation.md)) do not apply.
5. **REST and a minimal token source, not the Azure SDK.** Omega calls the two Key Vault operations it needs (get key, sign) over REST and obtains tokens itself from three sources: a client secret, workload identity federation, and a managed identity through the instance metadata service, in `DefaultAzureCredential` order. The SDK (`azidentity` with `azcore` and MSAL) would bring a sizeable dependency tree into a security-critical control plane for three HTTP requests, where the other upstream backends already call REST directly.

## Consequences

Easier:

- The CA key, for both X.509 and JWT, is non-exportable and lives in a FIPS 140 validated module when the key is HSM-backed. Reading `--data-dir` no longer yields the trust domain.
- No second CA product to run: an Azure deployment needs one key and one role assignment.
- The issuance code is shared with the disk CA, so X.509 profile and JWT claims stay identical across the two.

Harder:

- One Key Vault round trip per issued SVID, X.509 or JWT. Issuance latency and throughput are bound by the vault's latency and throttling limits; Omega surfaces a `429` as an issuance error and does not retry.
- Key Vault being unreachable stops issuance; already issued SVIDs and validation are unaffected.
- Credential sources are narrower than the SDK's: no Azure CLI, App Service or Azure Arc credentials. Adding one is a small change in `azure_token.go`, or a reason to revisit the SDK.
- Rotation needs restarts and operator-minted certificates instead of the disk CA's runtime steps.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md): *"Is it an upstream system Omega depends on but does not own?"*

Yes. Key Vault holds the key; Omega owns the issuance policy, as it does for the disk CA.
