# CA key in Azure Key Vault

`--ca-backend=azure-keyvault` keeps the private key of Omega's CA in Azure Key Vault or Azure Managed HSM. Omega still builds every certificate and token itself, but signs them by sending their SHA-256 digest to Key Vault's `sign` operation, so the key never leaves Key Vault and never touches the server's disk or memory. Both X.509-SVIDs and JWT-SVIDs are signed by it. [ADR 0021](adr/0021-azure-key-vault-remote-signer.md) explains why this backend is a remote signer rather than a hosted CA.

## Set up the key

Create an EC P-256 key permitted to sign. A software key and an HSM-backed key (`--kty EC-HSM`, or any key in a Managed HSM) both work:

```bash
az keyvault key create --vault-name myvault --name omega-ca --kty EC --curve P-256 --ops sign verify
```

Grant the server's identity the `get` and `sign` key permissions: the `Key Vault Crypto User` role on a vault using Azure RBAC, a `get,sign` access policy on one using access policies, or the `Managed HSM Crypto User` local role on a Managed HSM. Omega needs nothing else: it never creates, imports or exports keys.

## Credentials

Omega reads its Microsoft Entra ID credential from the environment, trying the same sources in the same order as the Azure SDK's `DefaultAzureCredential`, minus the developer-tool ones:

| Source | Environment |
| --- | --- |
| Service principal with a secret | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` |
| Workload identity federation (AKS) | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, set by the workload identity webhook |
| Managed identity | none; `AZURE_CLIENT_ID` selects a user-assigned identity |

`AZURE_AUTHORITY_HOST` points at a sovereign cloud's login endpoint. The OAuth scope follows the vault's host, so `*.vault.azure.net`, `*.managedhsm.azure.net`, `*.vault.usgovcloudapi.net` and `*.vault.azure.cn` all work without further configuration. Tokens are cached until five minutes before they expire, are sent only over https, and never appear in logs or errors.

## Run the server

```bash
omega server \
  --ca-backend=azure-keyvault \
  --ca-azure-keyvault-url=https://myvault.vault.azure.net \
  --ca-azure-keyvault-key=omega-ca
```

At startup Omega fetches the key, checks that it is an enabled EC P-256 key permitted to sign, and pins the version it found (or the one `--ca-azure-keyvault-key-version` names) for the life of the process. A missing permission, a wrong key or an unreachable vault stops the server here rather than at the first issuance.

## The CA certificate

Key Vault holds a key, not a certificate, so Omega needs a CA certificate for that key. There are two ways to get one.

Without `--ca-azure-keyvault-ca-cert`, Omega self-signs a CA certificate through Key Vault on first start (ten years, `Omega Key Vault CA`) and keeps it in `<data-dir>/ca/azure-keyvault-ca.crt`. Later starts reuse it. If the key has changed since (a new current version), the server refuses to start instead of silently minting a new root that no workload trusts: pin the old version, or move the file aside to mint a new CA on purpose. The kept file must hold only that one certificate; extra CAs to trust go in a supplied file.

With `--ca-azure-keyvault-ca-cert=FILE`, Omega uses the certificate in `FILE` whose public key is the Key Vault key. It must be a CA certificate (basic constraints `CA:TRUE`, `keyCertSign`) valid now, and it must be a self-signed root: Omega serves it as the trust bundle and does not send a chain. Every other certificate in the file is trusted as well, in the X.509 bundle and in the JWKS, but does not sign; each must also be an unexpired, self-signed EC P-256 CA certificate. Use this form when running more than one replica (copy the certificate the first replica minted into the file, so all replicas serve the same CA) and during a key rotation.

## Latency and limits

Each X.509-SVID and each JWT-SVID costs one Key Vault round trip: the network latency to the vault plus its signing time, which is lowest from inside the vault's region and higher for an HSM-backed key. Validation of JWT-SVIDs is local and costs nothing extra, since it needs only the public key. Key Vault throttles cryptographic operations per vault (see the Azure Key Vault service limits); when it does, the issuance fails with the `429` status and the caller has to retry. Omega does not retry a sign itself, and each sign has a ten-second timeout. Size the vault for the issuance rate: roughly one X.509-SVID per workload every SVID lifetime, plus one sign per JWT-SVID requested.

Every signature Key Vault returns is verified against the public key fetched at startup before Omega uses it, so a response signed by any other key is refused.

## Rotating the key

This backend does not rotate at runtime: `omega ca prepare|activate|retire` and `SIGHUP` apply to the disk CA only. A rotation is a sequence of restarts with overlapping trust, driven by the CA certificate file:

1. Create a new key version, mint a CA certificate for it, and add that certificate to the file after the current one. Restart. The new CA is trusted but the old version still signs, as long as the old version is pinned with `--ca-azure-keyvault-key-version`.
2. Once peers and workloads have fetched the new bundle, pin the new version and restart. The new key signs; the old certificate stays in the file and stays trusted.
3. After 24 hours (the longest JWT-SVID lifetime), remove the old certificate and restart.

Minting the certificate for a new version is the operator's job in this flow; the simplest way is to start one server with an empty data directory and the new version pinned, and copy the certificate it writes.

## Limitations

Only EC P-256 keys (ES256) are supported; RSA keys are refused at startup. Developer credentials (Azure CLI, Azure Developer CLI, Visual Studio Code) and the App Service and Azure Arc managed identity endpoints are not supported, since the backend implements only the three sources above. A certificate chain (a CA certificate issued by an enterprise root rather than self-signed) is not supported.
