# examples/ca-vault-pki

End-to-end demo of `omega server --ca-backend=vault-pki`: prove
that omega delegates X.509-SVID signing to an upstream Vault PKI
mount instead of self-signing with a local CA.

`make demo` does six things:

1. boots a small `cmd/mock-vault` Go binary that stands up its own
   ECDSA Root CA and serves the two endpoints omega actually
   calls — `GET /v1/<mount>/ca_chain` and
   `POST /v1/<mount>/sign/<role>` — gated by a configurable
   `X-Vault-Token` header;
2. boots `omega server` with the Vault PKI flags pointing at the
   mock (`--ca-backend=vault-pki --ca-vault-pki-addr=...
   --ca-vault-pki-token=... --ca-vault-pki-mount=pki
   --ca-vault-pki-role=omega`);
3. fetches `/v1/bundle` from omega and asserts the bundle subject
   is `CN=Mock Vault Root CA` (not omega's local self-signed CA);
4. registers a SPIFFE namespace and submits a workload CSR via
   `POST /v1/svid`;
5. asserts the issued leaf chains to the bundle (`openssl verify`)
   and carries the requested SPIFFE ID as a URI SAN;
6. asserts the leaf's `Issuer` is the mock Vault CA, so an
   accidental fall-back to the local self-signed default would
   fail the demo.

The mock is intentionally tiny — no `/v1/auth/*`, no
`/v1/sys/mounts`, no policy engine. A real deployment replaces the
mock with a Vault dev or production server by pointing
`--ca-vault-pki-addr` at it. The token surface stays the same
(`--ca-vault-pki-token`, `--ca-vault-pki-token-file`, or the
`OMEGA_VAULT_PKI_TOKEN` environment variable).

## Run

```text
make demo
```

The script tears itself down on exit; force a manual cleanup:

```text
make down
```

## Adapt to a real Vault

Bring up a Vault server (dev mode is fine for trying it out, but
the demo runs against the mock so CI does not depend on the Vault
distribution):

```text
vault server -dev -dev-root-token-id=root
export VAULT_ADDR=http://127.0.0.1:8200
vault secrets enable pki
vault secrets tune -max-lease-ttl=87600h pki
vault write pki/root/generate/internal \
  common_name=omega.local ttl=8760h
vault write pki/roles/omega \
  allowed_domains=omega.local allow_subdomains=true \
  allow_any_name=true allow_ip_sans=false \
  allowed_uri_sans="spiffe://omega.local/*" ttl=1h
```

Then run omega against it:

```text
omega server \
  --trust-domain omega.local \
  --ca-backend vault-pki \
  --ca-vault-pki-addr https://vault.example.com:8200 \
  --ca-vault-pki-token-file /run/secrets/omega-vault-token \
  --ca-vault-pki-ca-cert /etc/ssl/private-cas.pem \
  --ca-vault-pki-mount pki \
  --ca-vault-pki-role omega
```

Production deployments should always prefer
`--ca-vault-pki-token-file` (or the `OMEGA_VAULT_PKI_TOKEN`
environment variable) over the literal `--ca-vault-pki-token`
flag, since process arguments are visible to other users on the
host via `ps`.
