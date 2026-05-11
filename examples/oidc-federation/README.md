# examples/oidc-federation

End-to-end demo of [`POST /v1/oidc/exchange`](../../api/openapi.yaml):
swap an external OIDC IdP's ID token for an omega JWT-SVID under a
Human principal's SPIFFE ID.

`make demo` does five things:

1. boots a tiny in-process OIDC IdP (`./mock-idp`) that generates an
   ECDSA P-256 key pair and serves the minimal OIDC surface omega
   actually consumes (`/.well-known/openid-configuration` +
   `/jwks.json`). A demo-only `/sign` endpoint lets the script ask
   for a freshly signed ID token with arbitrary claims;
2. boots `omega server` with the mock IdP wired in via
   `--oidc-idp 'name=demo-idp,issuer=http://127.0.0.1:18181,audience=omega-clients,template=spiffe://omega.demo/humans/{idp}/{preferred_username}'`;
3. asks the mock IdP to sign an ID token for
   `sub=alice@example.com, preferred_username=alice, aud=omega-clients`;
4. POSTs that token to `/v1/oidc/exchange` and decodes the omega
   JWT-SVID that comes back;
5. asserts the rendered SPIFFE ID is
   `spiffe://omega.demo/humans/demo-idp/alice` and that the issued
   token's RFC 8693 `act` claim records the upstream IdP as
   `{idp: demo-idp, iss: http://..., kind: oidc-idp, sub: alice@example.com}`.

The mock IdP is intentionally tiny - no `/authorize`, no `/token`,
no consent screen. omega never calls any of those. A real
deployment swaps the mock for Keycloak / Okta / Entra ID / Google
Workspace / Dex / Authentik / etc. by pointing `--oidc-idp` at
their issuer URL.

## Run

```text
make demo
```

The script tears itself down on exit. To force a manual cleanup:

```text
make down
```

## Adapt to a real IdP

For an external IdP, drop the mock and point `omega server` at the
issuer directly. For Keycloak:

```text
omega server \
  --trust-domain omega.example.com \
  --oidc-idp 'name=corp,issuer=https://keycloak.example/realms/staff,audience=omega-clients,template=spiffe://omega.example.com/humans/{idp}/{preferred_username}'
```

A workload logs into Keycloak, receives an ID token, and posts:

```text
POST /v1/oidc/exchange
{
  "idp":      "corp",
  "id_token": "<JWS from Keycloak>",
  "audience": ["target-api"]
}
```

omega validates the token against Keycloak's JWKS, renders the
SPIFFE ID, and issues an omega JWT-SVID the workload can present
to any downstream relying party that accepts the omega trust domain.
