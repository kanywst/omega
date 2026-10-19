# examples/ui-auth

A person signs in to the web UI and manages Cedar policies as themselves. The UI server acts for them on the policy API with their JWT-SVID, and the audit chain names them as actor and the UI as `via` ([ADR 0023](../../docs/adr/0023-ui-proxy-acts-for-signed-in-people.md)).

`make demo`:

1. issues a demo CA, the control plane's TLS certificate and the UI's X.509-SVID, `spiffe://omega.demo/platform/ui`;
2. starts the mock OIDC IdP from [`examples/oidc-federation`](../oidc-federation/), whose `/authorize` signs in `alice` at once (no login page) and whose ID tokens live 65 seconds;
3. starts `omega server` with TLS, `--require-auth`, `--oidc-idp` for the mock IdP, `--ui-proxy spiffe://omega.demo/platform/ui`, and alice's human SPIFFE ID `spiffe://omega.demo/humans/demo-idp/alice` as the only `--domain-root-admin`;
4. builds the UI (`npm ci` when `ui/node_modules` is missing, then `npm run build`) and starts it with sign-in configured;
5. runs `drive.py`, which plays the browser and checks:
   - before sign-in, the UI's own SVID cannot write policy, and a cross-origin write is refused;
   - sign-in uses PKCE S256, a nonce and a state, a callback without the browser's login cookie does not sign in, and the redirect after sign-in stays on the UI's origin;
   - the session answer names alice and carries no token;
   - a write without the CSRF token is refused; alice creates, reads, updates and deletes a policy, and an update with a stale ETag answers `412`;
   - the UI renews alice's JWT-SVID through the IdP's refresh token before it expires;
   - the audit chain records each change with alice as actor and the UI as `via`, and the UI's own refused write with the UI as actor;
   - after sign-out the session cookie no longer writes.

Needs Go, Node.js 20 or later, `openssl` and `python3`.

## Run

```text
make demo
```

The script stops every process on exit. `make down` removes what is left in `/tmp/omega-ui-auth-demo`.

## Run the UI against a real IdP

Register the UI as an OIDC client with the redirect URI `https://ui.example.com/api/auth/callback`, issue it an X.509-SVID, and start both sides:

```text
omega server --tls-cert server.pem --tls-key server.key --client-ca ca.pem --require-auth \
  --oidc-idp 'name=corp,issuer=https://idp.example.com,audience=<client-id>,template=spiffe://omega.example.com/humans/{idp}/{preferred_username}' \
  --domain-root-admin spiffe://omega.example.com/humans/corp/alice \
  --ui-proxy spiffe://omega.example.com/platform/ui

OMEGA_API=https://omega.example.com:8080 OMEGA_API_CA=ca.pem \
OMEGA_API_CLIENT_CERT=ui.pem OMEGA_API_CLIENT_KEY=ui.key \
OMEGA_UI_URL=https://ui.example.com \
OMEGA_UI_OIDC_ISSUER=https://idp.example.com OMEGA_UI_OIDC_CLIENT_ID=<client-id> OMEGA_UI_OIDC_IDP=corp \
node .next/standalone/server.js
```

[ui/README.md](../../ui/README.md) lists every setting.
