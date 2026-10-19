# Omega UI

Admin dashboard for the Omega control plane. Read-only, except that a
signed-in `--domain-root-admin` can manage stored Cedar policies.
Next.js 15 (App Router) + Tailwind CSS v4 + shadcn-style primitives,
hand-tuned to the Linear/Vercel design language. Lives in its own tree
on purpose - Omega's "one binary" promise applies to `server` / `agent` /
CLI, not the UI.

## Run locally

```bash
# 1. start the control plane (in the repo root)
make run-server

# 2. in another shell, the UI
cd ui
pnpm install
pnpm dev
# -> http://localhost:3000
```

The UI talks to the control plane through its server-side proxy at
`/api/omega/*` → `OMEGA_API` (default `http://127.0.0.1:8080`). Set
`OMEGA_API` in `ui/.env.local` to point elsewhere. The proxy forwards
only the calls the pages make and answers `404` for any other path.

## Stack

| Layer       | Choice                              |
| ----------- | ----------------------------------- |
| Framework   | Next.js 15 (App Router, Turbopack)  |
| Styling     | Tailwind CSS v4 + CSS-first config  |
| Primitives  | Radix UI + cmdk + lucide-react      |
| Data        | @tanstack/react-query               |
| Validation  | zod                                 |
| Type system | TypeScript strict                   |
| Lint/format | Biome                               |
| Fonts       | Geist Sans + Geist Mono (OFL)       |

## Pages

| Route       | Surface                                              |
| ----------- | ---------------------------------------------------- |
| `/`         | Overview: counts, audit head, demo `curl`            |
| `/domains`  | SPIFFE namespace list                                |
| `/svid`     | Recent X.509 / JWT SVIDs (audit-derived)             |
| `/policy`   | AuthZEN evaluations (audit-derived)                  |
| `/policies` | Cedar policies: list, text, validate; with sign-in, create, edit, delete |
| `/audit`    | Full chain + verify badge                            |
| `/bundle`   | Download X.509 / JWKS bundles                        |

## Keyboard

- `⌘K` / `Ctrl+K` - command palette
- `g h` `g d` `g s` `g p` `g c` `g a` `g b` - jump to page

## Design rules

The UI is built against a 10-rule AI-slop avoidance list. Short
version:

- One accent color, no gradients, no `rounded-2xl shadow-md` cards.
- Geist Sans + Geist Mono. Inter is forbidden.
- Mono for SPIFFE IDs / hashes / kids - never truncated.
- Empty states show the next CLI command, not a button.
- No emoji. No "Welcome back!" copy.

## Status

Read-only, except the Policies pages for a signed-in person. Mutation flows for domains and SVIDs are a planned follow-up.

## Sign-in and policy writes

Without sign-in configured the UI never writes: the `/api/omega/*` proxy calls the control plane as the UI itself, and the Policies pages say how to enable writes. With it, a person signs in through the OIDC IdP the control plane federates with, and the UI acts for them on the policy API ([ADR 0023](../docs/adr/0023-ui-proxy-acts-for-signed-in-people.md)):

1. `/api/auth/login` starts the authorization code flow with PKCE, and `/api/auth/callback` redeems the code, checks the ID token's nonce and exchanges the ID token at `POST /v1/oidc/exchange` for the person's JWT-SVID.
2. The session lives in the UI server's memory. The browser holds only a random id in the `__Host-omega-session` cookie (`httpOnly`, `Secure`, `SameSite=Lax`); no token reaches it.
3. On `/v1/policies` the proxy presents the person's JWT-SVID in the `Omega-User-Token` header, next to the UI's own X.509-SVID. The control plane authorizes and audits the request as the person, with the UI as `via`. Every other route is called as the UI itself.
4. A state-changing request must come from `OMEGA_UI_URL`'s origin and, from a signed-in browser, carry the session's CSRF token, which the page reads from `/api/auth/session`.
5. A minute before the person's JWT-SVID expires, the UI renews it through the IdP's refresh token. The session ends at sign-out, when renewal fails, or after `OMEGA_UI_SESSION_MAX_AGE`.

Sessions are in memory, so run one UI replica (or sticky sessions), and a restart signs everyone out.

| Variable | Required | Meaning |
| --- | --- | --- |
| `OMEGA_API` | no | Control plane URL (default `http://127.0.0.1:8080`); `https://` with sign-in |
| `OMEGA_API_CA` | no | PEM CA bundle that verifies the control plane's certificate |
| `OMEGA_API_CLIENT_CERT` | with sign-in | The UI's X.509-SVID (PEM), listed on the server with `--ui-proxy`; re-read when it changes |
| `OMEGA_API_CLIENT_KEY` | with sign-in | Its private key (PEM) |
| `OMEGA_UI_OIDC_ISSUER` | turns sign-in on | The IdP's issuer URL (discovery at `/.well-known/openid-configuration`); `https://` outside `localhost` |
| `OMEGA_UI_OIDC_CLIENT_ID` | with sign-in | The UI's OIDC client id; also an audience of the server's `--oidc-idp` |
| `OMEGA_UI_OIDC_CLIENT_SECRET` | no | Client secret, sent with `client_secret_basic`; omit for a public client |
| `OMEGA_UI_OIDC_IDP` | with sign-in | The `name` of the server's `--oidc-idp` for this IdP |
| `OMEGA_UI_OIDC_SCOPES` | no | Default `openid profile email`; add `offline_access` if the IdP needs it for a refresh token |
| `OMEGA_UI_URL` | with sign-in | The UI's public origin; the redirect URI is `<OMEGA_UI_URL>/api/auth/callback`. `https://` outside `localhost` |
| `OMEGA_UI_TOKEN_AUDIENCE` | no | Default `omega-ui`; must equal the server's `--ui-proxy-audience` |
| `OMEGA_UI_TOKEN_TTL` | no | Seconds the person's JWT-SVID is requested for (default 900); the server caps it at the ID token's remaining life |
| `OMEGA_UI_SESSION_MAX_AGE` | no | Seconds a session lasts at most, renewals included (default 28800) |

When `OMEGA_UI_OIDC_ISSUER` is set but another required variable is not, the UI refuses to sign anyone in and stays read-only. Register `<OMEGA_UI_URL>/api/auth/callback` as the client's redirect URI at the IdP. The server needs `--require-auth`, the `--oidc-idp`, the person as a `--domain-root-admin` and the UI as a `--ui-proxy`; see [docs/policies.md](../docs/policies.md#from-the-web-ui). `examples/ui-auth` runs the whole flow against a mock IdP.
