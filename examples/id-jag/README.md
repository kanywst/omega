# ID-JAG: enterprise IdP grant → delegated JWT-SVID → MCP tool

An AI agent holds a user's SSO session at an enterprise IdP. It asks the IdP for an [ID-JAG](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/) (Identity Assertion JWT Authorization Grant) addressed to Omega, presents it at Omega's token endpoint authenticated by its own JWT-SVID, and calls an MCP tool with the delegated token it gets back. The tool sees the user at the root of the delegation chain.

See [docs/id-jag.md](../../docs/id-jag.md) for the explained walkthrough and [ADR 0011](../../docs/adr/0011-id-jag-authorization-grant.md) for the design decision.

## Run

```bash
make demo
```

It builds and starts three processes, then runs the agent:

| Process | Role |
| --- | --- |
| `idp/` | Stand-in enterprise IdP. Signs an ID token for the user and exchanges it (RFC 8693) for an ID-JAG whose `aud` is Omega's issuer and whose `client_id` is the agent's SPIFFE ID. |
| `omega server --id-jag-idp ...` | Trusts that IdP for ID-JAGs, gates the grant with `policies/id-jag.cedar`, and audits it. Runs with `--id-jag-insecure-client-binding` because the demo has no mTLS. |
| `../mcp-a2a-delegation/tool-server` | MCP tool that verifies the JWT-SVID against Omega's JWKS and echoes the delegation chain. |

## Walkthrough

[docs/id-jag.md](../../docs/id-jag.md) explains the flow with diagrams, shows the tokens at each step, and lists what each demo step asserts. The demo also checks that the raw ID token is refused as a grant (wrong `typ`) and that a different agent cannot redeem the ID-JAG (`client_id` mismatch).

## Against a real IdP

Point `--id-jag-idp` at an IdP that issues ID-JAGs for Omega's `--issuer-url`, and register the agent there with Omega as the target and its SPIFFE ID as the client identifier the IdP puts in `client_id`. In production run Omega with `--require-auth` and `--client-ca`, and have the agent authenticate with the X.509-SVID it gets from the SPIFFE Workload API. The demo uses the open `POST /v1/svid/jwt` with `--id-jag-insecure-client-binding` instead, which is why Omega logs a development-only warning.
