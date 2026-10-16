# Local policy decisions on the node

A control plane (mTLS, `--require-auth`) and a node agent whose local PDP decides from the synced policy bundle. The demo shows that local decisions match the policy, land in the control plane's audit chain, follow a policy stored and deleted through the policy API and a file change after a `SIGHUP`, and stop with a `503` once the node has been cut off for longer than `--policy-max-age`.

See [docs/local-pdp.md](../../docs/local-pdp.md) for how it works and [ADR 0016](../../docs/adr/0016-local-policy-decisions.md) for the design decision.

## Run

```bash
make demo
```

| Step | Expected |
| --- | --- |
| `spiffe://omega.local/media/web` reads | allow (it is in `Domain::"media"`) |
| `spiffe://omega.local/sports/web` reads | deny |
| control plane `GET /v1/audit` | both decisions, as `access.evaluate.local` by `spiffe://omega.local/nodes/n1` |
| `omega policy apply` a forbid on `media/web`, then `omega policy delete` | deny centrally and on the node, then allow again; `policy.create` and `policy.delete` in the audit chain; an invalid policy is refused |
| policy file replaced, server `SIGHUP` | the node denies after its next sync |
| control plane stopped | the node keeps answering, then `503` after `--policy-max-age` |

The script makes a throwaway CA with `openssl` and issues the server certificate, a root admin SVID for its own calls, and the agent's SVID; the server lists `spiffe://omega.local/nodes/` as `--decision-recorder`. The server signs every policy bundle (`--policy-bundle-signing-key`) and the agent accepts only bundles with that signature (`--policy-bundle-key`), and spools each decision to disk before answering (`--decision-spool`), per [ADR 0018](../../docs/adr/0018-signed-bundles-and-decision-spool.md). The agent runs with `--policy-sync-interval 1s --policy-max-age 4s` so the demo is quick. `make down` cleans up.
