# Local policy decisions on the node

A control plane and a node agent whose local PDP decides from the synced policy bundle. The demo shows that local decisions match the policy, land in the control plane's audit chain, follow a policy change after a `SIGHUP`, and stop with a `503` once the node has been cut off for longer than `--policy-max-age`.

See [docs/local-pdp.md](../../docs/local-pdp.md) for how it works and [ADR 0016](../../docs/adr/0016-local-policy-decisions.md) for the design decision.

## Run

```bash
make demo
```

| Step | Expected |
| --- | --- |
| `spiffe://omega.local/media/web` reads | allow (it is in `Domain::"media"`) |
| `spiffe://omega.local/sports/web` reads | deny |
| control plane `GET /v1/audit` | both decisions, `source: local` |
| policy file replaced, server `SIGHUP` | the node denies after its next sync |
| control plane stopped | the node keeps answering, then `503` after `--policy-max-age` |

The agent runs with `--policy-sync-interval 1s --policy-max-age 4s` so the demo is quick. `make down` cleans up.
