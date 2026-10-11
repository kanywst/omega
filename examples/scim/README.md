# SCIM provisioning

An identity provider, played by `curl`, pushes users and a group to Omega over SCIM 2.0, and the Cedar decision follows each change. See [docs/scim.md](../../docs/scim.md) and [ADR 0017](../../docs/adr/0017-scim-provisioning.md).

## Run

```bash
make demo
```

| Step | Expected |
| --- | --- |
| alice and bob are created, `Engineering` is created with alice | `people:engineering` exists; alice may deploy, bob may not |
| bob is added to `Engineering` | bob may deploy |
| alice is deactivated | alice may not deploy |
| the Omega API tries to add a member to `people:engineering` | `409` |
| control plane `GET /v1/audit` | `scim.*` rows with `scim:corp` as actor |

The policy is [`policies/deploy.cedar`](policies/deploy.cedar). `make down` cleans up.
