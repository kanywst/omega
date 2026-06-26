# Omega Kubernetes Operator (OmegaDomain)

This example walks through using the Omega operator to declaratively
manage Omega domains as Kubernetes custom resources. Apply an
`OmegaDomain` manifest and the reconciler ensures the domain exists on
the configured Omega control plane.

## What gets installed

The operator ships one cluster-scoped CRD:

| Group                     | Kind        | Short name | Scope   |
| ------------------------- | ----------- | ---------- | ------- |
| `omega.kanywst.github.io` | OmegaDomain | `odom`     | Cluster |

A reconcile loop watches `OmegaDomain` resources and translates them
into HTTP calls against the Omega control plane:

```text
kubectl apply -f sample-domain.yaml
        |
        v
+----------------------+      GET  /v1/domains/{name}      +----------------+
| omega operator       | --------------------------------> | omega server   |
| (controller-runtime) | <-------- 404 / 200 -------------- | (control plane)|
|                      |                                   |                |
|                      | --------- POST /v1/domains -----> |                |
|                      |                                   |                |
+----------------------+                                   +----------------+
        |
        v
status.conditions[Ready] = True
```

CR deletion does **not** delete the domain on the control plane.
Domain destruction is an explicit operator action via
`omega domain delete`, not something a `kubectl delete` should do
silently.

## End-to-end on kind

The flow below runs the operator out-of-cluster (point at any kubeconfig)
and the Omega control plane on the host. This is the fastest dev loop;
in-cluster Helm packaging follows the same wiring.

```bash
# 1. Bring up a kind cluster.
kind create cluster --name omega-operator

# 2. Install the CRD.
kubectl apply -f ../../charts/omega/crds/omegadomain.yaml

# 3. In one terminal, run the Omega control plane on the host.
omega server --http-addr 127.0.0.1:8080 --data-dir /tmp/omega-operator-demo

# 4. In another terminal, run the operator pointing at it.
omega operator \
  --omega-url=http://127.0.0.1:8080 \
  --metrics-addr=:8081 \
  --health-addr=:8082

# 5. Apply the sample CRs.
kubectl apply -f sample-domain.yaml
```

## Verify

```bash
# Both domains show Ready=True after a successful reconcile.
kubectl get omegadomain
# NAME         DOMAIN       READY   REASON   AGE
# media-news   media.news   True    Ready    3s
# payments     payments     True    Ready    3s

# The control plane confirms the rows.
curl -sS http://127.0.0.1:8080/v1/domains | jq
```

Detail of one resource:

```bash
kubectl describe omegadomain media-news
# ...
# Status:
#   Conditions:
#     Last Transition Time:  2026-04-30T...
#     Message:               domain present on control plane
#     Reason:                Ready
#     Status:                True
#     Type:                  Ready
#   Observed Generation:     1
```

## Going to production

The example uses a single-replica out-of-cluster operator. Production
deployments pick up three additional knobs:

- `--leader-elect` enables controller-runtime leader election (Lease
  object) so a Deployment with `replicas: 2+` runs exactly one active
  reconciler.
- The operator pod needs a ServiceAccount with `get / list / watch /
  update` on `omegadomains` and `omegadomains/status`. A Helm template
  is planned; until then, copy the RBAC stub in
  [`rbac.yaml`](rbac.yaml).
- `--omega-url` should point at the in-cluster Service, e.g.
  `http://omega-server.omega-system.svc:8080`.

## Known limitations

- Only `OmegaDomain` is implemented. SVID issuance via CRD
  (`OmegaIdentity`) is a planned follow-up.
- The reconciler talks plain HTTP. mTLS to the control plane is a
  planned follow-up (the operator will mount a workload SVID and
  verify the server cert against the trust bundle).
- `kubectl delete omegadomain` removes the CR but intentionally does
  not delete the domain on the control plane.
