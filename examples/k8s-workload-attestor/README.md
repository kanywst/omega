# examples/k8s-workload-attestor

End-to-end demo of `omega agent --k8s-workload-attestor`: a process in a pod gets the SPIFFE ID of its pod, while a host process with the same UID gets the `--map` UID mapping. The pod runs an unmodified SPIFFE Workload API client (`omega svid fetch`) and presents nothing but its connection.

`make demo` does the following:

1. boots a one-node `kind` cluster (default name `omega-k8s-wl`);
2. builds a static Linux `omega` for the node's architecture and copies it into the node container;
3. renders the chart's ServiceAccount and pod-reader ClusterRole (`agent.k8sWorkloadAttestor.enabled=true`), applies them, and gives the agent a kubeconfig with that service account's token, so the agent has exactly the chart's RBAC;
4. starts `omega server` and `omega agent --map uid=0,id=spiffe://omega.local/host/root --k8s-workload-attestor` inside the node container, which shares its PID namespace with the pods as a DaemonSet with `hostPID` would;
5. fetches an SVID from a host process running as root and asserts it is `spiffe://omega.local/host/root`;
6. runs a pod in namespace `wl-demo` with service account `web`, also as root, that fetches an SVID over a hostPath socket, and asserts it is `spiffe://omega.local/k8s/wl-demo/web`, not the uid 0 mapping;
7. checks the agent logged the pod's selectors (`k8s:ns:wl-demo`, `k8s:sa:web`, ...).

The control plane runs without `--require-auth`, which is what the agent-side attestor needs: the agent requests SVIDs for the identities it attests. This is the self-issued development and evaluation path; see [ADR 0020](../../docs/adr/0020-agent-side-kubernetes-workload-attestor.md) for what the attestor does not do compared with SPIRE's.

## Run

```text
make demo
```

The script deletes the kind cluster on exit. `KEEP_CLUSTER=1 make demo` keeps it for repeated runs, and `make down` removes it.

## Requirements

`kind`, `kubectl`, `helm`, `docker`, `go` (the demo builds its own Linux binary) and `python3`.
