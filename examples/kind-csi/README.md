# Workload API through the SPIFFE CSI driver

The Helm chart with `csi.enabled=true` deploys the upstream [SPIFFE CSI driver](https://github.com/spiffe/spiffe-csi) next to the Omega agent. A pod then mounts the Workload API with a `csi.spiffe.io` ephemeral volume instead of a hostPath, so it needs no hostPath permission and no knowledge of where the agent's socket lives on the node.

```yaml
volumes:
  - name: spiffe-workload-api
    csi:
      driver: csi.spiffe.io
      readOnly: true
```

The socket appears in the pod as `agent.sock` in the mounted directory.

## Run

```bash
make demo
```

It creates a kind cluster, loads a locally built image, installs the chart with `csi.enabled=true` and a uid mapping for uid 10001, runs a pod that mounts `csi.spiffe.io` and runs `omega svid fetch` against the mounted socket, and checks the pod received `spiffe://omega.local/csi/demo`. It needs Docker, kind, kubectl and helm; `make down` removes the cluster (the script also removes it on exit unless `KEEP=1`).

## What to know

The CSI driver runs privileged, for the bidirectional mount propagation it needs, and installs the cluster-wide CSIDriver `csi.spiffe.io`; do not enable it in a cluster that already runs another SPIFFE CSI driver. The Omega agent attests a pod by the UID it connects with, and once the CSIDriver exists any pod in any namespace can mount `csi.spiffe.io`. A pod running as a UID in `agent.uidMap` therefore receives that identity. Map UIDs that only the intended workloads use (not 65532, the default user of most distroless images), and restrict which pods may use `csi.spiffe.io` volumes with admission policy.
