# ADR 0020: An agent-side Kubernetes workload attestor for the self-issued path

## Status

Accepted.

## Context

The node agent identified a workload only by the UID it connects with (`SO_PEERCRED`) and a static `--map uid=...,id=...` table. On a Kubernetes node that is a poor fit: containers commonly share UIDs (many run as root or as the same non-root user), so a UID says little about which pod is calling, and a UID table cannot follow pods as they are scheduled. The server already has a Kubernetes path, `POST /v1/attest/k8s`, but it needs the workload itself to present a projected ServiceAccount token, which a plain SPIFFE Workload API client does not do.

The established answer, and the one SPIRE's agent uses, is for the node agent to identify the peer process: the kernel names its PID, the PID's cgroup names its pod and container, and the cluster names the pod's namespace, service account and labels. Omega's direction is to consume an upstream SPIFFE trust domain in production rather than to compete with SPIRE's issuing and attestation side. This attestor is for Omega's self-issued development and evaluation path, where an operator wants pod identities on a kind or test cluster without deploying SPIRE.

Two questions shape the design. Where is the pod looked up, and how does the result reach the control plane?

## Decision

1. **The agent attests, and the server is unchanged.** Omega has no registration-entry store and no selector matching on the server; the agent already requests `POST /v1/svid` for a SPIFFE ID it decided on, from the UID table. The attestor slots in at the same point: it decides the SPIFFE ID, and issuance goes through the existing endpoint. Sending selectors to the server would need a registration model the project does not have and does not plan, since that is the part of SPIRE it consumes rather than rebuilds.
2. **Peer PID, then cgroup.** On Linux the listener now records the peer PID from `SO_PEERCRED`. `/proc/<pid>/cgroup` is parsed for the pod UID and the 64-hex container ID, under cgroup v1 and v2, the cgroupfs and systemd drivers, and containerd, CRI-O and Docker naming. Paths are matched anywhere in the line, because an agent in its own cgroup namespace sees other processes' paths relative to its own (`/../../kubepods.slice/...`). A process in a pod's cgroup but in no container (the sandbox, CRI-O's `conmon`) is refused, and so is a path that is under the kubelet's `kubepods` tree or names a container ID in a layout the parser does not know (a kubelet with a custom `--cgroup-root`, a container outside Kubernetes): only a process with neither counts as a host process.
3. **The pod from kube-apiserver, filtered to this node.** The agent lists pods with the field selector `spec.nodeName=<node>`, re-checks the node on each result, and matches the pod UID (or, for a static pod, the config hash in a mirror pod's `kubernetes.io/config.mirror` annotation) and the container ID in the regular, init or ephemeral container statuses. The annotation and owner references are writable by anyone who can create a pod, so a hash only nominates candidates: the container in the status, which the kubelet writes, decides, and two candidates that both list it are refused rather than resolved by list order. The list is cached and re-fetched on a miss at most once a second, so a stream of unknown processes cannot turn into apiserver load; a miss inside that second is answered as transient (`Unavailable`), so the workload's client retries rather than treating it as a refusal. The kubelet's `/pods` endpoint was the alternative; it avoids apiserver load but needs `nodes/proxy`, which on most clusters also lets the holder reach every kubelet API including exec. Read access to pod specs is the smaller grant.
4. **The SPIFFE ID comes from a template.** `--k8s-workload-svid-template` takes the same placeholders as the server's `--k8s-svid-template` (`{namespace}`, `{serviceaccount}`, `{podname}`) and is rendered by the same function, so the two Kubernetes paths name a workload the same way. Selectors in the usual `k8s:ns:...`, `k8s:sa:...`, `k8s:pod-label:<k>:<v>` form are logged with each attestation, for diagnosis, not matched.
5. **A pod process is never handed to the UID table.** If the attestor is on and the peer is in a pod, the outcome is the pod's identity or a refusal. Only a process outside any pod (a host process) falls back to `--map`. Workloads with the same SPIFFE ID share one cached SVID and its key pair, as SPIRE's agent shares one per registration entry; with the default template that is every pod of a service account, and `{podname}` in the template gives each pod its own.
6. **Off by default, Linux only.** `omega agent --k8s-workload-attestor` with `--k8s-node-name` (or `NODE_NAME` from the downward API). The Helm value `agent.k8sWorkloadAttestor.enabled` sets the flags, injects `NODE_NAME`, turns on `hostPID`, and runs the agent under its own ServiceAccount bound to a ClusterRole with `list` on pods, so the server's ServiceAccount does not gain it.

`hostPID` is strictly required: the kernel reports a peer's PID only to a process in the same PID namespace or an ancestor of it, so an agent in its own PID namespace sees PID 0 for every pod. With the attestor on, a PID of 0 is refused for every peer, so `--map` workloads also stop working without it. The agent stays non-root with every capability dropped; `/proc/<pid>/cgroup` and `/proc/<pid>/stat` are world-readable.

## Consequences

Easier:

- A pod gets an identity from what it is (namespace, service account, pod) through an unmodified SPIFFE Workload API client, on a node where UIDs mean little.
- Both Kubernetes paths, server-side token attestation and agent-side process attestation, render SPIFFE IDs from the same template language.

Harder:

- The agent shares the host's PID namespace and can list every pod spec in the cluster. RBAC cannot scope `list` to one node.
- A container on the node that is not a pod (one started by Docker directly, say) is refused rather than given its UID's mapping.
- The agent trusts kube-apiserver for the pod's namespace and service account; the node check limits a wrong answer to pods on this node.
- PIDs are reused. A peer that connects, hands its socket to another process and exits, followed by a target process that is given the same PID before the agent reads `/proc`, would be attested as the target. The agent checks that the PID's start time is unchanged across the lookup, which closes the window during the lookup but not between `connect` and the first read. SPIRE closes it with a pidfd; this attestor does not.
- Issuance through `POST /v1/svid` is open only when the server runs without `--require-auth`; under it an agent may obtain only its own identity (S3 in the threat model), so this attestor serves the self-issued development and evaluation path. A workload that must enrol against a server with `--require-auth` uses `POST /v1/attest/k8s` with its own projected token.
- It is not a substitute for SPIRE's Kubernetes workload attestor. There is no registration-entry model, no selector matching, no image or container-name selectors in the SPIFFE ID, no kubelet verification, and no node attestation of the agent itself.

## Scope fit

Rule 3 in [design-philosophy.md](../design-philosophy.md): *"Is it an upstream system Omega depends on but does not own?"*

Yes. The workload attestor is a Plugin-layer seam (Kubernetes / EC2 / GCP IAM / Docker / Unix uid), and the facts it relies on belong to the kernel and the cluster. This is the Kubernetes implementation of that seam inside the existing agent role (ADR 0004), with UID attestation kept as the fallback.
