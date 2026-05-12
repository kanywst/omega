# examples/k8s-attest

End-to-end demo of `omega server --k8s-attest`: prove that the
TokenReview-based Kubernetes attestor accepts a real ServiceAccount
projected token, rejects a wrong-audience token, and issues an
X.509-SVID whose SPIFFE ID is derived from the validated
`(namespace, serviceaccount)` pair instead of being trusted from the
CSR.

`make demo` does six things:

1. boots a one-node `kind` cluster (default name `omega-k8s-attest`);
2. creates a namespace and ServiceAccount and mints two projected
   tokens via `kubectl create token --audience` — one for the
   audience omega expects, one for a different audience;
3. starts `omega server` out-of-cluster against the kind kubeconfig
   with `--k8s-attest --kubeconfig=... --k8s-token-audience=omega
   --k8s-svid-template=spiffe://omega.demo/ns/{namespace}/sa/{serviceaccount}`;
4. submits the correct-audience token plus a workload CSR to
   `POST /v1/attest/k8s` and asserts the returned `spiffe_id` matches
   the template rendered against the validated token claims;
5. verifies the issued leaf chains to `/v1/bundle` and carries the
   rendered SPIFFE ID as a URI SAN, proving the SPIFFE identity in
   the cert came from the token, not the CSR;
6. submits the wrong-audience token and asserts the server returns
   `HTTP 401` (the TokenReview rejection path that omega audits as
   `attest.k8s decision=deny`).

The deployment shape — control-plane omega out-of-cluster, workloads
in the cluster — collapses to one host for the demo but mirrors a
realistic production layout. The same flags work unchanged against a
real cluster: point `--kubeconfig` at the workload cluster's
kubeconfig (or omit it and rely on the in-cluster ServiceAccount
config when omega runs as a pod).

## Run

```text
make demo
```

The script tears the kind cluster down on exit; force a manual
cleanup:

```text
make down
```

Pass `KEEP_CLUSTER=1 make demo` to retain the cluster across
iterations (faster for repeated runs).

## Requirements

- `kind` (any recent release)
- `kubectl` (1.24 or later — the demo uses `kubectl create token`)
- `omega` on `$PATH` (the parent `Makefile` builds and exports it
  for CI; locally, run `make build` once at the repo root)
- `openssl`, `curl`, `python3`

## Adapt to a real cluster

Skip steps 1–2 above and bring up `omega server` out-of-cluster (or
as a pod with `automountServiceAccountToken: true`):

```text
omega server \
  --trust-domain omega.example \
  --k8s-attest \
  --kubeconfig /etc/omega/workload-cluster.kubeconfig \
  --k8s-token-audience omega \
  --k8s-svid-template "spiffe://omega.example/ns/{namespace}/sa/{serviceaccount}"
```

Workload pods then need a projected token volume with the matching
audience (the demo uses `kubectl create token` for brevity, but the
production pattern is the projected token volume):

```yaml
spec:
  volumes:
    - name: omega-token
      projected:
        sources:
          - serviceAccountToken:
              audience: omega
              expirationSeconds: 600
              path: token
  containers:
    - name: workload
      volumeMounts:
        - name: omega-token
          mountPath: /var/run/omega
          readOnly: true
```

The workload reads the token from `/var/run/omega/token` and
exchanges it at `POST /v1/attest/k8s`.
