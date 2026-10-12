#!/usr/bin/env bash
# run-demo.sh: a pod gets its SVID through the SPIFFE CSI driver.
#
# Installs the Omega chart into a kind cluster with csi.enabled, then runs
# a pod that mounts the Workload API with a `csi.spiffe.io` ephemeral
# volume (no hostPath) and fetches its X.509-SVID from the Omega agent.
set -euo pipefail

CLUSTER="${CLUSTER:-omega-csi}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ID="spiffe://omega.local/csi/demo"

cleanup() { [[ "${KEEP:-}" == 1 ]] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[demo] creating kind cluster $CLUSTER"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 120s >/dev/null

echo "[demo] building and loading the omega image"
docker build -q -t omega:csi-demo "$REPO_ROOT" >/dev/null
kind load docker-image omega:csi-demo --name "$CLUSTER" >/dev/null

echo "[demo] installing the chart with the SPIFFE CSI driver"
helm install omega "$REPO_ROOT/charts/omega" --wait --timeout 5m \
	--set image.repository=omega --set image.tag=csi-demo --set image.pullPolicy=Never \
	--set server.persistence.enabled=false \
	--set agent.serverURL=http://omega-server:8080 \
	--set "agent.uidMap[0]=uid=65532\\,id=$ID" \
	--set csi.enabled=true >/dev/null
kubectl rollout status daemonset/omega-csi --timeout=180s >/dev/null

echo "[demo] running a pod that mounts the Workload API through csi.spiffe.io"
kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: csi-workload
spec:
  restartPolicy: Never
  securityContext:
    runAsUser: 65532
  containers:
    - name: workload
      image: omega:csi-demo
      imagePullPolicy: Never
      args: ["svid", "fetch", "--socket", "/spiffe-workload-api/agent.sock"]
      volumeMounts:
        - name: spiffe-workload-api
          mountPath: /spiffe-workload-api
          readOnly: true
  volumes:
    - name: spiffe-workload-api
      csi:
        driver: csi.spiffe.io
        readOnly: true
YAML
for _ in $(seq 1 60); do
	phase="$(kubectl get pod csi-workload -o jsonpath='{.status.phase}' 2>/dev/null || true)"
	[[ "$phase" == Succeeded || "$phase" == Failed ]] && break
	sleep 2
done
logs="$(kubectl logs csi-workload 2>&1 || true)"
if [[ "$phase" != Succeeded ]] || ! grep -q "$ID" <<<"$logs"; then
	echo "FAIL: the pod did not get its SVID (phase $phase)" >&2
	echo "$logs" | tail -20 >&2
	kubectl describe pod csi-workload | tail -20 >&2
	exit 1
fi
echo "  ok: the pod fetched $ID over the CSI-mounted socket"
echo
echo "[demo] success - Workload API delivered by the SPIFFE CSI driver, no hostPath in the pod"
