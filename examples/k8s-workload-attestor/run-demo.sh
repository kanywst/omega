#!/usr/bin/env bash
# run-demo.sh: prove that `omega agent --k8s-workload-attestor` gives a
# process in a pod the identity of its pod, and a host process the
# identity of its UID.
#
# Topology: a one-node kind cluster. The control plane and the agent
# both run inside the kind node container (it is the "host" the pods
# share a PID namespace with), the agent reaches kube-apiserver with a
# token for the chart's agent ServiceAccount, which holds only its
# pod-reader ClusterRole, and the workload is a pod that runs `omega svid fetch`
# against the agent's socket on a hostPath.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-k8s-workload-attestor-demo}"
CLUSTER_NAME="${CLUSTER_NAME:-omega-k8s-wl}"
NODE="${CLUSTER_NAME}-control-plane"
SERVER_PORT="${SERVER_PORT:-18491}"
NAMESPACE="${NAMESPACE:-wl-demo}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-web}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
POD_ID="spiffe://omega.local/k8s/${NAMESPACE}/${SERVICE_ACCOUNT}"
HOST_ID="spiffe://omega.local/host/root"
# Single quotes keep the placeholders for omega's template renderer.
# shellcheck disable=SC2016
TEMPLATE='spiffe://omega.local/k8s/{namespace}/{serviceaccount}'

for cmd in kind kubectl helm go docker; do
	command -v "$cmd" >/dev/null || {
		echo "[demo] FAIL: $cmd not in PATH"
		exit 1
	}
done

dump_logs() {
	for f in server.log agent.log; do
		echo "[demo] $f:"
		docker exec "$NODE" cat "/opt/omega/$f" 2>/dev/null | tail -30 | sed 's/^/       /' || true
	done
}

cleanup() {
	if [[ "${KEEP_CLUSTER:-0}" != "1" ]]; then
		kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
	else
		docker exec "$NODE" pkill -f /opt/omega/omega >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

echo "[demo] booting kind cluster $CLUSTER_NAME"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
	kind create cluster --name "$CLUSTER_NAME" >"$DEMO_DIR/kind.log" 2>&1
fi
KUBECONFIG="$DEMO_DIR/kubeconfig"
export KUBECONFIG
kind get kubeconfig --name "$CLUSTER_NAME" >"$KUBECONFIG"

echo "[demo] building a static linux omega for the node"
case "$(docker exec "$NODE" uname -m)" in
x86_64) GOARCH=amd64 ;;
aarch64) GOARCH=arm64 ;;
*) echo "[demo] FAIL: unsupported node architecture"; exit 1 ;;
esac
(cd "$REPO_ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -o "$DEMO_DIR/omega" ./cmd/omega)
docker exec "$NODE" mkdir -p /opt/omega /run/omega
docker cp "$DEMO_DIR/omega" "$NODE:/opt/omega/omega" >/dev/null

echo "[demo] granting the agent's service account the chart's pod-reader role"
kubectl get namespace omega-system >/dev/null 2>&1 || kubectl create namespace omega-system >/dev/null
helm template omega "$REPO_ROOT/charts/omega" --namespace omega-system \
	--set agent.k8sWorkloadAttestor.enabled=true \
	--show-only templates/agent-rbac.yaml | kubectl apply -n omega-system -f - >/dev/null
AGENT_TOKEN=$(kubectl -n omega-system create token omega-agent --duration 1h)
docker exec -i "$NODE" sh -c 'cat > /opt/omega/kubeconfig' <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: kind
    cluster:
      server: https://127.0.0.1:6443
      certificate-authority: /etc/kubernetes/pki/ca.crt
contexts:
  - name: agent
    context: {cluster: kind, user: agent}
users:
  - name: agent
    user:
      token: ${AGENT_TOKEN}
current-context: agent
EOF

echo "[demo] starting omega server and agent in the node"
docker exec -d "$NODE" sh -c "/opt/omega/omega server --http-addr 127.0.0.1:$SERVER_PORT --trust-domain omega.local --data-dir /opt/omega/server >/opt/omega/server.log 2>&1"
docker exec -d "$NODE" sh -c "/opt/omega/omega agent --socket /run/omega/agent.sock --server http://127.0.0.1:$SERVER_PORT \
	--map uid=0,id=$HOST_ID \
	--k8s-workload-attestor --kubeconfig /opt/omega/kubeconfig --k8s-node-name $NODE \
	--k8s-workload-svid-template '$TEMPLATE' >/opt/omega/agent.log 2>&1"
for _ in $(seq 1 100); do
	docker exec "$NODE" test -S /run/omega/agent.sock && break
	sleep 0.2
done
docker exec "$NODE" test -S /run/omega/agent.sock || {
	echo "[demo] FAIL: the agent socket did not appear"
	dump_logs
	exit 1
}

echo "[demo] a host process running as uid 0 gets the UID mapping (expect $HOST_ID)"
GOT=$(docker exec "$NODE" /opt/omega/omega svid fetch --socket /run/omega/agent.sock | sed -n 's/^# spiffe-id: //p')
if [[ "$GOT" != "$HOST_ID" ]]; then
	echo "[demo] FAIL: host process got $GOT"
	dump_logs
	exit 1
fi

echo "[demo] a pod running as uid 0 gets its pod's identity, not the uid 0 mapping (expect $POD_ID)"
PAUSE_IMAGE=$(docker exec "$NODE" crictl images -o json | python3 -c '
import json, sys
for img in json.load(sys.stdin)["images"]:
    for tag in img.get("repoTags") or []:
        if "/pause:" in tag:
            print(tag)
            sys.exit(0)
sys.exit(1)
')
kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE" >/dev/null
kubectl -n "$NAMESPACE" get sa "$SERVICE_ACCOUNT" >/dev/null 2>&1 || kubectl -n "$NAMESPACE" create serviceaccount "$SERVICE_ACCOUNT" >/dev/null
kubectl -n "$NAMESPACE" delete pod fetch --ignore-not-found >/dev/null
# The pause image is already on the node, and the static omega binary
# needs nothing from the image.
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: fetch
  namespace: ${NAMESPACE}
spec:
  serviceAccountName: ${SERVICE_ACCOUNT}
  restartPolicy: Never
  securityContext:
    runAsUser: 0
  containers:
    - name: fetch
      image: ${PAUSE_IMAGE}
      imagePullPolicy: Never
      command: ["/opt/omega/omega", "svid", "fetch", "--socket", "/run/omega/agent.sock"]
      volumeMounts:
        - {name: omega, mountPath: /opt/omega, readOnly: true}
        - {name: sock, mountPath: /run/omega}
  volumes:
    - {name: omega, hostPath: {path: /opt/omega, type: Directory}}
    - {name: sock, hostPath: {path: /run/omega, type: Directory}}
EOF
if ! kubectl -n "$NAMESPACE" wait pod/fetch --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s >/dev/null; then
	echo "[demo] FAIL: the fetch pod did not succeed"
	kubectl -n "$NAMESPACE" get pod fetch -o wide || true
	kubectl -n "$NAMESPACE" logs fetch | sed 's/^/       /' || true
	dump_logs
	exit 1
fi
GOT=$(kubectl -n "$NAMESPACE" logs fetch | sed -n 's/^# spiffe-id: //p')
if [[ "$GOT" != "$POD_ID" ]]; then
	echo "[demo] FAIL: pod got $GOT"
	dump_logs
	exit 1
fi
if ! docker exec "$NODE" grep -q "k8s:ns:$NAMESPACE" /opt/omega/agent.log; then
	echo "[demo] FAIL: the agent did not log the pod's selectors"
	dump_logs
	exit 1
fi

echo "[demo] success"
echo "[demo]   host process (uid 0): $HOST_ID"
echo "[demo]   pod process (uid 0):  $POD_ID"
docker exec "$NODE" grep "k8s attested" /opt/omega/agent.log | tail -1 | sed 's/^/[demo]   /'
