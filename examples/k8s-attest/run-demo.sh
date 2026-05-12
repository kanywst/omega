#!/usr/bin/env bash
# run-demo.sh: prove that omega's K8s attestor accepts a real
# Kubernetes ServiceAccount projected token, rejects the wrong
# audience, and issues a SPIFFE-ID-carrying X.509-SVID for the
# authenticated `(namespace, serviceaccount)` pair.
#
# Topology: a one-node kind cluster mints the SA token, omega runs
# out-of-cluster on the host and uses the kind kubeconfig to perform
# the TokenReview against the apiserver. That is the same shape as a
# production deployment where omega lives in the control plane and
# workloads in worker clusters, just collapsed onto one host.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-k8s-attest-demo}"
SERVER_PORT="${SERVER_PORT:-18490}"
CLUSTER_NAME="${CLUSTER_NAME:-omega-k8s-attest}"
TRUST_DOMAIN="${TRUST_DOMAIN:-omega.demo}"
NAMESPACE="${NAMESPACE:-omega-attest-demo}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-workload}"
TOKEN_AUDIENCE="${TOKEN_AUDIENCE:-omega}"
SVID_TEMPLATE="${SVID_TEMPLATE:-spiffe://${TRUST_DOMAIN}/ns/{namespace}/sa/{serviceaccount}}"
EXPECTED_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/ns/${NAMESPACE}/sa/${SERVICE_ACCOUNT}"

for cmd in kind kubectl omega openssl curl python3; do
	command -v "$cmd" >/dev/null || {
		echo "[demo] FAIL: $cmd not in PATH"
		exit 1
	}
done

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	if [[ "${KEEP_CLUSTER:-0}" != "1" ]]; then
		kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

wait_for_url() {
	local url="$1" log="$2"
	for _ in $(seq 1 50); do
		if curl -fsS "$url" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	echo "[demo] FAIL: $url did not become ready within 10s"
	[[ -f "$log" ]] && { echo "[demo] log tail ($log):"; tail -30 "$log" | sed 's/^/       /'; }
	exit 1
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

echo "[demo] booting kind cluster $CLUSTER_NAME"
# An existing cluster of the same name is reused so iterative runs
# stay fast. CI starts from a clean runner so this is a no-op there.
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
	kind create cluster --name "$CLUSTER_NAME" >"$DEMO_DIR/kind.log" 2>&1
fi

KUBECONFIG_FILE="$DEMO_DIR/kubeconfig"
kind get kubeconfig --name "$CLUSTER_NAME" >"$KUBECONFIG_FILE"

echo "[demo] creating ns=$NAMESPACE sa=$SERVICE_ACCOUNT"
KUBECONFIG="$KUBECONFIG_FILE" kubectl create namespace "$NAMESPACE" >/dev/null
KUBECONFIG="$KUBECONFIG_FILE" kubectl -n "$NAMESPACE" create serviceaccount "$SERVICE_ACCOUNT" >/dev/null

echo "[demo] minting projected SA token (audience=$TOKEN_AUDIENCE)"
TOKEN=$(KUBECONFIG="$KUBECONFIG_FILE" kubectl -n "$NAMESPACE" create token "$SERVICE_ACCOUNT" \
	--audience "$TOKEN_AUDIENCE" --duration 5m)
WRONG_TOKEN=$(KUBECONFIG="$KUBECONFIG_FILE" kubectl -n "$NAMESPACE" create token "$SERVICE_ACCOUNT" \
	--audience "not-omega" --duration 5m)

echo "[demo] starting omega server on :$SERVER_PORT"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN" \
	--data-dir "$DEMO_DIR/server" \
	--k8s-attest \
	--kubeconfig "$KUBECONFIG_FILE" \
	--k8s-token-audience "$TOKEN_AUDIENCE" \
	--k8s-svid-template "$SVID_TEMPLATE" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_for_url "http://127.0.0.1:$SERVER_PORT/healthz" "$DEMO_DIR/server.log"

# Generate a workload keypair + CSR. openssl `-subj` splits on '/',
# so the SPIFFE URI must NOT live in the CN - omega derives the
# SPIFFE ID from the validated token, not from CSR fields.
openssl ecparam -name prime256v1 -genkey -noout -out "$DEMO_DIR/wl.key" 2>/dev/null
openssl req -new -key "$DEMO_DIR/wl.key" -subj "/CN=omega-k8s-attest-workload" -out "$DEMO_DIR/wl.csr" 2>/dev/null
CSR_PEM_JSON=$(python3 -c "import json; print(json.dumps(open('$DEMO_DIR/wl.csr').read()))")

echo "[demo] attesting with a correct-audience token (expect 200)"
SVID_JSON=$(curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/attest/k8s" \
	-H 'content-type: application/json' \
	-d "{\"token\":\"$TOKEN\",\"csr\":$CSR_PEM_JSON}")

GOT_SPIFFE_ID=$(echo "$SVID_JSON" | python3 -c "import sys,json; sys.stdout.write(json.load(sys.stdin)['spiffe_id'])")
if [[ "$GOT_SPIFFE_ID" != "$EXPECTED_SPIFFE_ID" ]]; then
	echo "[demo] FAIL: spiffe_id mismatch"
	echo "        want: $EXPECTED_SPIFFE_ID"
	echo "        got:  $GOT_SPIFFE_ID"
	exit 1
fi

echo "$SVID_JSON" | python3 -c "import sys,json; sys.stdout.write(json.load(sys.stdin)['svid'])" >"$DEMO_DIR/leaf.pem"
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/bundle.pem"

if ! openssl verify -CAfile "$DEMO_DIR/bundle.pem" "$DEMO_DIR/leaf.pem" >"$DEMO_DIR/verify.log" 2>&1; then
	echo "[demo] FAIL: leaf does not chain to omega CA"
	sed 's/^/       /' "$DEMO_DIR/verify.log"
	exit 1
fi
if ! openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -text 2>/dev/null | grep -q "URI:$EXPECTED_SPIFFE_ID"; then
	echo "[demo] FAIL: leaf does not carry the SPIFFE ID URI SAN"
	openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -text 2>/dev/null | grep -A2 'Subject Alternative Name' | sed 's/^/       /'
	exit 1
fi

echo "[demo] attesting with a wrong-audience token (expect 401)"
STATUS=$(curl -s -o "$DEMO_DIR/wrong.json" -w '%{http_code}' \
	-X POST "http://127.0.0.1:$SERVER_PORT/v1/attest/k8s" \
	-H 'content-type: application/json' \
	-d "{\"token\":\"$WRONG_TOKEN\",\"csr\":$CSR_PEM_JSON}")
if [[ "$STATUS" != "401" ]]; then
	echo "[demo] FAIL: wrong-audience token: got HTTP $STATUS, want 401"
	cat "$DEMO_DIR/wrong.json" | sed 's/^/       /'
	exit 1
fi

echo "[demo] success"
echo "[demo]   spiffe_id:   $GOT_SPIFFE_ID"
echo "[demo]   trust_anchor: $(openssl x509 -in "$DEMO_DIR/bundle.pem" -noout -subject 2>/dev/null)"
echo "[demo]   leaf issuer:  $(openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -issuer 2>/dev/null)"
echo "[demo]   deny path:    wrong-audience token rejected with HTTP 401"
