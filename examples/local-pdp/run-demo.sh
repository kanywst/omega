#!/usr/bin/env bash
# run-demo.sh: local policy decisions on the node, audited centrally.
#
# Asserts:
#   * the agent's local PDP allows a media workload and denies another;
#   * both decisions reach the control plane's audit chain as source=local;
#   * a policy change (SIGHUP on the server) reaches the node on the next sync;
#   * with the control plane gone, the local PDP keeps deciding until
#     --policy-max-age and then answers 503.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-local-pdp-demo}"
SERVER_PORT="${SERVER_PORT:-18099}"
PDP_PORT="${PDP_PORT:-18181}"

cleanup() {
	for p in server agent; do
		[[ -f "$DEMO_DIR/$p.pid" ]] && kill "$(cat "$DEMO_DIR/$p.pid")" 2>/dev/null || true
	done
}
trap cleanup EXIT

wait_up() {
	for _ in $(seq 1 100); do
		curl -fsS -o /dev/null "$1" 2>/dev/null && return 0
		sleep 0.1
	done
	echo "FAIL: $1 did not come up" >&2
	exit 1
}

decide() { # spiffe-id -> HTTP status and decision
	curl -s -o "$DEMO_DIR/decision.json" -w '%{http_code}' -X POST "http://127.0.0.1:$PDP_PORT/access/v1/evaluation" \
		-H 'Content-Type: application/json' \
		-d "{\"subject\":{\"type\":\"Spiffe\",\"id\":\"$1\"},\"action\":{\"name\":\"read\"},\"resource\":{\"type\":\"Doc\",\"id\":\"d\"}}"
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/policies"
EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
cp "$EXAMPLE_DIR/policies/media.cedar" "$DEMO_DIR/policies/"

echo "[demo] building omega"
go -C "$REPO_ROOT" build -o "$DEMO_DIR/omega" ./cmd/omega

echo "[demo] starting the control plane on :$SERVER_PORT"
"$DEMO_DIR/omega" server --http-addr "127.0.0.1:$SERVER_PORT" --trust-domain omega.local \
	--data-dir "$DEMO_DIR/server" --policy-dir "$DEMO_DIR/policies" >"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_up "http://127.0.0.1:$SERVER_PORT/healthz"
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/domains" -H 'Content-Type: application/json' -d '{"name":"media"}' >/dev/null

echo "[demo] starting the agent with a local PDP on :$PDP_PORT"
"$DEMO_DIR/omega" agent --socket "$DEMO_DIR/agent.sock" --server "http://127.0.0.1:$SERVER_PORT" \
	--map "uid=$(id -u),id=spiffe://omega.local/media/web" \
	--local-pdp-addr "127.0.0.1:$PDP_PORT" --policy-sync-interval 1s --policy-max-age 4s \
	>"$DEMO_DIR/agent.log" 2>&1 &
echo $! >"$DEMO_DIR/agent.pid"
wait_up "http://127.0.0.1:$PDP_PORT/healthz"
for _ in $(seq 1 50); do
	grep -q '"revision":"[0-9a-f]' <(curl -fsS "http://127.0.0.1:$PDP_PORT/healthz") && break
	sleep 0.1
done

echo "[demo] deciding locally"
[[ "$(decide spiffe://omega.local/media/web)" == 200 ]] && grep -q '"decision":true' "$DEMO_DIR/decision.json" \
	|| { echo "FAIL: media workload not allowed" >&2; cat "$DEMO_DIR/decision.json" >&2; exit 1; }
echo "  media/web   -> allow"
[[ "$(decide spiffe://omega.local/sports/web)" == 200 ]] && grep -q '"decision":false' "$DEMO_DIR/decision.json" \
	|| { echo "FAIL: sports workload not denied" >&2; exit 1; }
echo "  sports/web  -> deny"

echo "[demo] waiting for the decisions to reach the central audit chain"
for _ in $(seq 1 50); do
	n=$( (curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/audit?since=0" | grep -o '"source":"local"' || true) | wc -l | tr -d ' ')
	[[ "$n" -ge 2 ]] && break
	sleep 0.2
done
[[ "$n" -ge 2 ]] || { echo "FAIL: local decisions not audited ($n)" >&2; exit 1; }
echo "  $n local decisions recorded"

echo "[demo] changing the policy on the control plane (SIGHUP)"
printf 'forbid (principal, action, resource);\n' >"$DEMO_DIR/policies/media.cedar"
kill -HUP "$(cat "$DEMO_DIR/server.pid")"
for _ in $(seq 1 50); do
	decide spiffe://omega.local/media/web >/dev/null
	grep -q '"decision":false' "$DEMO_DIR/decision.json" && break
	sleep 0.2
done
grep -q '"decision":false' "$DEMO_DIR/decision.json" || { echo "FAIL: policy change did not reach the node" >&2; exit 1; }
echo "  media/web   -> deny after the change"

echo "[demo] stopping the control plane; the node keeps deciding until max-age"
kill "$(cat "$DEMO_DIR/server.pid")"; rm -f "$DEMO_DIR/server.pid"
[[ "$(decide spiffe://omega.local/media/web)" == 200 ]] || { echo "FAIL: local PDP stopped too early" >&2; exit 1; }
echo "  still answering"
for _ in $(seq 1 80); do
	[[ "$(decide spiffe://omega.local/media/web)" == 503 ]] && break
	sleep 0.1
done
[[ "$(decide spiffe://omega.local/media/web)" == 503 ]] || { echo "FAIL: local PDP did not fail closed" >&2; exit 1; }
echo "  503 once the bundle is older than --policy-max-age"

echo
echo "[demo] success - decided on the node, audited centrally, fails closed when cut off"
