#!/usr/bin/env bash
# run-demo.sh brings up two federated Omega control planes (omega.alpha
# on :18088, omega.beta on :18089) plus one agent per side, then asks
# each agent for its X.509 trust bundle map and asserts that both trust
# domains' CAs are present.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-federation-demo}"
ALPHA_PORT="${ALPHA_PORT:-18088}"
BETA_PORT="${BETA_PORT:-18089}"
UID_LOCAL="$(id -u)"

cleanup() {
	[[ -f "$DEMO_DIR/alpha-server.pid" ]] && kill "$(cat "$DEMO_DIR/alpha-server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/beta-server.pid" ]] && kill "$(cat "$DEMO_DIR/beta-server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/alpha-agent.pid" ]] && kill "$(cat "$DEMO_DIR/alpha-agent.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/beta-agent.pid" ]] && kill "$(cat "$DEMO_DIR/beta-agent.pid")" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/alpha" "$DEMO_DIR/beta"

echo "[demo] starting omega.alpha on :$ALPHA_PORT (federate-with omega.beta)"
omega server \
	--http-addr "127.0.0.1:$ALPHA_PORT" \
	--trust-domain omega.alpha \
	--data-dir "$DEMO_DIR/alpha" \
	--federate-with "name=omega.beta,url=http://127.0.0.1:$BETA_PORT" \
	--federation-allow-insecure \
	>"$DEMO_DIR/alpha-server.log" 2>&1 &
echo $! >"$DEMO_DIR/alpha-server.pid"

echo "[demo] starting omega.beta on :$BETA_PORT (federate-with omega.alpha)"
omega server \
	--http-addr "127.0.0.1:$BETA_PORT" \
	--trust-domain omega.beta \
	--data-dir "$DEMO_DIR/beta" \
	--federate-with "name=omega.alpha,url=http://127.0.0.1:$ALPHA_PORT" \
	--federation-allow-insecure \
	>"$DEMO_DIR/beta-server.log" 2>&1 &
echo $! >"$DEMO_DIR/beta-server.pid"

# Both servers do an immediate peer fetch on startup, but the two
# servers start concurrently — whichever ticks first may find its peer
# still binding its port. The registry's regular refresh interval is
# 30s, which is too long for a CI demo, so poll each /v1/federation/bundles
# endpoint until both ends carry the merged 2-bundle map.
wait_federated() {
	local label="$1" port="$2"
	for _ in $(seq 1 100); do
		body="$(curl -fsS "http://127.0.0.1:$port/v1/federation/bundles" 2>/dev/null || true)"
		if echo "$body" | grep -q omega.alpha && echo "$body" | grep -q omega.beta; then
			return 0
		fi
		sleep 0.3
	done
	echo "FAIL: $label did not converge to a 2-bundle federation map" >&2
	echo "----- $label server.log tail -----" >&2
	tail -80 "$DEMO_DIR/$label-server.log" >&2 || true
	return 1
}
wait_federated alpha "$ALPHA_PORT"
wait_federated beta "$BETA_PORT"

echo "[demo] starting omega.alpha agent (socket $DEMO_DIR/alpha.sock)"
omega agent \
	--socket "$DEMO_DIR/alpha.sock" \
	--server "http://127.0.0.1:$ALPHA_PORT" \
	--map "uid=$UID_LOCAL,id=spiffe://omega.alpha/demo" \
	>"$DEMO_DIR/alpha-agent.log" 2>&1 &
echo $! >"$DEMO_DIR/alpha-agent.pid"

echo "[demo] starting omega.beta agent (socket $DEMO_DIR/beta.sock)"
omega agent \
	--socket "$DEMO_DIR/beta.sock" \
	--server "http://127.0.0.1:$BETA_PORT" \
	--map "uid=$UID_LOCAL,id=spiffe://omega.beta/demo" \
	>"$DEMO_DIR/beta-agent.log" 2>&1 &
echo $! >"$DEMO_DIR/beta-agent.pid"

sleep 1

echo "[demo] building federation/check"
go -C "$(dirname "$0")/check" build -o "$DEMO_DIR/check" .

# Capture each control plane's own CA fingerprint so we can confirm the
# Workload API surface really merges the peer's bundle, not just relabels
# the local CA.
ALPHA_FP="$(curl -s "http://127.0.0.1:$ALPHA_PORT/v1/bundle" | openssl x509 -noout -fingerprint -sha256 | tr -d ':' | awk -F= '{print tolower($2)}')"
BETA_FP="$(curl -s "http://127.0.0.1:$BETA_PORT/v1/bundle" | openssl x509 -noout -fingerprint -sha256 | tr -d ':' | awk -F= '{print tolower($2)}')"

echo "[demo] expected fingerprints:"
echo "  omega.alpha: $ALPHA_FP"
echo "  omega.beta:  $BETA_FP"

verify_agent() {
	local label="$1" socket="$2"
	echo "[demo] $label agent bundle map:"
	local out
	out="$("$DEMO_DIR/check" --socket "$socket")"
	echo "$out" | sed 's/^/  /'
	if ! echo "$out" | grep -q "omega.alpha .*$ALPHA_FP"; then
		echo "FAIL: $label agent missing or mismatched omega.alpha bundle" >&2
		exit 1
	fi
	if ! echo "$out" | grep -q "omega.beta .*$BETA_FP"; then
		echo "FAIL: $label agent missing or mismatched omega.beta bundle" >&2
		exit 1
	fi
}

verify_agent "alpha" "$DEMO_DIR/alpha.sock"
verify_agent "beta" "$DEMO_DIR/beta.sock"

echo "[demo] success — both agents serve the merged trust bundle map"
