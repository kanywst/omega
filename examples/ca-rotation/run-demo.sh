#!/usr/bin/env bash
# run-demo.sh: rotate the built-in CA without restarting the server.
#
# Asserts, at each step and with only SIGHUP to the server:
#   * prepare: the bundle trusts two CAs, the active key still signs;
#   * activate: a new key signs, a JWT-SVID from the old one still verifies;
#   * retire: the bundle trusts one CA, the old JWT-SVID no longer verifies;
#   * spiffe_sequence advances with every change.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-ca-rotation-demo}"
PORT="${PORT:-18096}"
CP="http://127.0.0.1:$PORT"

cleanup() { [[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true; }
trap cleanup EXIT

field() { python3 -c "import sys, json; print(json.load(sys.stdin)$1)"; }
certs() { curl -fsS "$CP/v1/bundle" | grep -c 'BEGIN CERTIFICATE'; }
sequence() { curl -fsS "$CP/v1/spiffe-bundle" | field '["spiffe_sequence"]'; }
kids() { curl -fsS "$CP/v1/jwt/bundle" | python3 -c 'import sys, json; print(",".join(sorted(k["kid"] for k in json.load(sys.stdin)["keys"])))'; }
mint() { # [spiffe-id] -> a JWT-SVID from the current signing key
	curl -fsS -X POST "$CP/v1/svid/jwt" -H 'Content-Type: application/json' \
		-d "{\"spiffe_id\":\"${1:-spiffe://omega.local/web}\",\"audience\":[\"demo\"]}" | field '["token"]'
}
valid() { # subject token -> 200 when the server verifies it in a token exchange
	curl -s -o "$DEMO_DIR/exchange.json" -w '%{http_code}' -X POST "$CP/v1/token/exchange" -H 'Content-Type: application/json' \
		-d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",\"subject_token\":\"$1\",\"subject_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",\"actor_token\":\"$(mint spiffe://omega.local/agent)\",\"actor_token_type\":\"urn:ietf:params:oauth:token-type:jwt\",\"requested_spiffe_id\":\"spiffe://omega.local/agent\",\"audience\":[\"next\"]}"
}
step() { "$DEMO_DIR/omega" ca "$@" --data-dir "$DEMO_DIR/data" >/dev/null; kill -HUP "$(cat "$DEMO_DIR/server.pid")"; sleep 1; }
expect() {
	if [[ "$2" != "$3" ]]; then echo "FAIL: $1: got $2, want $3" >&2; tail -20 "$DEMO_DIR/server.log" >&2; exit 1; fi
	echo "  $1 -> $2"
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
echo "[demo] building omega"
go -C "$REPO_ROOT" build -o "$DEMO_DIR/omega" ./cmd/omega

echo "[demo] starting the control plane"
"$DEMO_DIR/omega" server --http-addr "127.0.0.1:$PORT" --trust-domain omega.local --data-dir "$DEMO_DIR/data" >"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
for _ in $(seq 1 100); do curl -fsS -o /dev/null "$CP/healthz" 2>/dev/null && break; sleep 0.1; done
OLD_KIDS="$(kids)"
OLD_TOKEN="$(mint)"
expect "trusted CAs" "$(certs)" 1
expect "spiffe_sequence" "$(sequence)" 1

echo "[demo] omega ca prepare + SIGHUP: the next CA is trusted, not signing"
step prepare
expect "trusted CAs" "$(certs)" 2
expect "spiffe_sequence" "$(sequence)" 2
[[ "$(mint | cut -d. -f1)" == "$(echo "$OLD_TOKEN" | cut -d. -f1)" ]] || { echo "FAIL: a prepared CA signed" >&2; exit 1; }
echo "  tokens are still signed by the old key"

echo "[demo] omega ca activate + SIGHUP: the new CA signs, the old stays trusted"
step activate
expect "trusted CAs" "$(certs)" 2
expect "spiffe_sequence" "$(sequence)" 3
[[ "$(mint | cut -d. -f1)" != "$(echo "$OLD_TOKEN" | cut -d. -f1)" ]] || { echo "FAIL: still signing with the old key" >&2; exit 1; }
echo "  new tokens carry the new key id"
expect "a token from the old CA is accepted" "$(valid "$OLD_TOKEN")" 200

echo "[demo] omega ca retire --force + SIGHUP: only the new CA is trusted"
step retire --force
expect "trusted CAs" "$(certs)" 1
expect "spiffe_sequence" "$(sequence)" 4
[[ "$(kids)" != "$OLD_KIDS" ]] || { echo "FAIL: the old key is still published" >&2; exit 1; }
code="$(valid "$OLD_TOKEN")"
[[ "$code" != 200 ]] || { echo "FAIL: a token from the retired CA was accepted" >&2; exit 1; }
echo "  a token from the retired CA is refused ($code)"

n="$(curl -fsS "$CP/v1/audit?since=0" | grep -o '"kind":"ca.reload"' | wc -l | tr -d ' ')"
expect "ca.reload rows in the audit chain" "$n" 3

echo
echo "[demo] success - rotated the CA with no restart and no window without trust"
