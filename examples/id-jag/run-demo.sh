#!/usr/bin/env bash
# run-demo.sh: IdP-issued ID-JAG -> omega delegated JWT-SVID -> MCP tool.
#
# Asserts:
#   * the agent redeems the ID-JAG at POST /oauth2/token and the tool
#     sees the chain [alice, claude-code];
#   * an ID token presented as the grant, and the ID-JAG presented by a
#     different agent, are both rejected with invalid_grant;
#   * the audit log has one token.id_jag allow row rooted at alice.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-id-jag-demo}"
SERVER_PORT="${SERVER_PORT:-18098}"
IDP_PORT="${IDP_PORT:-19100}"
TOOL_PORT="${TOOL_PORT:-19001}"
ISSUER="https://omega.demo.local"
ALICE="spiffe://omega.local/humans/corp/alice"
AGENT="spiffe://omega.local/agents/claude-code"

cleanup() {
	for p in server idp tool; do
		[[ -f "$DEMO_DIR/$p.pid" ]] && kill "$(cat "$DEMO_DIR/$p.pid")" 2>/dev/null || true
	done
}
trap cleanup EXIT

wait_up() {
	for _ in $(seq 1 50); do
		curl -fsS -o /dev/null "$1" 2>/dev/null && return 0
		sleep 0.1
	done
	echo "FAIL: $1 did not come up" >&2
	exit 1
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"

echo "[demo] building omega + demo binaries"
go -C "$REPO_ROOT" build -o "$DEMO_DIR/omega" ./cmd/omega
go -C "$REPO_ROOT" build -o "$DEMO_DIR/idp" ./examples/id-jag/idp
go -C "$REPO_ROOT" build -o "$DEMO_DIR/client" ./examples/id-jag/client
go -C "$REPO_ROOT" build -o "$DEMO_DIR/tool-server" ./examples/mcp-a2a-delegation/tool-server

echo "[demo] starting IdP on :$IDP_PORT"
"$DEMO_DIR/idp" --addr "127.0.0.1:$IDP_PORT" --ras-issuer "$ISSUER" --client-at-ras "$AGENT" \
	>"$DEMO_DIR/idp.log" 2>&1 &
echo $! >"$DEMO_DIR/idp.pid"
wait_up "http://127.0.0.1:$IDP_PORT/healthz"

echo "[demo] starting omega on :$SERVER_PORT (trusting the IdP for ID-JAGs; dev-mode client binding)"
"$DEMO_DIR/omega" server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain omega.local \
	--issuer-url "$ISSUER" \
	--data-dir "$DEMO_DIR/server" \
	--policy-dir "$EXAMPLE_DIR/policies" \
	--id-jag-insecure-client-binding \
	--id-jag-idp "name=corp,issuer=http://127.0.0.1:$IDP_PORT,template=spiffe://omega.local/humans/{idp}/{sub}" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_up "http://127.0.0.1:$SERVER_PORT/healthz"

echo "[demo] starting tool-server on :$TOOL_PORT"
"$DEMO_DIR/tool-server" \
	--addr "127.0.0.1:$TOOL_PORT" \
	--jwks-url "http://127.0.0.1:$SERVER_PORT/v1/jwt/bundle" \
	--audience "mcp://github-issue" \
	>"$DEMO_DIR/tool.log" 2>&1 &
echo $! >"$DEMO_DIR/tool.pid"
wait_up "http://127.0.0.1:$TOOL_PORT/healthz"

echo "[demo] metadata"
curl -fsS "http://127.0.0.1:$SERVER_PORT/.well-known/oauth-authorization-server"
echo

"$DEMO_DIR/client" \
	--idp-url "http://127.0.0.1:$IDP_PORT" \
	--omega-url "http://127.0.0.1:$SERVER_PORT" \
	--omega-issuer "$ISSUER" \
	--tool-url "http://127.0.0.1:$TOOL_PORT/tool/issues" \
	--agent "$AGENT" \
	| tee "$DEMO_DIR/client.out"

echo
echo "[demo] verifying the tool saw the chain rooted at alice"
if ! grep -qF -- "\"delegation_chain\":[\"$ALICE\",\"$AGENT\"]" "$DEMO_DIR/client.out"; then
	echo "FAIL: tool response did not carry [$ALICE, $AGENT]" >&2
	exit 1
fi

echo "[demo] verifying the audit log"
audit=$(curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/audit?since=0")
allow=$(printf '%s' "$audit" | grep -o '"kind":"token.id_jag"[^}]*"decision":"allow"' | wc -l | tr -d ' ')
deny=$(printf '%s' "$audit" | grep -o '"kind":"token.id_jag"[^}]*"decision":"deny"' | wc -l | tr -d ' ')
if [[ "$allow" -ne 1 || "$deny" -ne 2 ]]; then
	echo "FAIL: want 1 allow + 2 deny token.id_jag rows, got $allow allow + $deny deny" >&2
	echo "$audit" >&2
	exit 1
fi

echo
echo "[demo] success - ID-JAG redeemed for a delegated JWT-SVID, misuse rejected and audited"
