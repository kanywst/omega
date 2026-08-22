#!/usr/bin/env bash
# run-demo.sh: prove that omega follows an upstream SPIFFE trust-material
# rotation over the Workload API, with nothing signalling it.
#
# examples/spire-upstream covers the file transport, where the operator
# swaps two files and sends SIGHUP. Here omega is pointed at the upstream's
# Workload API socket instead: the rotation is applied to the upstream, no
# message reaches omega, and /v1/bundle, /v1/jwt/bundle and spiffe_sequence
# have to move anyway. See ADR 0010.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-spire-upstream-live-demo}"
UPSTREAM_PORT="${UPSTREAM_PORT:-18892}"
SERVER_PORT="${SERVER_PORT:-18893}"
TRUST_DOMAIN="${TRUST_DOMAIN:-upstream.demo}"
EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/agent.pid" ]] && kill "$(cat "$DEMO_DIR/agent.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/upstream.pid" ]] && kill "$(cat "$DEMO_DIR/upstream.pid")" 2>/dev/null || true
}
trap cleanup EXIT

wait_for_url() {
	local url="$1" log="$2"
	for _ in $(seq 1 50); do
		if curl -fsS "$url" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.1
	done
	echo "[demo] FAIL: $url did not become ready within 5s"
	[[ -f "$log" ]] && { echo "[demo] log tail ($log):"; tail -20 "$log" | sed 's/^/       /'; }
	exit 1
}

wait_for_log() {
	local pattern="$1" log="$2"
	for _ in $(seq 1 100); do
		if grep -q "$pattern" "$log"; then
			return 0
		fi
		sleep 0.1
	done
	echo "[demo] FAIL: did not observe \"$pattern\" in the log within 10s"
	echo "[demo] log tail ($log):"; tail -20 "$log" | sed 's/^/       /'
	exit 1
}

sequence() {
	curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/spiffe-bundle" |
		python3 -c 'import sys, json; print(json.load(sys.stdin)["spiffe_sequence"])'
}

kids() {
	python3 -c 'import sys, json
keys = json.load(sys.stdin).get("keys", [])
print(",".join(sorted(k.get("kid", "") for k in keys)))'
}

assert_eq() {
	local what="$1" got="$2" want="$3"
	if [[ "$got" != "$want" ]]; then
		echo "[demo] FAIL: $what"
		echo "       got:  $got"
		echo "       want: $want"
		exit 1
	fi
	echo "[demo]   ok: $what ($got)"
}

# No signal, no request: poll the served bundle rather than sleeping a guess.
wait_for_served_bundle() {
	local want="$1"
	for _ in $(seq 1 100); do
		curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/served.pem" 2>/dev/null || true
		if cmp -s "$DEMO_DIR/served.pem" "$want"; then
			return 0
		fi
		sleep 0.1
	done
	echo "[demo] FAIL: omega did not follow the upstream rotation within 10s"
	echo "[demo] server log tail:"; tail -20 "$DEMO_DIR/server.log" | sed 's/^/       /'
	exit 1
}

# One generation of an upstream SPIRE / Istio trust domain, minted by a
# throwaway built-in omega. Omega only ever consumes this material, so any
# issuer emitting a SPIFFE bundle plus an EC P-256 JWKS would do.
mint_upstream_generation() {
	local gen="$1"
	omega server \
		--http-addr "127.0.0.1:$UPSTREAM_PORT" \
		--trust-domain "$TRUST_DOMAIN" \
		--data-dir "$DEMO_DIR/upstream-$gen" \
		>"$DEMO_DIR/upstream-$gen.log" 2>&1 &
	echo $! >"$DEMO_DIR/upstream.pid"
	wait_for_url "http://127.0.0.1:$UPSTREAM_PORT/healthz" "$DEMO_DIR/upstream-$gen.log"
	curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/v1/bundle" >"$DEMO_DIR/bundle-$gen.pem"
	curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/v1/jwt/bundle" >"$DEMO_DIR/jwks-$gen.json"
	kill "$(cat "$DEMO_DIR/upstream.pid")" 2>/dev/null || true
	wait "$(cat "$DEMO_DIR/upstream.pid")" 2>/dev/null || true
	rm -f "$DEMO_DIR/upstream.pid"
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

echo "[demo] minting two upstream generations (a CA + signing-key rotation)"
mint_upstream_generation a
mint_upstream_generation b

KIDS_A="$(kids <"$DEMO_DIR/jwks-a.json")"
KIDS_B="$(kids <"$DEMO_DIR/jwks-b.json")"
if [[ "$KIDS_A" == "$KIDS_B" ]] || cmp -s "$DEMO_DIR/bundle-a.pem" "$DEMO_DIR/bundle-b.pem"; then
	echo "[demo] FAIL: the two generations share trust material; the fixture is not a rotation"
	exit 1
fi
echo "[demo]   generation a kids: $KIDS_A"
echo "[demo]   generation b kids: $KIDS_B"

echo "[demo] building mock-spire-agent"
go -C "$EXAMPLE_DIR/mock-spire-agent" build -o "$DEMO_DIR/mock-spire-agent" .

# What the upstream currently publishes. Rotating means rewriting these.
cp "$DEMO_DIR/bundle-a.pem" "$DEMO_DIR/upstream-bundle.pem"
cp "$DEMO_DIR/jwks-a.json" "$DEMO_DIR/upstream-jwks.json"

echo "[demo] starting the upstream workload API socket"
"$DEMO_DIR/mock-spire-agent" \
	--socket "$DEMO_DIR/agent.sock" \
	--trust-domain "$TRUST_DOMAIN" \
	--bundle "$DEMO_DIR/upstream-bundle.pem" \
	--jwks "$DEMO_DIR/upstream-jwks.json" \
	>"$DEMO_DIR/agent.log" 2>&1 &
echo $! >"$DEMO_DIR/agent.pid"
wait_for_log "serving the workload API" "$DEMO_DIR/agent.log"

echo "[demo] starting omega following that socket on :$SERVER_PORT"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--identity-source spire-upstream \
	--trust-domain "$TRUST_DOMAIN" \
	--identity-source-workload-api "unix://$DEMO_DIR/agent.sock" \
	--identity-source-workload-api-jwt \
	--data-dir "$DEMO_DIR/server" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_for_url "http://127.0.0.1:$SERVER_PORT/healthz" "$DEMO_DIR/server.log"

echo "[demo] serving the upstream trust material (generation a)"
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/served.pem"
if ! cmp -s "$DEMO_DIR/served.pem" "$DEMO_DIR/bundle-a.pem"; then
	echo "[demo] FAIL: /v1/bundle did not serve the upstream anchors verbatim"
	exit 1
fi
echo "[demo]   ok: /v1/bundle == upstream generation a"
assert_eq "/v1/jwt/bundle serves the upstream signing keys" \
	"$(curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/jwt/bundle" | kids)" "$KIDS_A"
assert_eq "spiffe_sequence starts at 1" "$(sequence)" "1"

# ADR 0007: consuming an upstream does not make omega an issuer.
echo "[demo] issuance routes stay disabled (no local CA)"
for path in /v1/svid /v1/svid/jwt /v1/token/exchange; do
	code="$(curl -sS -o /dev/null -w '%{http_code}' \
		-X POST "http://127.0.0.1:$SERVER_PORT$path" \
		-H 'content-type: application/json' -d '{}')"
	assert_eq "POST $path" "$code" "501"
done

echo "[demo] rotating the upstream to generation b — omega is not told"
cp "$DEMO_DIR/bundle-b.pem" "$DEMO_DIR/upstream-bundle.pem"
cp "$DEMO_DIR/jwks-b.json" "$DEMO_DIR/upstream-jwks.json"
wait_for_served_bundle "$DEMO_DIR/bundle-b.pem"
echo "[demo]   ok: /v1/bundle == upstream generation b, with no signal sent"

# The JWKS arrives on its own stream and can land after the anchors.
for _ in $(seq 1 100); do
	[[ "$(curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/jwt/bundle" | kids)" == "$KIDS_B" ]] && break
	sleep 0.1
done
assert_eq "/v1/jwt/bundle followed the signing-key rotation" \
	"$(curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/jwt/bundle" | kids)" "$KIDS_B"

SEQ_AFTER_ROTATION="$(sequence)"
if (( SEQ_AFTER_ROTATION < 2 )); then
	echo "[demo] FAIL: spiffe_sequence is $SEQ_AFTER_ROTATION after a rotation, want >= 2"
	exit 1
fi
echo "[demo]   ok: spiffe_sequence advanced to $SEQ_AFTER_ROTATION"

# Fail-closed on the live transport too: an upstream that stops serving the
# domain must not disarm the control plane. Serving anchors that are merely
# old beats serving none.
echo "[demo] upstream stops publishing the trust domain (fail-closed)"
: >"$DEMO_DIR/upstream-bundle.pem"
wait_for_log "keeping previous" "$DEMO_DIR/server.log"
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/served.pem"
if ! cmp -s "$DEMO_DIR/served.pem" "$DEMO_DIR/bundle-b.pem"; then
	echo "[demo] FAIL: an unusable upstream update replaced the previously-good anchors"
	exit 1
fi
echo "[demo]   ok: still serving generation b"
assert_eq "spiffe_sequence did not advance" "$(sequence)" "$SEQ_AFTER_ROTATION"

echo "[demo] success — consumed an upstream rotation with no operator in the loop"
