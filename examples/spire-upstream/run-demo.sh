#!/usr/bin/env bash
# run-demo.sh: prove the spire-upstream identity source consumes an
# upstream SPIFFE trust domain, refuses to issue, and follows an
# upstream rotation on SIGHUP without a restart.
#
# The regression this guards is silent and time-delayed: upstream SPIRE
# rotates its CA and JWT signing key on its own schedule, and a control
# plane that read the bundle once at boot keeps serving anchors that no
# longer cover freshly-issued upstream SVIDs. Nothing surfaces at boot
# or in a health check, and agents cache whatever the control plane
# hands them, so the staleness fans out instead of self-correcting.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-spire-upstream-demo}"
UPSTREAM_PORT="${UPSTREAM_PORT:-18890}"
SERVER_PORT="${SERVER_PORT:-18891}"
TRUST_DOMAIN="${TRUST_DOMAIN:-upstream.demo}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
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

# Reloads are asynchronous: SIGHUP is handled off the request path, so
# poll the server log for the outcome rather than sleeping a guess.
wait_for_log() {
	local pattern="$1" log="$2"
	for _ in $(seq 1 50); do
		if grep -q "$pattern" "$log"; then
			return 0
		fi
		sleep 0.1
	done
	echo "[demo] FAIL: did not observe \"$pattern\" in the server log within 5s"
	echo "[demo] log tail ($log):"; tail -20 "$log" | sed 's/^/       /'
	exit 1
}

sequence() {
	curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/spiffe-bundle" |
		python3 -c 'import sys, json; print(json.load(sys.stdin)["spiffe_sequence"])'
}

# Sorted kid list of the JWKS on stdin, so a rotation is comparable as
# a plain string regardless of key order.
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

# mint_upstream_generation boots a throwaway built-in omega, harvests
# its trust bundle and JWKS, and shuts it down. It stands in for an
# upstream SPIRE / Istio trust domain: omega only ever consumes this
# material, so any issuer that emits a SPIFFE bundle plus an EC P-256
# JWKS would do.
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

echo "[demo] minting two upstream generations (a CA rotation)"
mint_upstream_generation a
mint_upstream_generation b

KIDS_A="$(kids <"$DEMO_DIR/jwks-a.json")"
KIDS_B="$(kids <"$DEMO_DIR/jwks-b.json")"
if [[ "$KIDS_A" == "$KIDS_B" ]]; then
	echo "[demo] FAIL: both generations share the same signing kid; the fixture is not a rotation"
	exit 1
fi
if cmp -s "$DEMO_DIR/bundle-a.pem" "$DEMO_DIR/bundle-b.pem"; then
	echo "[demo] FAIL: both generations share the same CA; the fixture is not a rotation"
	exit 1
fi
echo "[demo]   generation a kids: $KIDS_A"
echo "[demo]   generation b kids: $KIDS_B"

# The live files are what omega reads; rotation is a swap of these.
cp "$DEMO_DIR/bundle-a.pem" "$DEMO_DIR/live-bundle.pem"
cp "$DEMO_DIR/jwks-a.json" "$DEMO_DIR/live-jwks.json"

echo "[demo] starting omega in spire-upstream mode on :$SERVER_PORT"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--identity-source spire-upstream \
	--trust-domain "$TRUST_DOMAIN" \
	--identity-source-bundle "$DEMO_DIR/live-bundle.pem" \
	--identity-source-jwt-bundle "$DEMO_DIR/live-jwks.json" \
	--data-dir "$DEMO_DIR/server" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
SERVER_PID="$(cat "$DEMO_DIR/server.pid")"
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

# ADR 0007: this source runs no CA. Issuance must report 501 rather
# than quietly minting an identity the upstream never authorised.
echo "[demo] issuance routes stay disabled (no local CA)"
for path in /v1/svid /v1/svid/jwt /v1/token/exchange; do
	code="$(curl -sS -o /dev/null -w '%{http_code}' \
		-X POST "http://127.0.0.1:$SERVER_PORT$path" \
		-H 'content-type: application/json' -d '{}')"
	assert_eq "POST $path" "$code" "501"
done

# A rotation that lands a corrupt file must not disarm the control
# plane: serving no anchors breaks every handshake, which is strictly
# worse than serving anchors that are merely old.
echo "[demo] SIGHUP with a corrupt bundle (fail-closed)"
printf -- '-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n' \
	>"$DEMO_DIR/live-bundle.pem"
kill -HUP "$SERVER_PID"
wait_for_log "keeping previous" "$DEMO_DIR/server.log"
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/served.pem"
if ! cmp -s "$DEMO_DIR/served.pem" "$DEMO_DIR/bundle-a.pem"; then
	echo "[demo] FAIL: a rejected reload replaced the previously-good anchors"
	exit 1
fi
echo "[demo]   ok: still serving generation a after a rejected reload"
assert_eq "spiffe_sequence did not advance" "$(sequence)" "1"

echo "[demo] rotating the upstream to generation b, then SIGHUP"
cp "$DEMO_DIR/bundle-b.pem" "$DEMO_DIR/live-bundle.pem"
cp "$DEMO_DIR/jwks-b.json" "$DEMO_DIR/live-jwks.json"
kill -HUP "$SERVER_PID"
wait_for_log "trust material reloaded" "$DEMO_DIR/server.log"

curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/served.pem"
if ! cmp -s "$DEMO_DIR/served.pem" "$DEMO_DIR/bundle-b.pem"; then
	echo "[demo] FAIL: /v1/bundle still serves the pre-rotation anchors"
	exit 1
fi
echo "[demo]   ok: /v1/bundle == upstream generation b"
assert_eq "/v1/jwt/bundle follows the signing-key rotation" \
	"$(curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/jwt/bundle" | kids)" "$KIDS_B"
assert_eq "spiffe_sequence advanced" "$(sequence)" "2"

# Peers use spiffe_sequence to decide whether to re-read a bundle, so a
# signal that rotated nothing must not look like a rotation.
echo "[demo] SIGHUP with unchanged material (no-op)"
kill -HUP "$SERVER_PID"
wait_for_log "trust material unchanged" "$DEMO_DIR/server.log"
assert_eq "spiffe_sequence stayed put" "$(sequence)" "2"

echo "[demo] success — consumed an upstream rotation without a restart"
