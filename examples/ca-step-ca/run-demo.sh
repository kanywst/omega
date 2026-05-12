#!/usr/bin/env bash
# run-demo.sh: prove that omega's step-ca backend delegates X.509-SVID
# signing to an upstream step-ca instance, with a real one-time-token
# round-trip on the wire.
#
# Sequence:
#   1. Generate a fresh provisioner ECDSA keypair (the demo's only
#      shared secret between omega and the mock).
#   2. Boot mock-step-ca with the provisioner's public JWK so it can
#      verify omega's OTT signatures.
#   3. Boot omega server with the provisioner's private JWK and
#      `--ca-backend=step-ca` pointing at the mock.
#   4. Fetch /v1/bundle and assert it equals the mock's root.
#   5. Submit a workload CSR through POST /v1/svid; assert the issued
#      leaf chains to the bundle, carries the SPIFFE ID URI SAN, and
#      is issued by the mock step-ca CA (not omega's local default).

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-ca-step-ca-demo}"
SERVER_PORT="${SERVER_PORT:-18490}"
STEP_PORT="${STEP_PORT:-18491}"
PROVISIONER="${PROVISIONER:-omega}"
TRUST_DOMAIN="${TRUST_DOMAIN:-omega.demo}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://omega.demo/example/web}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid"  ]] && kill "$(cat "$DEMO_DIR/server.pid")"  2>/dev/null || true
	[[ -f "$DEMO_DIR/step-ca.pid" ]] && kill "$(cat "$DEMO_DIR/step-ca.pid")" 2>/dev/null || true
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

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[demo] minting provisioner keypair"
# Use a small inline Go program to emit a fresh ECDSA private JWK and
# its matching public JWK. Run from the example dir via `go -C` so
# the omega module's go.mod (the source of go-jose) is in scope.
# Keeping the key minting inline avoids a third binary in the example
# and means the demo is hermetic - the provisioner key never
# persists past `make down`.
go -C "$EXAMPLE_DIR" run ./keygen.go \
	-out-priv "$DEMO_DIR/provisioner.priv.jwk" \
	-out-pub  "$DEMO_DIR/provisioner.pub.jwk"

echo "[demo] building mock-step-ca"
go -C "$EXAMPLE_DIR/mock-step-ca" build -o "$DEMO_DIR/mock-step-ca" .

echo "[demo] starting mock step-ca on http://127.0.0.1:$STEP_PORT"
"$DEMO_DIR/mock-step-ca" \
	--addr "127.0.0.1:$STEP_PORT" \
	--provisioner "$PROVISIONER" \
	--provisioner-pub-jwk "$DEMO_DIR/provisioner.pub.jwk" \
	>"$DEMO_DIR/step-ca.log" 2>&1 &
echo $! >"$DEMO_DIR/step-ca.pid"
wait_for_url "http://127.0.0.1:$STEP_PORT/healthz" "$DEMO_DIR/step-ca.log"

echo "[demo] starting omega server on :$SERVER_PORT (ca-backend=step-ca)"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN" \
	--data-dir "$DEMO_DIR/server" \
	--ca-backend step-ca \
	--ca-step-ca-url "http://127.0.0.1:$STEP_PORT" \
	--ca-step-ca-provisioner "$PROVISIONER" \
	--ca-step-ca-provisioner-key-file "$DEMO_DIR/provisioner.priv.jwk" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_for_url "http://127.0.0.1:$SERVER_PORT/healthz" "$DEMO_DIR/server.log"

# 1. Bundle must equal the mock step-ca's CA.
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/bundle.pem"
BUNDLE_CN=$(openssl x509 -in "$DEMO_DIR/bundle.pem" -noout -subject | head -1)
if ! echo "$BUNDLE_CN" | grep -q 'Mock step-ca Root CA'; then
	echo "[demo] FAIL: bundle is not the mock step-ca CA (got: $BUNDLE_CN)"
	exit 1
fi

# Register the SPIFFE namespace.
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/domains" \
	-H 'content-type: application/json' \
	-d '{"name":"example"}' >/dev/null

# 2. Generate a workload keypair + CSR and submit through POST /v1/svid.
openssl ecparam -name prime256v1 -genkey -noout -out "$DEMO_DIR/wl.key"
# openssl `-subj` splits on '/'; keep CN neutral so a SPIFFE URI does
# not collide with the field separator. The SPIFFE ID flows in the
# spiffe_id JSON field, not the CSR.
openssl req -new -key "$DEMO_DIR/wl.key" -subj "/CN=omega-step-ca-demo-workload" -out "$DEMO_DIR/wl.csr"
# Build the request body entirely in Python with the shell values
# delivered through argv, so a path or SPIFFE ID that happened to
# contain a quote or backslash cannot break out of the JSON string.
PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({'spiffe_id': sys.argv[1], 'csr': open(sys.argv[2]).read()}))
" "$SPIFFE_ID" "$DEMO_DIR/wl.csr")
SVID_JSON=$(curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/svid" \
	-H 'content-type: application/json' \
	-d "$PAYLOAD")
echo "$SVID_JSON" | python3 -c "import sys,json; sys.stdout.write(json.load(sys.stdin)['svid'])" >"$DEMO_DIR/leaf.pem"

# 3a. Leaf must chain to the bundle.
if ! openssl verify -CAfile "$DEMO_DIR/bundle.pem" "$DEMO_DIR/leaf.pem" >"$DEMO_DIR/verify.log" 2>&1; then
	echo "[demo] FAIL: leaf does not chain to step-ca CA"
	cat "$DEMO_DIR/verify.log" | sed 's/^/       /'
	exit 1
fi
# 3b. Leaf must carry the SPIFFE ID URI SAN. mock-step-ca copied it
# from the OTT, so this also proves the OTT flowed correctly.
if ! openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -text | grep -q "URI:$SPIFFE_ID"; then
	echo "[demo] FAIL: leaf does not carry the SPIFFE ID URI SAN"
	openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -text | grep -A2 'Subject Alternative Name' | sed 's/^/       /'
	exit 1
fi
# 3c. Issuer must be the mock step-ca CA, not omega's local default.
ISSUER_CN=$(openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -issuer)
if ! echo "$ISSUER_CN" | grep -q 'Mock step-ca Root CA'; then
	echo "[demo] FAIL: leaf issuer is not the mock step-ca CA (got: $ISSUER_CN)"
	exit 1
fi

echo "[demo] success"
echo "[demo]   bundle:      $BUNDLE_CN"
echo "[demo]   leaf issuer: $ISSUER_CN"
echo "[demo]   spiffe_id:   $SPIFFE_ID"
