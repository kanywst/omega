#!/usr/bin/env bash
# run-demo.sh boots a tiny mock Vault PKI engine and an omega
# server wired to it via --ca-backend=vault-pki. It then:
#
#   1. fetches the trust bundle (must equal the mock's CA);
#   2. submits a CSR through POST /v1/svid and gets back an SVID
#      signed by the mock's CA (proving omega delegated signing,
#      did not self-sign);
#   3. asserts the issued leaf chains to the bundle openssl
#      reports the same SAN URI as the requested SPIFFE ID.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-ca-vault-pki-demo}"
SERVER_PORT="${SERVER_PORT:-18390}"
VAULT_PORT="${VAULT_PORT:-18391}"
VAULT_TOKEN="${VAULT_TOKEN:-demo-token}"
VAULT_MOUNT="${VAULT_MOUNT:-pki}"
VAULT_ROLE="${VAULT_ROLE:-omega}"
TRUST_DOMAIN="${TRUST_DOMAIN:-omega.demo}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://omega.demo/example/web}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/vault.pid"  ]] && kill "$(cat "$DEMO_DIR/vault.pid")"  2>/dev/null || true
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

echo "[demo] building mock-vault"
go -C "$EXAMPLE_DIR/mock-vault" build -o "$DEMO_DIR/mock-vault" .

echo "[demo] starting mock Vault on http://127.0.0.1:$VAULT_PORT"
"$DEMO_DIR/mock-vault" \
	--addr "127.0.0.1:$VAULT_PORT" \
	--mount "$VAULT_MOUNT" \
	--role "$VAULT_ROLE" \
	--token "$VAULT_TOKEN" \
	>"$DEMO_DIR/vault.log" 2>&1 &
echo $! >"$DEMO_DIR/vault.pid"
wait_for_url "http://127.0.0.1:$VAULT_PORT/healthz" "$DEMO_DIR/vault.log"

echo "[demo] starting omega server on :$SERVER_PORT (ca-backend=vault-pki)"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN" \
	--data-dir "$DEMO_DIR/server" \
	--ca-backend vault-pki \
	--ca-vault-pki-addr "http://127.0.0.1:$VAULT_PORT" \
	--ca-vault-pki-token "$VAULT_TOKEN" \
	--ca-vault-pki-mount "$VAULT_MOUNT" \
	--ca-vault-pki-role "$VAULT_ROLE" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_for_url "http://127.0.0.1:$SERVER_PORT/healthz" "$DEMO_DIR/server.log"

# 1. Trust bundle = mock Vault's CA.
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/bundle.pem"
if ! grep -q 'BEGIN CERTIFICATE' "$DEMO_DIR/bundle.pem"; then
	echo "[demo] FAIL: /v1/bundle did not return PEM"
	exit 1
fi
BUNDLE_CN=$(openssl x509 -in "$DEMO_DIR/bundle.pem" -noout -subject 2>/dev/null | head -1)
if ! echo "$BUNDLE_CN" | grep -q 'Mock Vault Root CA'; then
	echo "[demo] FAIL: bundle is not the mock Vault CA (got: $BUNDLE_CN)"
	exit 1
fi

# Register the SPIFFE namespace.
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/domains" \
	-H 'content-type: application/json' \
	-d "{\"name\":\"example\"}" >/dev/null

# 2. Generate a workload keypair + CSR and submit.
openssl ecparam -name prime256v1 -genkey -noout -out "$DEMO_DIR/wl.key" 2>/dev/null
# openssl `-subj` uses '/' as the field separator, so a SPIFFE URI
# in the CN would split. omega does not consume the CN anyway (the
# SPIFFE ID is the spiffe_id JSON field, the CSR is only a key
# carrier), so use a neutral CN.
openssl req -new -key "$DEMO_DIR/wl.key" -subj "/CN=omega-demo-workload" -out "$DEMO_DIR/wl.csr" 2>/dev/null
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

# 3a. The leaf must chain to the bundle.
if ! openssl verify -CAfile "$DEMO_DIR/bundle.pem" "$DEMO_DIR/leaf.pem" >"$DEMO_DIR/verify.log" 2>&1; then
	echo "[demo] FAIL: leaf does not chain to vault CA"
	cat "$DEMO_DIR/verify.log" | sed 's/^/       /'
	exit 1
fi

# 3b. The leaf must carry the SPIFFE ID as a URI SAN. openssl
# prints SANs in the text representation; grep is enough here.
if ! openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -text 2>/dev/null | grep -q "URI:$SPIFFE_ID"; then
	echo "[demo] FAIL: leaf does not carry the requested SPIFFE ID URI SAN"
	openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -text 2>/dev/null | grep -A2 'Subject Alternative Name' | sed 's/^/       /'
	exit 1
fi

# 3c. The leaf must NOT be self-signed by omega (the Subject of
# the issuer must be the mock Vault Root CA, not omega's local CA).
ISSUER_CN=$(openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -issuer 2>/dev/null)
if ! echo "$ISSUER_CN" | grep -q 'Mock Vault Root CA'; then
	echo "[demo] FAIL: leaf issuer is not the mock Vault CA (got: $ISSUER_CN)"
	exit 1
fi

echo "[demo] success"
echo "[demo]   bundle:      $BUNDLE_CN"
echo "[demo]   leaf issuer: $ISSUER_CN"
echo "[demo]   spiffe_id:   $SPIFFE_ID"
