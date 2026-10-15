#!/usr/bin/env bash
# run-demo.sh boots a tiny mock AWS Private CA and an omega server
# wired to it via --ca-backend=aws-pca. It then:
#
#   1. fetches the trust bundle (must hold the mock's issuing CA and
#      its root);
#   2. submits a CSR through POST /v1/svid and gets back an SVID
#      signed by the mock's issuing CA (proving omega delegated
#      signing and polled through RequestInProgressException);
#   3. asserts the issued leaf chains to the bundle and carries the
#      requested SPIFFE ID as its URI SAN.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-ca-aws-pca-demo}"
SERVER_PORT="${SERVER_PORT:-18393}"
PCA_PORT="${PCA_PORT:-18392}"
CA_ARN="${CA_ARN:-arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/demo}"
TRUST_DOMAIN="${TRUST_DOMAIN:-omega.demo}"
SPIFFE_ID="${SPIFFE_ID:-spiffe://omega.demo/example/web}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/pca.pid" ]] && kill "$(cat "$DEMO_DIR/pca.pid")" 2>/dev/null || true
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

echo "[demo] building mock-pca"
go -C "$EXAMPLE_DIR/mock-pca" build -o "$DEMO_DIR/mock-pca" .

echo "[demo] starting mock AWS Private CA on http://127.0.0.1:$PCA_PORT"
"$DEMO_DIR/mock-pca" --addr "127.0.0.1:$PCA_PORT" --ca-arn "$CA_ARN" >"$DEMO_DIR/pca.log" 2>&1 &
echo $! >"$DEMO_DIR/pca.pid"
wait_for_url "http://127.0.0.1:$PCA_PORT/healthz" "$DEMO_DIR/pca.log"

# omega reads AWS credentials from the standard chain. Pin it to
# static demo keys and keep any real profile, SSO cache or instance
# metadata out of the picture.
echo "[demo] starting omega server on :$SERVER_PORT (ca-backend=aws-pca)"
env AWS_ACCESS_KEY_ID=AKIDDEMO AWS_SECRET_ACCESS_KEY=demo-secret \
	AWS_SESSION_TOKEN= AWS_PROFILE= \
	AWS_CONFIG_FILE="$DEMO_DIR/aws-config" AWS_SHARED_CREDENTIALS_FILE="$DEMO_DIR/aws-credentials" \
	AWS_EC2_METADATA_DISABLED=true \
	omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN" \
	--data-dir "$DEMO_DIR/server" \
	--ca-backend aws-pca \
	--ca-aws-pca-arn "$CA_ARN" \
	--ca-aws-pca-endpoint "http://127.0.0.1:$PCA_PORT" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_for_url "http://127.0.0.1:$SERVER_PORT/healthz" "$DEMO_DIR/server.log"

# 1. Trust bundle = mock issuing CA + its root.
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/bundle" >"$DEMO_DIR/bundle.pem"
BUNDLE_CERTS=$(grep -c 'BEGIN CERTIFICATE' "$DEMO_DIR/bundle.pem" || true)
if [[ "$BUNDLE_CERTS" != "2" ]]; then
	echo "[demo] FAIL: /v1/bundle holds $BUNDLE_CERTS certificates, want the issuing CA and its root"
	exit 1
fi
BUNDLE_CN=$(openssl x509 -in "$DEMO_DIR/bundle.pem" -noout -subject 2>/dev/null | head -1)
if ! echo "$BUNDLE_CN" | grep -q 'Mock PCA Issuing CA'; then
	echo "[demo] FAIL: bundle does not start with the mock issuing CA (got: $BUNDLE_CN)"
	exit 1
fi

# Register the SPIFFE namespace.
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/domains" \
	-H 'content-type: application/json' \
	-d "{\"name\":\"example\"}" >/dev/null

# 2. Generate a workload keypair + CSR and submit. The CSR carries no
# SAN; omega passes the SPIFFE ID to AWS through ApiPassthrough.
openssl ecparam -name prime256v1 -genkey -noout -out "$DEMO_DIR/wl.key" 2>/dev/null
openssl req -new -key "$DEMO_DIR/wl.key" -subj "/CN=omega-demo-workload" -out "$DEMO_DIR/wl.csr" 2>/dev/null
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
	echo "[demo] FAIL: leaf does not chain to the mock PCA bundle"
	sed 's/^/       /' "$DEMO_DIR/verify.log"
	exit 1
fi

# 3b. The leaf must carry the SPIFFE ID as a URI SAN.
if ! openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -text 2>/dev/null | grep -q "URI:$SPIFFE_ID"; then
	echo "[demo] FAIL: leaf does not carry the requested SPIFFE ID URI SAN"
	exit 1
fi

# 3c. The leaf's issuer must be the mock issuing CA, not omega's local CA.
ISSUER_CN=$(openssl x509 -in "$DEMO_DIR/leaf.pem" -noout -issuer 2>/dev/null)
if ! echo "$ISSUER_CN" | grep -q 'Mock PCA Issuing CA'; then
	echo "[demo] FAIL: leaf issuer is not the mock issuing CA (got: $ISSUER_CN)"
	exit 1
fi

# 3d. omega must have polled through the in-progress answer.
if [[ "$(grep -c 'ACMPrivateCA.GetCertificate$' "$DEMO_DIR/pca.log" || true)" -lt 2 ]]; then
	echo "[demo] FAIL: omega did not poll GetCertificate past RequestInProgressException"
	exit 1
fi

echo "[demo] success"
echo "[demo]   bundle:      $BUNDLE_CN (+ root)"
echo "[demo]   leaf issuer: $ISSUER_CN"
echo "[demo]   spiffe_id:   $SPIFFE_ID"
