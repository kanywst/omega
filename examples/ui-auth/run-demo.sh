#!/usr/bin/env bash
# run-demo.sh: a person signs in to the web UI and manages Cedar policies.
#
#   1. issues a demo CA, the control plane's TLS certificate and the UI's
#      X.509-SVID (spiffe://omega.demo/platform/ui);
#   2. boots the mock OIDC IdP (examples/oidc-federation/mock-idp), which
#      signs in alice at /authorize without a login page;
#   3. boots omega with TLS, --require-auth, --oidc-idp for the mock IdP,
#      --ui-proxy for the UI's SPIFFE ID, and alice's human SPIFFE ID as
#      the only --domain-root-admin;
#   4. builds and starts the UI with sign-in configured;
#   5. drive.py signs alice in (authorization code + PKCE), then creates,
#      updates and deletes a policy through the UI's /api/omega routes and
#      checks the CSRF and origin checks, the 412 on a stale ETag, the
#      audit rows (actor alice, via the UI) and sign-out.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-ui-auth-demo}"
SERVER_PORT="${SERVER_PORT:-18280}"
IDP_PORT="${IDP_PORT:-18281}"
UI_PORT="${UI_PORT:-18282}"
UI2_PORT="${UI2_PORT:-18283}"
TRUST_DOMAIN=omega.demo
UI_ID="spiffe://$TRUST_DOMAIN/platform/ui"
ALICE="spiffe://$TRUST_DOMAIN/humans/demo-idp/alice"

cleanup() {
	for p in ui ui2 server mock-idp; do
		[[ -f "$DEMO_DIR/$p.pid" ]] && kill "$(cat "$DEMO_DIR/$p.pid")" 2>/dev/null || true
	done
}
trap cleanup EXIT

fail_with_logs() {
	echo "[demo] FAIL: $1" >&2
	for log in server mock-idp ui ui2; do
		[[ -f "$DEMO_DIR/$log.log" ]] && { echo "[demo] $log.log tail:" >&2; tail -20 "$DEMO_DIR/$log.log" | sed 's/^/       /' >&2; }
	done
	exit 1
}

# wait_up URL [CURL-ARGS...]
wait_up() {
	for _ in $(seq 1 300); do
		curl -fsS -o /dev/null "${@:2}" "$1" 2>/dev/null && return 0
		sleep 0.1
	done
	fail_with_logs "$1 did not come up"
}

# issue NAME [URI-SAN] [IP-SAN]: a leaf signed by the demo CA.
issue() {
	local ext="$DEMO_DIR/pki/$1.ext"
	{
		echo "basicConstraints=CA:FALSE"
		echo "keyUsage=digitalSignature"
		echo "extendedKeyUsage=serverAuth,clientAuth"
		if [[ -n "${2:-}" ]]; then echo "subjectAltName=URI:$2"; fi
		if [[ -n "${3:-}" ]]; then echo "subjectAltName=IP:$3"; fi
	} >"$ext"
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
		-keyout "$DEMO_DIR/pki/$1.key" -out "$DEMO_DIR/pki/$1.csr" 2>/dev/null
	openssl x509 -req -in "$DEMO_DIR/pki/$1.csr" -CA "$DEMO_DIR/pki/ca.pem" -CAkey "$DEMO_DIR/pki/ca.key" \
		-CAcreateserial -days 1 -extfile "$ext" -out "$DEMO_DIR/pki/$1.pem" 2>/dev/null
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/pki"
EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"

echo "[demo] building omega and the mock IdP"
go -C "$REPO_ROOT" build -o "$DEMO_DIR/omega" ./cmd/omega
go -C "$REPO_ROOT" build -o "$DEMO_DIR/mock-idp" ./examples/oidc-federation/mock-idp

echo "[demo] issuing a demo CA, the server certificate and the UI's X.509-SVID"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=demo-ca" -days 1 \
	-keyout "$DEMO_DIR/pki/ca.key" -out "$DEMO_DIR/pki/ca.pem" 2>/dev/null
issue server "" 127.0.0.1
issue ui "$UI_ID"

UI_URL="http://127.0.0.1:$UI_PORT"
ISSUER="http://127.0.0.1:$IDP_PORT"

echo "[demo] starting the mock IdP on $ISSUER"
"$DEMO_DIR/mock-idp" --addr "127.0.0.1:$IDP_PORT" --client-id omega-ui \
	--redirect-uri "$UI_URL/api/auth/callback" --login-sub alice@example.com --login-username alice --id-token-ttl 65s \
	>"$DEMO_DIR/mock-idp.log" 2>&1 &
echo $! >"$DEMO_DIR/mock-idp.pid"
wait_up "$ISSUER/.well-known/openid-configuration"

echo "[demo] starting omega on :$SERVER_PORT (--require-auth, --ui-proxy $UI_ID)"
"$DEMO_DIR/omega" server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN" \
	--data-dir "$DEMO_DIR/server" \
	--tls-cert "$DEMO_DIR/pki/server.pem" --tls-key "$DEMO_DIR/pki/server.key" \
	--client-ca "$DEMO_DIR/pki/ca.pem" --require-auth \
	--oidc-idp "name=demo-idp,issuer=$ISSUER,audience=omega-ui,template=spiffe://$TRUST_DOMAIN/humans/{idp}/{preferred_username}" \
	--domain-root-admin "$ALICE" \
	--ui-proxy "$UI_ID" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_up "https://127.0.0.1:$SERVER_PORT/healthz" --cacert "$DEMO_DIR/pki/ca.pem" \
	--cert "$DEMO_DIR/pki/ui.pem" --key "$DEMO_DIR/pki/ui.key"

echo "[demo] building the UI"
cd "$REPO_ROOT/ui"
[[ -d node_modules ]] || npm ci --no-audit --no-fund >"$DEMO_DIR/npm.log" 2>&1 || fail_with_logs "npm ci (see $DEMO_DIR/npm.log)"
npm run build >"$DEMO_DIR/build.log" 2>&1 || { tail -30 "$DEMO_DIR/build.log"; fail_with_logs "next build"; }
# The standalone server serves the pages' assets from beside it, so the
# UI can also be opened in a browser while the demo runs.
rm -rf .next/standalone/.next/static && cp -R .next/static .next/standalone/.next/static

# Two replicas of one UI, sharing the login secret.
LOGIN_SECRET="$(openssl rand -hex 32)"
start_ui() {
	PORT="$1" HOSTNAME=127.0.0.1 \
		OMEGA_API="https://127.0.0.1:$SERVER_PORT" \
		OMEGA_API_CA="$DEMO_DIR/pki/ca.pem" \
		OMEGA_API_CLIENT_CERT="$DEMO_DIR/pki/ui.pem" \
		OMEGA_API_CLIENT_KEY="$DEMO_DIR/pki/ui.key" \
		OMEGA_UI_URL="$UI_URL" \
		OMEGA_UI_OIDC_ISSUER="$ISSUER" \
		OMEGA_UI_OIDC_CLIENT_ID=omega-ui \
		OMEGA_UI_OIDC_IDP=demo-idp \
		OMEGA_UI_LOGIN_SECRET="$LOGIN_SECRET" \
		node .next/standalone/server.js >"$DEMO_DIR/$2.log" 2>&1 &
	echo $! >"$DEMO_DIR/$2.pid"
	wait_up "http://127.0.0.1:$1/api/auth/session"
}
echo "[demo] starting the UI on $UI_URL and a second replica on :$UI2_PORT"
start_ui "$UI_PORT" ui
start_ui "$UI2_PORT" ui2

echo "[demo] signing alice in and managing a policy through the UI"
python3 "$EXAMPLE_DIR/drive.py" "$UI_URL" "$ALICE" "$UI_ID" "http://127.0.0.1:$UI2_PORT" || fail_with_logs "drive.py"

echo "[demo] success"
