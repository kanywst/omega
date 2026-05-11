#!/usr/bin/env bash
# run-demo.sh drives a full OIDC IdP federation round-trip:
#
#   1. boots a tiny in-process OIDC IdP (cmd/mock-idp) that signs
#      ES256 ID tokens against a freshly generated key,
#   2. boots an omega server wired with --oidc-idp pointing at the
#      mock IdP,
#   3. asks the mock IdP to sign a representative human ID token
#      (sub=alice@example.com, preferred_username=alice),
#   4. POSTs that token to omega's /v1/oidc/exchange and decodes
#      the omega JWT-SVID returned,
#   5. asserts the SPIFFE ID was rendered correctly and that the
#      omega JWT-SVID carries an `act` claim recording the upstream
#      IdP.
#
# Used by `make demo` and by CI as a smoke test for the OIDC
# federation surface.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-oidc-federation-demo}"
SERVER_PORT="${SERVER_PORT:-18180}"
IDP_PORT="${IDP_PORT:-18181}"
TRUST_DOMAIN="${TRUST_DOMAIN:-omega.demo}"
IDP_NAME="${IDP_NAME:-demo-idp}"
IDP_AUD="${IDP_AUD:-omega-clients}"
TARGET_AUD="${TARGET_AUD:-target-api}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid"   ]] && kill "$(cat "$DEMO_DIR/server.pid")"   2>/dev/null || true
	[[ -f "$DEMO_DIR/mock-idp.pid" ]] && kill "$(cat "$DEMO_DIR/mock-idp.pid")" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[demo] building mock-idp"
go -C "$EXAMPLE_DIR/mock-idp" build -o "$DEMO_DIR/mock-idp" .

echo "[demo] starting mock IdP on http://127.0.0.1:$IDP_PORT"
"$DEMO_DIR/mock-idp" --addr "127.0.0.1:$IDP_PORT" >"$DEMO_DIR/mock-idp.log" 2>&1 &
echo $! >"$DEMO_DIR/mock-idp.pid"

# Wait for discovery to serve.
for _ in $(seq 1 30); do
	if curl -fsS "http://127.0.0.1:$IDP_PORT/.well-known/openid-configuration" >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done

ISSUER="http://127.0.0.1:$IDP_PORT"
TEMPLATE="spiffe://$TRUST_DOMAIN/humans/{idp}/{preferred_username}"

echo "[demo] starting omega server on :$SERVER_PORT (idp=$IDP_NAME issuer=$ISSUER)"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain "$TRUST_DOMAIN" \
	--data-dir "$DEMO_DIR/server" \
	--oidc-idp "name=$IDP_NAME,issuer=$ISSUER,audience=$IDP_AUD,template=$TEMPLATE" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"

# Wait for omega health.
for _ in $(seq 1 50); do
	if curl -fsS "http://127.0.0.1:$SERVER_PORT/healthz" >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done

echo "[demo] asking the mock IdP to sign an ID token for alice"
ID_TOKEN_JSON=$(curl -fsS -X POST "http://127.0.0.1:$IDP_PORT/sign" \
	-H 'content-type: application/json' \
	-d '{
		"sub": "alice@example.com",
		"aud": ["'"$IDP_AUD"'"],
		"preferred_username": "alice",
		"email": "alice@example.com",
		"name": "Alice Example"
	}')
ID_TOKEN=$(echo "$ID_TOKEN_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin)["id_token"])')

echo "[demo] exchanging the ID token at /v1/oidc/exchange"
EXCHANGE_HTTP=$(curl -sS -o "$DEMO_DIR/exchange.json" -w '%{http_code}' \
	-X POST "http://127.0.0.1:$SERVER_PORT/v1/oidc/exchange" \
	-H 'content-type: application/json' \
	-d '{
		"idp":      "'"$IDP_NAME"'",
		"id_token": "'"$ID_TOKEN"'",
		"audience": ["'"$TARGET_AUD"'"]
	}')
if [[ "$EXCHANGE_HTTP" != "200" ]]; then
	echo "[demo] FAIL: /v1/oidc/exchange returned HTTP $EXCHANGE_HTTP"
	echo "       body: $(cat "$DEMO_DIR/exchange.json")"
	echo "       server.log tail:"; tail -20 "$DEMO_DIR/server.log" | sed 's/^/       /'
	exit 1
fi
EXCHANGE_JSON=$(cat "$DEMO_DIR/exchange.json")

SPIFFE_ID=$(echo "$EXCHANGE_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin)["spiffe_id"])')
ACCESS_TOKEN=$(echo "$EXCHANGE_JSON" | python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')

EXPECTED_ID="spiffe://$TRUST_DOMAIN/humans/$IDP_NAME/alice"
if [[ "$SPIFFE_ID" != "$EXPECTED_ID" ]]; then
	echo "[demo] FAIL: rendered SPIFFE ID mismatch"
	echo "       got:  $SPIFFE_ID"
	echo "       want: $EXPECTED_ID"
	exit 1
fi

# Decode the JWT-SVID payload (no signature verification — that is
# what omega already did when issuing the token; the demo only needs
# to read the claims back).
ACT=$(JWT="$ACCESS_TOKEN" python3 -c 'import os,base64,json
tok=os.environ["JWT"].strip()
seg=tok.split(".")[1]
seg+="="*((4-len(seg)%4)%4)
claims=json.loads(base64.urlsafe_b64decode(seg))
print(json.dumps(claims.get("act",{}),sort_keys=True))')

EXPECTED_ACT='{"idp": "'"$IDP_NAME"'", "iss": "'"$ISSUER"'", "kind": "oidc-idp", "sub": "alice@example.com"}'
# Normalise both for stable comparison.
ACT_NORM=$(echo "$ACT"           | python3 -c 'import sys,json; print(json.dumps(json.loads(sys.stdin.read()), sort_keys=True))')
WANT_NORM=$(echo "$EXPECTED_ACT" | python3 -c 'import sys,json; print(json.dumps(json.loads(sys.stdin.read()), sort_keys=True))')
if [[ "$ACT_NORM" != "$WANT_NORM" ]]; then
	echo "[demo] FAIL: act claim mismatch"
	echo "       got:  $ACT_NORM"
	echo "       want: $WANT_NORM"
	exit 1
fi

echo "[demo] success"
echo "[demo]   rendered spiffe_id: $SPIFFE_ID"
echo "[demo]   act claim:          $ACT_NORM"
