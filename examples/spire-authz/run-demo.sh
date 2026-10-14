#!/usr/bin/env bash
# run-demo.sh: authorization and audit on top of a real SPIRE deployment.
#
# SPIRE is the identity issuer and stays that way. Omega consumes SPIRE's
# trust domain and adds what SPIRE leaves out of scope:
#
#   * callers authenticate to Omega with their SPIRE X.509-SVIDs;
#   * Cedar decides by SPIRE path (principal in Domain::"payments");
#   * people come from an identity provider over SCIM, and a deactivated
#     person loses access on the next decision;
#   * a node agent, itself authenticated by a SPIRE SVID, decides locally;
#   * every decision and change lands in one audit chain, attributed to the
#     SPIRE identity that made it.

set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$EXAMPLE_DIR/run"
DEMO="$RUN_DIR/demo"
ENV_FILE="$RUN_DIR/demo.env"
TD=upstream.demo
OMEGA="https://127.0.0.1:18895"
LOCAL_PDP="http://127.0.0.1:18182"

dc() { docker compose --env-file "$ENV_FILE" "$@"; }
spire_server() { dc exec -T spire-server /opt/spire/bin/spire-server "$@"; }

cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_healthy() {
	for _ in $(seq 1 60); do
		[ "$(dc ps "$1" --format '{{.Health}}' 2>/dev/null)" = "healthy" ] && return 0
		sleep 2
	done
	echo "[demo] FAIL: $1 did not become healthy"
	dc logs "$1" 2>&1 | tail -20 | sed 's/^/       /'
	exit 1
}

# as ID: call Omega presenting the SPIRE SVID issued to ID.
as() {
	local who="$1"
	shift
	curl -sS --cacert "$DEMO/demo-ca.pem" --cert "$DEMO/$who.pem" --key "$DEMO/$who.key" "$@"
}

scim() {
	curl -fsS --cacert "$DEMO/demo-ca.pem" -X "$1" "$OMEGA/scim/v2/corp$2" \
		-H "Authorization: Bearer $(cat "$DEMO/scim-token")" -H 'Content-Type: application/scim+json' ${3:+-d "$3"}
}

decide() { # url-base subject action resource-type -> true / false / HTTP error
	local body
	body="{\"subject\":{\"type\":\"Spiffe\",\"id\":\"$2\"},\"action\":{\"name\":\"$3\"},\"resource\":{\"type\":\"$4\",\"id\":\"r1\"}}"
	if [ "$1" = "$OMEGA" ]; then
		as admin -X POST "$OMEGA/access/v1/evaluation" -H 'Content-Type: application/json' -d "$body"
	else
		curl -sS -X POST "$1/access/v1/evaluation" -H 'Content-Type: application/json' -d "$body"
	fi | python3 -c 'import sys, json; print(str(json.load(sys.stdin).get("decision")).lower())'
}

expect() {
	if [ "$2" != "$3" ]; then
		echo "[demo] FAIL: $1: got $2, want $3"
		dc logs omega omega-agent 2>&1 | tail -20 | sed 's/^/       /'
		exit 1
	fi
	echo "[demo]   ok: $1 -> $2"
}

id_of() { # PEM -> SPIFFE ID in its URI SAN
	openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | grep -o 'spiffe://[^, ]*'
}

cd "$EXAMPLE_DIR"
cleanup
rm -rf "$RUN_DIR"
mkdir -p "$DEMO" "$RUN_DIR/svids"
: >"$RUN_DIR/bootstrap.crt"
echo "SPIRE_JOIN_TOKEN=placeholder" >"$ENV_FILE"

echo "[demo] starting SPIRE (the identity issuer)"
dc up -d spire-server >/dev/null 2>&1
wait_healthy spire-server
spire_server bundle show >"$RUN_DIR/bootstrap.crt"
TOKEN="$(spire_server token generate -spiffeID "spiffe://$TD/agent" -output json |
	python3 -c 'import sys, json; print(json.load(sys.stdin)["value"])')"
echo "SPIRE_JOIN_TOKEN=$TOKEN" >"$ENV_FILE"
PARENT="spiffe://$TD/spire/agent/join_token/$TOKEN"

# Omega reads SPIRE's trust bundle as a workload; the platform admin and the
# node agent get their SVIDs from SPIRE like any other workload.
echo "[demo] registering Omega, a platform admin and a node agent in SPIRE"
spire_server entry create -parentID "$PARENT" -spiffeID "spiffe://$TD/omega" \
	-selector "unix:path:/usr/local/bin/omega" >/dev/null
for id in platform/admin nodes/node1; do
	spire_server entry create -parentID "$PARENT" -spiffeID "spiffe://$TD/$id" \
		-selector "unix:path:/opt/spire/bin/spire-agent" >/dev/null
done

dc up -d spire-agent >/dev/null 2>&1
wait_healthy spire-agent

echo "[demo] fetching the admin's and the node agent's SVIDs from SPIRE"
# Written inside the agent container and copied out with compose cp, so the
# files belong to whoever runs the demo rather than to the container's root.
for _ in $(seq 1 30); do
	if dc exec -T spire-agent /opt/spire/bin/spire-agent api fetch x509 \
		-socketPath /run/spire/sockets/agent.sock -write /run/spire/sockets >/dev/null 2>&1; then
		for f in svid.0.pem svid.0.key svid.1.pem svid.1.key bundle.0.pem; do
			dc cp "spire-agent:/run/spire/sockets/$f" "$RUN_DIR/svids/$f" >/dev/null 2>&1 || true
		done
		[ -f "$RUN_DIR/svids/svid.1.pem" ] && break
	fi
	sleep 2
done
for pem in "$RUN_DIR"/svids/svid.*.pem; do
	n="${pem##*/svid.}"
	n="${n%.pem}"
	case "$(id_of "$pem")" in
	"spiffe://$TD/platform/admin") name="admin" ;;
	"spiffe://$TD/nodes/node1") name="node" ;;
	*) continue ;;
	esac
	# Leaf only: SPIRE writes the chain, and curl and Go both want the leaf
	# first with intermediates after, which is what the file holds.
	cp "$pem" "$DEMO/$name.pem"
	cp "$RUN_DIR/svids/svid.$n.key" "$DEMO/$name.key"
done
cp "$RUN_DIR/svids/bundle.0.pem" "$DEMO/spire-bundle.pem"
[ -f "$DEMO/admin.pem" ] && [ -f "$DEMO/node.pem" ] || {
	echo "[demo] FAIL: SPIRE did not issue the admin and node SVIDs"
	exit 1
}
echo "[demo]   admin: $(id_of "$DEMO/admin.pem")"
echo "[demo]   node:  $(id_of "$DEMO/node.pem")"

# Omega's own serving certificate. In upstream mode Omega issues nothing, so
# the demo makes a throwaway CA for the TLS listener.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=demo-ca" -days 1 \
	-keyout "$DEMO/demo-ca.key" -out "$DEMO/demo-ca.pem" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=omega" \
	-keyout "$DEMO/omega.key" -out "$DEMO/omega.csr" 2>/dev/null
printf 'subjectAltName=DNS:omega,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' >"$DEMO/omega.ext"
openssl x509 -req -in "$DEMO/omega.csr" -CA "$DEMO/demo-ca.pem" -CAkey "$DEMO/demo-ca.key" \
	-CAcreateserial -days 1 -extfile "$DEMO/omega.ext" -out "$DEMO/omega.pem" 2>/dev/null
openssl rand -hex 32 >"$DEMO/scim-token"
# The key that signs the policy bundle the node agent's local PDP loads.
openssl ecparam -name prime256v1 -genkey -noout -out "$DEMO/bundle.key" 2>/dev/null
openssl ec -in "$DEMO/bundle.key" -pubout -out "$DEMO/bundle.pem" 2>/dev/null
# Certificates are public; keys and the SCIM token stay owner-only (the
# containers read them as root).
chmod 644 "$DEMO"/*.pem
chmod 600 "$DEMO"/*.key "$DEMO/scim-token"

echo "[demo] starting Omega on SPIRE's trust domain (mTLS, --require-auth)"
dc up -d --build omega >/dev/null 2>&1
for _ in $(seq 1 60); do
	curl -fsS --cacert "$DEMO/demo-ca.pem" "$OMEGA/healthz" >/dev/null 2>&1 && break
	sleep 1
done

echo "[demo] the admin, authenticated by its SPIRE SVID, creates domains"
for d in payments people; do
	code="$(as admin -o /dev/null -w '%{http_code}' -X POST "$OMEGA/v1/domains" \
		-H 'Content-Type: application/json' -d "{\"name\":\"$d\"}")"
	expect "create domain $d" "$code" 201
done
code="$(as node -o /dev/null -w '%{http_code}' -X POST "$OMEGA/v1/domains" \
	-H 'Content-Type: application/json' -d '{"name":"shadow"}')"
expect "the node agent, not an admin, creating a domain" "$code" 403

echo "[demo] Cedar decides by SPIRE path"
expect "spiffe://$TD/payments/api reads the ledger" "$(decide "$OMEGA" "spiffe://$TD/payments/api" read Ledger)" true
expect "spiffe://$TD/media/web reads the ledger" "$(decide "$OMEGA" "spiffe://$TD/media/web" read Ledger)" false

echo "[demo] the identity provider pushes Alice into Payments Oncall over SCIM"
ALICE="spiffe://$TD/humans/corp/00u-alice"
alice_id="$(scim POST /Users '{"userName":"alice@corp.example","externalId":"00u-alice","active":true}' |
	python3 -c 'import sys, json; print(json.load(sys.stdin)["id"])')"
scim POST /Groups "{\"displayName\":\"Payments Oncall\",\"members\":[{\"value\":\"$alice_id\"}]}" >/dev/null
expect "Alice approves a refund" "$(decide "$OMEGA" "$ALICE" approve Refund)" true

echo "[demo] the node agent decides locally from the synced policy"
dc up -d omega-agent >/dev/null 2>&1
for _ in $(seq 1 60); do
	curl -fsS "$LOCAL_PDP/healthz" 2>/dev/null | grep -q '"revision":"[0-9a-f]' && break
	sleep 1
done
expect "local: payments/api reads the ledger" "$(decide "$LOCAL_PDP" "spiffe://$TD/payments/api" read Ledger)" true
expect "local: Alice approves a refund" "$(decide "$LOCAL_PDP" "$ALICE" approve Refund)" true

echo "[demo] the identity provider deactivates Alice"
scim PATCH "/Users/$alice_id" '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}' >/dev/null
expect "central: Alice approves a refund" "$(decide "$OMEGA" "$ALICE" approve Refund)" false
for _ in $(seq 1 30); do
	[ "$(decide "$LOCAL_PDP" "$ALICE" approve Refund)" = false ] && break
	sleep 1
done
expect "local, after the next sync: Alice approves a refund" "$(decide "$LOCAL_PDP" "$ALICE" approve Refund)" false

echo "[demo] one audit chain, attributed to SPIRE identities"
audit=""
for _ in $(seq 1 30); do
	audit="$(as admin "$OMEGA/v1/audit?since=0&limit=1000")"
	printf '%s' "$audit" | grep -q '"kind":"access.evaluate.local"' && break
	sleep 1
done
check() {
	printf '%s' "$audit" | python3 -c "
import sys, json
rows = json.load(sys.stdin)
rows = rows.get('items', rows) if isinstance(rows, dict) else rows
sys.exit(0 if any(r.get('kind') == '$1' and r.get('actor') == '$2' for r in rows) else 1)" ||
		{ echo "[demo] FAIL: no $1 row by $2"; exit 1; }
	echo "[demo]   ok: $1 by $2"
}
check domain.create "spiffe://$TD/platform/admin"
check scim.group.create "scim:corp"
check scim.user.patch "scim:corp"
check access.evaluate.local "spiffe://$TD/nodes/node1"
verify="$(as admin "$OMEGA/v1/audit/verify")"
printf '%s' "$verify" | grep -q '"valid":true' || { echo "[demo] FAIL: audit chain does not verify: $verify"; exit 1; }
echo "[demo]   ok: the chain verifies"

echo
echo "[demo] success - SPIRE issues, Omega authorizes and audits"
