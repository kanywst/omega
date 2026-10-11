#!/usr/bin/env bash
# run-demo.sh: an identity provider provisions Omega over SCIM 2.0.
#
# Asserts:
#   * users and a group pushed over SCIM become an Omega group whose
#     members are the users' SPIFFE IDs, and a Cedar policy on that group
#     allows them;
#   * adding a member over SCIM grants access, deactivating a user
#     revokes it at once;
#   * every change is in the audit chain with the provider as actor;
#   * the Omega API refuses to edit a group the provider owns.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-scim-demo}"
PORT="${PORT:-18097}"
CP="http://127.0.0.1:$PORT"
SCIM="$CP/scim/v2/corp"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
}
trap cleanup EXIT

scim() { # method path [body]
	curl -fsS -X "$1" "$SCIM$2" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/scim+json' ${3:+-d "$3"}
}

may_deploy() { # spiffe-id -> true/false
	curl -fsS -X POST "$CP/access/v1/evaluation" -H 'Content-Type: application/json' \
		-d "{\"subject\":{\"type\":\"Spiffe\",\"id\":\"$1\"},\"action\":{\"name\":\"deploy\"},\"resource\":{\"type\":\"App\",\"id\":\"web\"}}" |
		grep -o '"decision":[a-z]*' | cut -d: -f2
}

expect() { # what got want
	if [[ "$2" != "$3" ]]; then
		echo "FAIL: $1: got $2, want $3" >&2
		exit 1
	fi
	echo "  $1 -> $2"
}

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
TOKEN="$(openssl rand -hex 32)"
printf '%s\n' "$TOKEN" >"$DEMO_DIR/scim-token"
chmod 600 "$DEMO_DIR/scim-token"

echo "[demo] building omega"
go -C "$REPO_ROOT" build -o "$DEMO_DIR/omega" ./cmd/omega

echo "[demo] starting the control plane with a SCIM provider \"corp\" owning groups in domain \"people\""
"$DEMO_DIR/omega" server --http-addr "127.0.0.1:$PORT" --trust-domain omega.local \
	--data-dir "$DEMO_DIR/server" --policy-dir "$EXAMPLE_DIR/policies" \
	--scim-idp "name=corp,domain=people,token-file=$DEMO_DIR/scim-token" >"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
for _ in $(seq 1 100); do
	curl -fsS -o /dev/null "$CP/healthz" 2>/dev/null && break
	sleep 0.1
done
curl -fsS -X POST "$CP/v1/domains" -H 'Content-Type: application/json' -d '{"name":"people"}' >/dev/null

ALICE=spiffe://omega.local/humans/corp/00u-alice
BOB=spiffe://omega.local/humans/corp/00u-bob

echo "[demo] the provider pushes two users and an Engineering group with alice in it"
alice_id=$(scim POST /Users '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@corp.example","externalId":"00u-alice","active":true}' | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
bob_id=$(scim POST /Users '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@corp.example","externalId":"00u-bob","active":true}' | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
group=$(scim POST /Groups "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"Engineering\",\"members\":[{\"value\":\"$alice_id\"}]}")
group_id=$(printf '%s' "$group" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
printf '%s' "$group" | grep -q '"omegaGroup":"people:engineering"' || { echo "FAIL: group not mapped to people:engineering" >&2; exit 1; }
expect "alice may deploy" "$(may_deploy $ALICE)" true
expect "bob may deploy" "$(may_deploy $BOB)" false

echo "[demo] the provider adds bob to Engineering"
scim PATCH "/Groups/$group_id" "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:PatchOp\"],\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"$bob_id\"}]}]}" >/dev/null
expect "bob may deploy" "$(may_deploy $BOB)" true

echo "[demo] the provider deactivates alice"
scim PATCH "/Users/$alice_id" '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}' >/dev/null
expect "alice may deploy" "$(may_deploy $ALICE)" false

echo "[demo] the Omega API refuses to edit the provider's group"
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$CP/v1/domains/people/groups/engineering/members" \
	-H 'Content-Type: application/json' -d "{\"principal\":\"$ALICE\"}")
expect "PUT .../groups/engineering/members" "$code" 409

echo "[demo] the provisioning trail in the audit chain"
audit=$(curl -fsS "$CP/v1/audit?since=0")
for kind in scim.user.create scim.group.create scim.group.patch scim.user.patch; do
	printf '%s' "$audit" | grep -q "\"kind\":\"$kind\"" || { echo "FAIL: no $kind in the audit chain" >&2; exit 1; }
done
printf '%s' "$audit" | grep -q '"actor":"scim:corp"' || { echo "FAIL: provider not recorded as actor" >&2; exit 1; }
echo "  scim.user.create, scim.group.create, scim.group.patch, scim.user.patch by scim:corp"

echo
echo "[demo] success - provisioned over SCIM, enforced by Cedar, revoked on deactivation"
