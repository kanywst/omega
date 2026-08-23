#!/usr/bin/env bash
# run-demo.sh: omega consuming a real SPIRE deployment.
#
# examples/spire-upstream-live proves omega speaks the SPIFFE Workload API by
# serving it from a mock. This one removes the mock: upstream spire-server and
# spire-agent images, real join-token node attestation, a real registration
# entry for omega, and SPIRE's own localauthority command driving the CA
# rotation. What it costs is Docker and about a minute.
#
# The claim under test is the one the mock cannot make: that omega is an
# attestable workload of a real agent and follows that agent's rotations.

set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$EXAMPLE_DIR/run"
ENV_FILE="$RUN_DIR/demo.env"
TRUST_DOMAIN="${TRUST_DOMAIN:-upstream.demo}"
OMEGA_URL="${OMEGA_URL:-http://127.0.0.1:18894}"

dc() { docker compose --env-file "$ENV_FILE" "$@"; }
spire_server() { dc exec -T spire-server /opt/spire/bin/spire-server "$@"; }

cleanup() { dc down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_healthy() {
	local svc="$1"
	for _ in $(seq 1 60); do
		[ "$(dc ps "$svc" --format '{{.Health}}' 2>/dev/null)" = "healthy" ] && return 0
		sleep 2
	done
	echo "[demo] FAIL: $svc did not become healthy within 120s"
	dc logs "$svc" 2>&1 | tail -20 | sed 's/^/       /'
	exit 1
}

wait_url() {
	for _ in $(seq 1 60); do
		curl -fsS "$OMEGA_URL/healthz" >/dev/null 2>&1 && return 0
		sleep 1
	done
	echo "[demo] FAIL: omega did not serve /healthz within 60s"
	dc logs omega 2>&1 | tail -20 | sed 's/^/       /'
	exit 1
}

assert_eq() {
	local what="$1" got="$2" want="$3"
	if [ "$got" != "$want" ]; then
		echo "[demo] FAIL: $what"
		echo "       got:  $got"
		echo "       want: $want"
		exit 1
	fi
	echo "[demo]   ok: $what ($got)"
}

sequence() {
	curl -fsS "$OMEGA_URL/v1/spiffe-bundle" |
		python3 -c 'import sys, json; print(json.load(sys.stdin)["spiffe_sequence"])'
}

kids() {
	python3 -c 'import sys, json
keys = json.load(sys.stdin).get("keys", [])
print(",".join(sorted(k.get("kid", "") for k in keys)))'
}

# Trust anchors as a sorted list of certificate fingerprints, so what SPIRE
# holds and what omega serves are comparable regardless of PEM formatting or
# ordering.
anchors() {
	python3 -c '
import hashlib, re, sys, base64
pem = sys.stdin.read()
blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem, re.S)
print(",".join(sorted(hashlib.sha256(base64.b64decode("".join(b.split()))).hexdigest()[:16] for b in blocks)))'
}

spire_anchors() { spire_server bundle show | anchors; }
omega_anchors() { curl -fsS "$OMEGA_URL/v1/bundle" | anchors; }

# The rotation is asynchronous and nothing signals omega, so poll.
wait_for_anchors() {
	local want="$1"
	for _ in $(seq 1 60); do
		[ "$(omega_anchors)" = "$want" ] && return 0
		sleep 1
	done
	echo "[demo] FAIL: omega did not follow the upstream within 60s"
	echo "       spire: $want"
	echo "       omega: $(omega_anchors)"
	dc logs omega 2>&1 | tail -20 | sed 's/^/       /'
	exit 1
}

cd "$EXAMPLE_DIR"
cleanup
rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR"
# The bind mount has to exist before compose creates the agent, or Docker
# makes a directory where a file belongs.
: >"$RUN_DIR/bootstrap.crt"
echo "SPIRE_JOIN_TOKEN=placeholder" >"$ENV_FILE"

echo "[demo] starting spire-server"
dc up -d spire-server >/dev/null 2>&1
wait_healthy spire-server

echo "[demo] bootstrapping the agent against the server's trust bundle"
spire_server bundle show >"$RUN_DIR/bootstrap.crt"

# The join token is minted once and pinned in the env file. The agent's key
# manager is `memory` and a join token is not reattestable, so recreating the
# agent container with a different token strands it - every later `dc up` has
# to resolve the same value.
TOKEN="$(spire_server token generate -spiffeID "spiffe://$TRUST_DOMAIN/agent" -output json |
	python3 -c 'import sys, json; print(json.load(sys.stdin)["value"])')"
echo "SPIRE_JOIN_TOKEN=$TOKEN" >"$ENV_FILE"

# omega is a workload like any other: no entry, no answer from the agent.
echo "[demo] registering omega as a workload of that trust domain"
spire_server entry create \
	-parentID "spiffe://$TRUST_DOMAIN/spire/agent/join_token/$TOKEN" \
	-spiffeID "spiffe://$TRUST_DOMAIN/omega" \
	-selector "docker:label:io.omega.role:control-plane" >/dev/null

echo "[demo] starting spire-agent"
dc up -d spire-agent >/dev/null 2>&1
wait_healthy spire-agent

echo "[demo] starting omega against the agent's workload API socket"
dc up -d --build omega >/dev/null 2>&1
wait_url

echo "[demo] omega serves SPIRE's trust anchors"
SPIRE_ANCHORS="$(spire_anchors)"
assert_eq "/v1/bundle == spire-server bundle show" "$(omega_anchors)" "$SPIRE_ANCHORS"

JWT_KIDS="$(curl -fsS "$OMEGA_URL/v1/jwt/bundle" | kids)"
if [ -z "$JWT_KIDS" ]; then
	echo "[demo] FAIL: /v1/jwt/bundle served no upstream signing keys"
	exit 1
fi
echo "[demo]   ok: /v1/jwt/bundle carries SPIRE's signing key ($JWT_KIDS)"
assert_eq "spiffe_sequence starts at 1" "$(sequence)" "1"

# ADR 0007: consuming an upstream does not make omega an issuer.
echo "[demo] issuance routes stay disabled (no local CA)"
for path in /v1/svid /v1/svid/jwt /v1/token/exchange; do
	code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$OMEGA_URL$path" \
		-H 'content-type: application/json' -d '{}')"
	assert_eq "POST $path" "$code" "501"
done

authority_field() {
	python3 -c "import sys, json; d = json.load(sys.stdin); print(d[\"$1\"][\"authority_id\"])"
}

# SPIRE rotates its X.509 CA on its own schedule; localauthority is that same
# operation on demand. Prepare alone would grow the bundle, which omega would
# follow without anything having actually rotated, so this activates the
# prepared authority and asserts it became the active one.
echo "[demo] rotating SPIRE's X.509 CA — omega is not told"
BEFORE_CA="$(spire_server localauthority x509 show -output json | authority_field active)"
PREPARED_CA="$(spire_server localauthority x509 prepare -output json | authority_field prepared_authority)"
spire_server localauthority x509 activate -authorityID "$PREPARED_CA" >/dev/null
ACTIVE_CA="$(spire_server localauthority x509 show -output json | authority_field active)"
assert_eq "SPIRE promoted the prepared X.509 authority" "$ACTIVE_CA" "$PREPARED_CA"
if [ "$ACTIVE_CA" = "$BEFORE_CA" ]; then
	echo "[demo] FAIL: the active authority did not change; this is not a rotation"
	exit 1
fi

ROTATED_ANCHORS="$(spire_anchors)"
if [ "$ROTATED_ANCHORS" = "$SPIRE_ANCHORS" ]; then
	echo "[demo] FAIL: the upstream bundle did not change across a CA rotation"
	exit 1
fi
wait_for_anchors "$ROTATED_ANCHORS"
echo "[demo]   ok: /v1/bundle followed SPIRE's CA rotation, with no signal sent"

# The JWT half rotates on its own schedule too, and arrives on its own stream.
echo "[demo] rotating SPIRE's JWT signing key — omega is not told"
PREPARED_JWT="$(spire_server localauthority jwt prepare -output json | authority_field prepared_authority)"
spire_server localauthority jwt activate -authorityID "$PREPARED_JWT" >/dev/null
assert_eq "SPIRE promoted the prepared JWT authority" \
	"$(spire_server localauthority jwt show -output json | authority_field active)" "$PREPARED_JWT"

for _ in $(seq 1 60); do
	ROTATED_KIDS="$(curl -fsS "$OMEGA_URL/v1/jwt/bundle" | kids)"
	[ "$ROTATED_KIDS" != "$JWT_KIDS" ] && break
	sleep 1
done
if [ "$ROTATED_KIDS" = "$JWT_KIDS" ]; then
	echo "[demo] FAIL: /v1/jwt/bundle still serves only the pre-rotation signing key"
	exit 1
fi
echo "[demo]   ok: /v1/jwt/bundle followed the signing-key rotation ($ROTATED_KIDS)"

SEQ="$(sequence)"
if [ "$SEQ" -lt 3 ]; then
	echo "[demo] FAIL: spiffe_sequence is $SEQ after two rotations, want >= 3"
	exit 1
fi
echo "[demo]   ok: spiffe_sequence advanced to $SEQ"

echo "[demo] success — omega consumed a real SPIRE rotation with no operator in the loop"
