#!/usr/bin/env bash
# run-demo.sh boots Postgres + two omega servers wired to the same DB,
# proves only one is leader, kills the leader, watches the follower
# promote, and confirms a write to a follower is rejected with 503 +
# Retry-After (so callers can transparently retry against the leader).
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-postgres-ha-demo}"
PG_CONTAINER="${PG_CONTAINER:-omega-pg-ha-demo}"
PG_PORT="${PG_PORT:-55434}"
PG_DSN="${PG_DSN:-postgres://omega:omega@127.0.0.1:$PG_PORT/omega?sslmode=disable}"

A_PORT="${A_PORT:-18101}"
B_PORT="${B_PORT:-18102}"
POLL=0.2

cleanup() {
	for f in "$DEMO_DIR"/a.pid "$DEMO_DIR"/b.pid; do
		[[ -f "$f" ]] && kill "$(cat "$f")" 2>/dev/null || true
	done
	docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

echo "[ha] starting Postgres :$PG_PORT"
docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$PG_CONTAINER" \
	-e POSTGRES_PASSWORD=omega -e POSTGRES_USER=omega -e POSTGRES_DB=omega \
	-p "$PG_PORT:5432" postgres:16-alpine >/dev/null

# Probe from the host so we wait for both Postgres readiness AND the
# Docker port forwarding to be live. Probing inside the container can
# return ready before the host port is reachable.
for _ in $(seq 1 120); do
	if (echo > "/dev/tcp/127.0.0.1/$PG_PORT") 2>/dev/null; then
		# TCP open; now wait for the server to actually answer the
		# startup packet by issuing a trivial query through psql.
		if docker exec "$PG_CONTAINER" psql -U omega -d omega -c 'SELECT 1' >/dev/null 2>&1; then
			break
		fi
	fi
	sleep 0.5
done

start_server() {
	local name="$1" port="$2"
	echo "[ha] starting omega-$name on :$port (db=$PG_DSN)"
	omega server \
		--http-addr "127.0.0.1:$port" \
		--trust-domain omega.ha \
		--data-dir "$DEMO_DIR/$name" \
		--db "$PG_DSN" \
		--ha-poll-interval 100ms \
		>"$DEMO_DIR/$name.log" 2>&1 &
	echo $! >"$DEMO_DIR/$name.pid"
	for _ in $(seq 1 60); do
		if curl -fsS -o /dev/null "http://127.0.0.1:$port/healthz" 2>/dev/null; then
			return
		fi
		sleep "$POLL"
	done
	echo "FAIL: omega-$name did not become healthy" >&2
	cat "$DEMO_DIR/$name.log" >&2
	exit 1
}

start_server a "$A_PORT"
start_server b "$B_PORT"

leader_state() {
	curl -fsS "http://127.0.0.1:$1/v1/leader" | grep -o '"is_leader":[a-z]*' | cut -d: -f2
}

wait_one_leader() {
	for _ in $(seq 1 50); do
		la="$(leader_state "$A_PORT")"
		lb="$(leader_state "$B_PORT")"
		if [[ "$la" != "$lb" ]]; then
			return
		fi
		sleep "$POLL"
	done
	echo "FAIL: neither server claimed exclusive leadership (a=$la b=$lb)" >&2
	exit 1
}

wait_one_leader
la="$(leader_state "$A_PORT")"
lb="$(leader_state "$B_PORT")"
if [[ "$la" == "true" ]]; then
	leader_name=a; leader_port="$A_PORT"; follower_name=b; follower_port="$B_PORT"
else
	leader_name=b; leader_port="$B_PORT"; follower_name=a; follower_port="$A_PORT"
fi
echo "[ha] leader=$leader_name follower=$follower_name"

echo "[ha] write to LEADER ($leader_name):"
curl -fsS -X POST "http://127.0.0.1:$leader_port/v1/domains" \
	-H "Content-Type: application/json" \
	-d '{"name":"media","description":"parent, created on leader"}' \
	-w "  status=%{http_code}\n" -o /dev/null
curl -fsS -X POST "http://127.0.0.1:$leader_port/v1/domains" \
	-H "Content-Type: application/json" \
	-d '{"name":"media.news","description":"created on leader"}' \
	-w "  status=%{http_code}\n" -o /dev/null

echo "[ha] write to FOLLOWER ($follower_name) — must 503 with Retry-After: 1:"
follower_resp_headers="$(curl -sS -D - -o /dev/null -X POST \
	"http://127.0.0.1:$follower_port/v1/domains" \
	-H "Content-Type: application/json" \
	-d '{"name":"x.y","description":"should be rejected"}')"
echo "$follower_resp_headers" | grep -E '^(HTTP|Retry-After)' | sed 's/^/  /'
echo "$follower_resp_headers" | grep -q "^HTTP/[0-9.]\+ 503" \
	|| { echo "FAIL: follower did not return 503" >&2; exit 1; }
echo "$follower_resp_headers" | grep -qi "^Retry-After: 1" \
	|| { echo "FAIL: follower 503 missing Retry-After: 1" >&2; exit 1; }

echo "[ha] killing leader ($leader_name) to trigger fail-over"
kill "$(cat "$DEMO_DIR/$leader_name.pid")"
wait "$(cat "$DEMO_DIR/$leader_name.pid")" 2>/dev/null || true
rm -f "$DEMO_DIR/$leader_name.pid"

# Postgres releases the advisory lock when the holder's TCP session
# closes; the follower picks it up on its next poll (we set 100ms
# above, plus a small grace window for the kernel to tear the conn).
for _ in $(seq 1 100); do
	if [[ "$(leader_state "$follower_port")" == "true" ]]; then
		break
	fi
	sleep "$POLL"
done
if [[ "$(leader_state "$follower_port")" != "true" ]]; then
	echo "FAIL: $follower_name did not promote within $((100 * POLL))s" >&2
	exit 1
fi
echo "[ha] $follower_name promoted to leader"

echo "[ha] write to NEW LEADER ($follower_name):"
curl -fsS -X POST "http://127.0.0.1:$follower_port/v1/domains" \
	-H "Content-Type: application/json" \
	-d '{"name":"media.after-failover","description":"created post-failover"}' \
	-w "  status=%{http_code}\n" -o /dev/null

echo "[ha] domains in shared Postgres:"
docker exec "$PG_CONTAINER" psql -U omega -d omega -c \
	"SELECT name, description FROM domains ORDER BY name;" \
	| sed 's/^/  /'

verify="$(curl -fsS "http://127.0.0.1:$follower_port/v1/audit/verify")"
echo "[ha] /v1/audit/verify → $verify"
echo "$verify" | grep -q '"valid":true' \
	|| { echo "FAIL: audit chain broken" >&2; exit 1; }

echo "[ha] success - leader gating works, follower fails over, audit chain intact"
