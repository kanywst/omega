#!/usr/bin/env bash
# run-demo.sh boots a Postgres container, runs an omega server backed by
# it, drives a couple of API calls, restarts the server to prove
# durability, and prints the canonical audit chain rows directly from
# Postgres so you can confirm the bytes really live there.
set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-postgres-demo}"
SERVER_PORT="${SERVER_PORT:-18097}"
PG_CONTAINER="${PG_CONTAINER:-omega-pg-demo}"
PG_PORT="${PG_PORT:-55433}"
PG_DSN="${PG_DSN:-postgres://omega:omega@127.0.0.1:$PG_PORT/omega?sslmode=disable}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"

echo "[demo] starting Postgres container :$PG_PORT"
docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$PG_CONTAINER" \
	-e POSTGRES_PASSWORD=omega -e POSTGRES_USER=omega -e POSTGRES_DB=omega \
	-p "$PG_PORT:5432" postgres:16-alpine >/dev/null

# Probe from the host so we wait for both Postgres readiness AND the
# Docker port forwarding to be live. Probing inside the container can
# return ready before the host port is reachable, which makes omega's
# first connection race the server and trip "connection reset by peer".
for _ in $(seq 1 120); do
	if (echo > "/dev/tcp/127.0.0.1/$PG_PORT") 2>/dev/null; then
		if docker exec "$PG_CONTAINER" psql -U omega -d omega -c 'SELECT 1' >/dev/null 2>&1; then
			break
		fi
	fi
	sleep 0.5
done

echo "[demo] starting omega server on :$SERVER_PORT (db=$PG_DSN)"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain omega.demo \
	--data-dir "$DEMO_DIR/server" \
	--db "$PG_DSN" \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"

# /healthz turns green as soon as the HTTP listener is up, but the
# Postgres-backed write path also needs the advisory-lock leader to be
# acquired (see leaderOnly in internal/server/api/http.go). Poll
# /v1/leader so we don't fire writes before this replica wins the lock.
ready=0
for _ in $(seq 1 150); do
	if curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/leader" 2>/dev/null | grep -q '"is_leader":true'; then
		ready=1
		break
	fi
	sleep 0.2
done
if [[ "$ready" != "1" ]]; then
	echo "FAIL: omega server did not become leader on :$SERVER_PORT" >&2
	echo "----- server.log -----" >&2
	tail -80 "$DEMO_DIR/server.log" >&2 || true
	exit 1
fi

echo "[demo] driving API calls (eval + create domain)"
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/access/v1/evaluation" \
	-H "Content-Type: application/json" \
	-d '{"subject":{"type":"User","id":"alice"},"action":{"name":"read"},"resource":{"type":"Doc","id":"x"}}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/domains" \
	-H "Content-Type: application/json" \
	-d '{"name":"media","description":"media"}' >/dev/null
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/domains" \
	-H "Content-Type: application/json" \
	-d '{"name":"media.news","description":"news"}' >/dev/null

echo "[demo] restarting server to prove durability"
kill "$(cat "$DEMO_DIR/server.pid")"
wait "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain omega.demo \
	--data-dir "$DEMO_DIR/server" \
	--db "$PG_DSN" \
	>>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
ready=0
for _ in $(seq 1 150); do
	if curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/leader" 2>/dev/null | grep -q '"is_leader":true'; then
		ready=1
		break
	fi
	sleep 0.2
done
if [[ "$ready" != "1" ]]; then
	echo "FAIL: omega server did not become leader on :$SERVER_PORT after restart" >&2
	echo "----- server.log -----" >&2
	tail -80 "$DEMO_DIR/server.log" >&2 || true
	exit 1
fi

echo "[demo] domains visible after restart:"
curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/domains" | sed 's/^/  /'
echo

echo "[demo] audit_log rows directly from Postgres:"
docker exec "$PG_CONTAINER" psql -U omega -d omega -c \
	"SELECT seq, kind, subject, decision, substr(hash, 1, 16) AS hash16, substr(prev_hash, 1, 16) AS prev16 FROM audit_log ORDER BY seq;" \
	| sed 's/^/  /'

verify="$(curl -fsS "http://127.0.0.1:$SERVER_PORT/v1/audit/verify")"
echo "[demo] /v1/audit/verify → $verify"

if ! echo "$verify" | grep -q '"valid":true'; then
	echo "FAIL: audit chain verification failed" >&2
	exit 1
fi

echo "[demo] success - omega is durable on Postgres and the audit chain is intact"
