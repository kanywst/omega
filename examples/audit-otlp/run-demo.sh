#!/usr/bin/env bash
# run-demo.sh exercises the OTLP/HTTP-protobuf audit forwarder:
#
#   1. boots a tiny in-process OTLP logs sink (cmd/otlp-sink) that
#      decodes ExportLogsServiceRequest bodies into JSONL,
#   2. boots an omega server wired to forward audit events to the
#      sink via --audit-otlp-endpoint with a short --audit-poll-interval,
#   3. drives two writes that produce audit rows (domain.create +
#      access.evaluate),
#   4. asserts the sink received both events, that their
#      omega.audit.kind attributes are correct, and that the
#      hash-chain fields (omega.audit.hash, omega.audit.prev_hash)
#      are present on every record.

set -euo pipefail

DEMO_DIR="${DEMO_DIR:-/tmp/omega-audit-otlp-demo}"
SERVER_PORT="${SERVER_PORT:-18290}"
SINK_PORT="${SINK_PORT:-18291}"

cleanup() {
	[[ -f "$DEMO_DIR/server.pid" ]] && kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
	[[ -f "$DEMO_DIR/sink.pid"   ]] && kill "$(cat "$DEMO_DIR/sink.pid")"   2>/dev/null || true
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

echo "[demo] building otlp-sink"
go -C "$EXAMPLE_DIR/otlp-sink" build -o "$DEMO_DIR/otlp-sink" .

echo "[demo] starting otlp-sink on :$SINK_PORT (out=$DEMO_DIR/events.jsonl)"
"$DEMO_DIR/otlp-sink" \
	--addr "127.0.0.1:$SINK_PORT" \
	--out "$DEMO_DIR/events.jsonl" \
	>"$DEMO_DIR/sink.log" 2>&1 &
echo $! >"$DEMO_DIR/sink.pid"
wait_for_url "http://127.0.0.1:$SINK_PORT/healthz" "$DEMO_DIR/sink.log"

echo "[demo] starting omega server on :$SERVER_PORT (audit-otlp -> http://127.0.0.1:$SINK_PORT)"
omega server \
	--http-addr "127.0.0.1:$SERVER_PORT" \
	--trust-domain omega.demo \
	--data-dir "$DEMO_DIR/server" \
	--audit-otlp-endpoint "127.0.0.1:$SINK_PORT" \
	--audit-otlp-insecure \
	--audit-poll-interval 200ms \
	>"$DEMO_DIR/server.log" 2>&1 &
echo $! >"$DEMO_DIR/server.pid"
wait_for_url "http://127.0.0.1:$SERVER_PORT/healthz" "$DEMO_DIR/server.log"

echo "[demo] writing one domain (audit kind=domain.create)"
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/v1/domains" \
	-H 'content-type: application/json' \
	-d '{"name":"otlp-demo"}' >/dev/null

echo "[demo] evaluating one AuthZEN request (audit kind=access.evaluate)"
curl -fsS -X POST "http://127.0.0.1:$SERVER_PORT/access/v1/evaluation" \
	-H 'content-type: application/json' \
	-d '{
		"subject":  {"type":"Spiffe","id":"spiffe://omega.demo/example/web"},
		"action":   {"name":"GET"},
		"resource": {"type":"HttpPath","id":"/api/foo"}
	}' >/dev/null

# Pump runs every 200ms; give it a couple of cycles to flush.
sleep 1

# Sink writes one JSONL line per audit event. Count the kinds we
# expect to have arrived.
for kind in domain.create access.evaluate; do
	count=$(grep -c "\"omega.audit.kind\":\"$kind\"" "$DEMO_DIR/events.jsonl" 2>/dev/null || true)
	if [[ "${count:-0}" -lt 1 ]]; then
		echo "[demo] FAIL: expected at least one $kind event at the sink"
		echo "[demo] events.jsonl tail:"; tail -10 "$DEMO_DIR/events.jsonl" 2>/dev/null | sed 's/^/       /' || true
		exit 1
	fi
done

# Every record must carry both the hash and the prev_hash so a
# downstream pipeline can verify the chain on its own.
missing=$(python3 - <<PY
import json
missing = 0
with open("$DEMO_DIR/events.jsonl") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        attrs = row.get("attributes", {})
        if not attrs.get("omega.audit.hash") or not attrs.get("omega.audit.prev_hash"):
            missing += 1
print(missing)
PY
)
if [[ "$missing" != "0" ]]; then
	echo "[demo] FAIL: $missing records were missing hash chain attributes"
	exit 1
fi

records=$(wc -l < "$DEMO_DIR/events.jsonl" | tr -d ' ')
echo "[demo] success — sink received $records LogRecord(s) with hash-chain attributes"
echo "[demo]   jsonl: $DEMO_DIR/events.jsonl"
