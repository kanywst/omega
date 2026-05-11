# examples/audit-otlp

End-to-end demo of the OTLP/HTTP-protobuf [audit forwarder](../../internal/server/audit/otlp.go):
ship every audit-log row to an OpenTelemetry-compatible logs
receiver as a `LogRecord`, with the hash-chain fields surfaced as
attributes for downstream dedupe and integrity verification.

`make demo` walks the full path:

1. boots `cmd/otlp-sink` — a minimal `POST /v1/logs` handler that
   decodes the `ExportLogsServiceRequest` protobuf and appends one
   JSONL line per `LogRecord` to a file;
2. boots `omega server` with `--audit-otlp-endpoint 127.0.0.1:<port>
   --audit-otlp-insecure --audit-poll-interval 200ms`;
3. drives one `POST /v1/domains` (audit `kind=domain.create`) and
   one `POST /access/v1/evaluation` (audit `kind=access.evaluate`);
4. waits one poll cycle and asserts both events arrived at the
   sink with their `omega.audit.kind` attribute set correctly;
5. asserts every received record carries
   `omega.audit.hash` and `omega.audit.prev_hash` so a downstream
   pipeline can verify the chain without re-fetching `/v1/audit`.

The sink is just enough OTLP to satisfy the omega forwarder; a
real deployment swaps it for the OTel Collector or any
OTLP-compatible receiver (Splunk OTLP, Grafana Loki via OTLP
ingest, Datadog, Honeycomb, Sentry, cloud logging endpoints).

## Run

```text
make demo
```

The script tears itself down on exit; force a manual cleanup with:

```text
make down
```

## Adapt to a real pipeline

Swap the sink endpoint for an OTel Collector (or a vendor's direct
OTLP receiver). Authentication is via `--audit-otlp-header`:

```text
omega server \
  --audit-otlp-endpoint https://collector.example.com:4318 \
  --audit-otlp-header 'Authorization: Bearer <token>'
```

A non-standard receiver path is supported as-is (the flag preserves
any path component you supply, per OTLP/HTTP §3.2):

```text
--audit-otlp-endpoint https://collector.internal/teams/sec/v1/logs
```
