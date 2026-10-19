# Observability

`omega-server` exposes a Prometheus-compatible `/metrics` endpoint on the
same listener as the admin API. The metrics are designed to give SREs the
operational visibility expected of a production identity / authorization
control plane: request rate and latency by route, decision allow/deny
counts, SVID issuance counts, audit append counts, and Go runtime
internals.

The `examples/observability/` directory ships a self-contained stack
(`omega-server` + Prometheus + Grafana) so you can see the dashboard
working end to end before wiring metrics into your own monitoring.

## Quick start

```bash
cd examples/observability
docker compose up --build
```

Then open <http://localhost:13001> for Grafana and
<http://localhost:19090> for Prometheus. The "Omega control plane"
dashboard is auto-provisioned. (Ports are intentionally non-default so
the example can coexist with the top-level `compose.yaml` quickstart.)

## Endpoint

| Property | Value                                            |
| -------- | ------------------------------------------------ |
| Path     | `/metrics`                                       |
| Listener | same as `--http-addr` (default `127.0.0.1:8080`) |
| Format   | Prometheus text exposition format                |
| Auth     | none. Place behind your existing scrape ACL.     |

In production you typically expose `/metrics` on a separate listener bound
to the cluster network only. That separation is on the roadmap; until
then, scrape the admin port from your monitoring namespace and block it
at the network layer from external clients.

## Metric reference

### Counters

| Name                           | Labels                        | Meaning                                                   |
| ------------------------------ | ----------------------------- | --------------------------------------------------------- |
| `omega_http_requests_total`    | `method`, `route`, `code`     | Total HTTP requests handled, by registered route pattern. |
| `omega_svid_issued_total`      | `kind` (`x509` / `jwt`)       | Total SVIDs issued.                                       |
| `omega_access_decisions_total` | `decision` (`allow` / `deny`) | Total AuthZEN access decisions.                           |
| `omega_audit_appended_total`   | `kind`                        | Total audit log entries appended (per event kind).        |
| `omega_domains_created_total`  | (none)                        | Total domains created via the admin API.                  |
| `omega_stored_policy_set_load_failures_total` | (none) | Times the stored Cedar policies failed to load; see [policies.md](policies.md#when-the-stored-set-does-not-load). |
| `omega_ui_proxy_refusals_suppressed_total` | (none) | Refused `Omega-User-Token` requests left off the audit chain because the caller already had one audited in the last minute; see [policies.md](policies.md#from-the-web-ui). |

### Histograms

| Name                                     | Labels            | Buckets (s)                                                                  |
| ---------------------------------------- | ----------------- | ---------------------------------------------------------------------------- |
| `omega_http_request_duration_seconds`    | `method`, `route` | Prometheus default buckets                                                   |
| `omega_access_decision_duration_seconds` | (none)            | 0.0001 / 0.0005 / 0.001 / 0.005 / 0.01 / 0.025 / 0.05 / 0.1 / 0.25 / 0.5 / 1 |

### Gauges

| Name               | Labels    | Meaning                                                            |
| ------------------ | --------- | ------------------------------------------------------------------ |
| `omega_build_info` | `version` | Always `1`. Use the `version` label to track rollout/canary state. |
| `omega_stored_policies` | (none) | Stored Cedar policies in the set the policy engine last loaded. |

### Standard collectors

The Go runtime collectors and the process collector are registered and
exported under their standard names (`go_*`, `process_*`). Use them for
goroutine count, GC pause time, file descriptor count, and resident set
size.

## Cardinality notes

The `route` label uses the registered Go 1.22 ServeMux pattern (for
example `POST /v1/domains/{name}`), not the request path. That keeps the
label space bounded by the number of declared routes, regardless of how
many distinct domains, SPIFFE IDs, or audit kinds exist.

The `kind` label on `omega_audit_appended_total` is bounded by the set
of audit event kinds emitted by the server (`domain.create`,
`svid.issue.x509`, `svid.issue.jwt`, `access.evaluate`). Adding a new
audit kind adds one new series; that is intentional.

## Wiring into an existing Prometheus

Add a scrape config:

```yaml
scrape_configs:
  - job_name: omega
    metrics_path: /metrics
    static_configs:
      - targets: ["omega-server.omega.svc.cluster.local:8080"]
```

Or use the Helm chart's ServiceMonitor (when shipped - tracked in the
roadmap). Until then a static target works.

## Grafana dashboard

`examples/observability/grafana/dashboards/omega.json` is the canonical
"Omega control plane" dashboard. It has nine panels covering build info,
totals, HTTP rate / latency, decision rate / latency, SVID issuance by
kind, and audit appends by kind. Import it into your own Grafana via
**Dashboards → New → Import → Upload JSON file**.

## Suggested alerts

These are starting points - tune thresholds against your traffic.

```yaml
groups:
  - name: omega
    rules:
      - alert: OmegaHighDenyRate
        expr: |
          sum(rate(omega_access_decisions_total{decision="deny"}[5m]))
            / sum(rate(omega_access_decisions_total[5m])) > 0.5
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Omega is denying more than 50% of access decisions"

      - alert: OmegaDecisionLatencyHigh
        expr: |
          histogram_quantile(0.99,
            sum by (le) (rate(omega_access_decision_duration_seconds_bucket[5m]))
          ) > 0.05
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Omega p99 decision evaluation latency above 50ms"

      - alert: OmegaHTTP5xxRate
        expr: |
          sum(rate(omega_http_requests_total{code=~"5.."}[5m])) > 0.1
        for: 10m
        labels: { severity: critical }
        annotations:
          summary: "Omega HTTP 5xx rate above 0.1/s"
```

## Tracing

`omega-server` and `omega agent` both speak OpenTelemetry. Tracing is
opt-in: with no configuration the SDK is a no-op (no exporter, no
overhead). Set one of the following to turn it on:

| Mechanism                                   | Effect                                   |
| ------------------------------------------- | ---------------------------------------- |
| `--otlp-endpoint host:port`                 | OTLP/HTTP exporter to that endpoint      |
| env `OTEL_EXPORTER_OTLP_ENDPOINT=host:port` | same, via the standard OTel env var      |
| env `OTEL_TRACES_EXPORTER=stdout`           | pretty-print spans to stderr (debugging) |
| env `OTEL_SDK_DISABLED=true`                | force no-op even if endpoint is set      |

Add `--otlp-insecure` (or `OTEL_EXPORTER_OTLP_INSECURE=true`) when
talking to a collector over plaintext HTTP - typical inside a cluster.

The example stack at `examples/observability/` runs an
`otel/opentelemetry-collector-contrib` instance on `:4318` that batches
spans and forwards them to a `jaegertracing/all-in-one` container; the
Jaeger UI is exposed on <http://localhost:16686>.

### Span schema

| Span name          | Parent        | Key attributes                                                                       |
| ------------------ | ------------- | ------------------------------------------------------------------------------------ |
| `<METHOD> <route>` | incoming HTTP | `http.request.method`, `http.route`, `http.response.status_code` (otelhttp defaults) |
| `policy.Evaluate`  | HTTP          | `authzen.subject.id`, `authzen.action`, `authzen.resource.type`, `authzen.decision`  |
| `ca.IssueSVID`     | HTTP          | `spiffe.id`, `svid.not_after`                                                        |
| `ca.IssueJWTSVID`  | HTTP          | `spiffe.id`, `jwt.audience`, `jwt.kid`, `rfc8705.bound`                              |
| `audit.append`     | HTTP          | `audit.kind`, `audit.subject`, `audit.decision`                                      |

W3C TraceContext is propagated end-to-end: an agent's
`FetchX509SVID` / `FetchJWTSVID` call (instrumented via `otelgrpc`)
appears as the parent of the control plane's `ca.Issue*` span, so a
single trace covers the workload's identity request from socket to CA
and audit log.

### Wiring into an existing collector

Point omega at your collector's OTLP/HTTP receiver:

```bash
omega server \
  --otlp-endpoint otel-collector.observability.svc.cluster.local:4318 \
  --otlp-insecure
```

Or rely on the standard env vars (`OTEL_EXPORTER_OTLP_ENDPOINT`,
`OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_RESOURCE_ATTRIBUTES`, …) so omega
fits whatever sidecar / DaemonSet collector convention your platform
already uses.
