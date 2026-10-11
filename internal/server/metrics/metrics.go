// Package metrics exposes the Prometheus collectors used by the omega control plane.
//
// The registry is dedicated (not the global default) so the surface stays
// minimal and predictable. Handlers and storage code increment counters
// directly via the package-level vars.
package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	Registry = prometheus.NewRegistry()

	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "omega_build_info",
		Help: "Omega build information; value is always 1, version label carries the build.",
	}, []string{"version"})

	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omega_http_requests_total",
		Help: "Total HTTP requests handled by the omega control plane.",
	}, []string{"method", "route", "code"})

	HTTPLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "omega_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, by method and route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	SVIDIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omega_svid_issued_total",
		Help: "Total SVIDs issued, by kind (x509 / jwt).",
	}, []string{"kind"})

	Decisions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omega_access_decisions_total",
		Help: "Total AuthZEN access decisions, by decision (allow / deny).",
	}, []string{"decision"})

	DecisionLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "omega_access_decision_duration_seconds",
		Help:    "AuthZEN policy evaluation latency in seconds.",
		Buckets: []float64{.0001, .0005, .001, .005, .01, .025, .05, .1, .25, .5, 1},
	})

	AuditAppended = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "omega_audit_appended_total",
		Help: "Total audit log entries appended, by kind.",
	}, []string{"kind"})

	DomainsUnprojected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "omega_domains_unprojected",
		Help: "Stored domains left out of policy evaluation because their names are invalid; a forbid on them matches nothing.",
	})

	DomainsCreated = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "omega_domains_created_total",
		Help: "Total domains created via the admin API.",
	})
)

func init() {
	Registry.MustRegister(
		BuildInfo, HTTPRequests, HTTPLatency,
		SVIDIssued, Decisions, DecisionLatency, AuditAppended, DomainsCreated, DomainsUnprojected,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
}

// SetBuildInfo sets the omega_build_info gauge to 1 with the given version label.
func SetBuildInfo(version string) {
	BuildInfo.WithLabelValues(version).Set(1)
}

// Handler returns the http.Handler that exposes the registry on /metrics.
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{Registry: Registry})
}

type recorder struct {
	http.ResponseWriter
	code int
}

func (r *recorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

// InstrumentHandler wraps an http.HandlerFunc and records request count + latency.
// pattern is the Go 1.22 ServeMux pattern (e.g. "POST /v1/domains") so cardinality
// stays bounded regardless of variable path segments.
func InstrumentHandler(pattern string, h http.HandlerFunc) http.HandlerFunc {
	method, route, ok := strings.Cut(pattern, " ")
	if !ok {
		method, route = "ANY", pattern
	}
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, code: http.StatusOK}
		h(rec, r)
		HTTPLatency.WithLabelValues(method, route).Observe(time.Since(start).Seconds())
		HTTPRequests.WithLabelValues(method, route, strconv.Itoa(rec.code)).Inc()
	}
}
