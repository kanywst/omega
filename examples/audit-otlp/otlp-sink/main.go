// otlp-sink is a minimal OTLP/HTTP-protobuf logs receiver for the
// examples/audit-otlp demo. It accepts POST /v1/logs bodies of
// content-type application/x-protobuf, decodes them as
// ExportLogsServiceRequest, and appends one JSONL line per
// LogRecord to --out. The body itself is also acknowledged with
// the partial-success envelope OTLP expects.
//
// The point of having a custom sink here (instead of pointing
// `omega server --audit-otlp-endpoint` at the OTel Collector) is
// that the demo's assertion loop can read the JSONL line by line
// and check the hash-chain fields the audit forwarder is supposed
// to surface as attributes - without standing up a Collector
// pipeline + Loki/Splunk just to read three rows.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:14318", "listen address")
	outPath := flag.String("out", "/tmp/otlp-sink.jsonl", "append decoded LogRecords as JSONL to this file")
	flag.Parse()

	out, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) // #nosec G304 -- demo binary, --out is an operator-supplied path
	if err != nil {
		log.Fatalf("otlp-sink: open %s: %v", *outPath, err)
	}
	defer out.Close()
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req := &collogspb.ExportLogsServiceRequest{}
		if err := proto.Unmarshal(body, req); err != nil {
			http.Error(w, "unmarshal: "+err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		for _, rl := range req.ResourceLogs {
			res := flattenAttrs(rl.GetResource().GetAttributes())
			for _, sl := range rl.GetScopeLogs() {
				for _, rec := range sl.GetLogRecords() {
					row := map[string]any{
						"ts":             time.Unix(0, int64(rec.GetTimeUnixNano())).UTC().Format(time.RFC3339Nano), // #nosec G115 -- post-1970 nanoseconds fit int64
						"severity":       rec.GetSeverityNumber().String(),
						"severity_text":  rec.GetSeverityText(),
						"body":           anyValue(rec.GetBody()),
						"attributes":     flattenAttrs(rec.GetAttributes()),
						"resource":       res,
					}
					line, _ := json.Marshal(row)
					_, _ = out.Write(append(line, '\n'))
				}
			}
		}
		mu.Unlock()
		// Empty 200 is the spec-compliant minimum for a successful
		// partial-success envelope - no rejected records to report.
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(emptySuccessResponse())
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("otlp-sink: listening on http://%s (out=%s)", *addr, *outPath)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("otlp-sink: listen: %v", err)
	}
}

func flattenAttrs(kvs []*commonpb.KeyValue) map[string]any {
	out := make(map[string]any, len(kvs))
	for _, kv := range kvs {
		out[kv.GetKey()] = anyValue(kv.GetValue())
	}
	return out
}

func anyValue(v *commonpb.AnyValue) any {
	if v == nil {
		return nil
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return x.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return x.DoubleValue
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue
	}
	return fmt.Sprintf("%v", v)
}

// emptySuccessResponse pre-marshals the all-zero
// ExportLogsServiceResponse so we do not allocate one per request.
func emptySuccessResponse() []byte {
	b, _ := proto.Marshal(&collogspb.ExportLogsServiceResponse{})
	if len(b) == 0 {
		// Some OTLP receivers send a single 0x00 byte; an empty body
		// is also valid. Use an empty slice but make sure the
		// caller still got Content-Type set.
		return bytes.NewBuffer(nil).Bytes()
	}
	return b
}
