// Package localpdp is the node agent's local policy decision point. It
// keeps a copy of the control plane's policy bundle, answers AuthZEN
// evaluations from it on the node, and ships every decision back to the
// control plane's audit chain.
package localpdp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kanywst/omega/internal/server/policy"
)

// Config tunes the local PDP.
type Config struct {
	// ServerURL is the control plane's base URL.
	ServerURL string
	// HTTPClient talks to the control plane; nil uses a default client.
	HTTPClient *http.Client
	// SyncInterval is how often the bundle is re-fetched.
	SyncInterval time.Duration
	// MaxAge is how old the last successful sync may be before the local
	// PDP refuses to decide (fail closed).
	MaxAge time.Duration
	// FlushInterval is how often decisions are shipped to the audit chain.
	FlushInterval time.Duration
	// BufferSize caps decisions waiting to be shipped. When it is full the
	// local PDP refuses to decide rather than make an unrecorded decision.
	BufferSize int
}

// PDP evaluates locally against the last synced bundle.
type PDP struct {
	cfg    Config
	engine *policy.Engine
	client *http.Client

	mu       sync.Mutex
	revision string
	synced   time.Time
	pending  []queued
}

type decision struct {
	ID        string              `json:"id"`
	DecidedAt time.Time           `json:"decided_at"`
	Request   policy.EvalRequest  `json:"request"`
	Response  policy.EvalResponse `json:"response"`
}

// queued is a decision encoded for shipping, with the bundle revision
// it was made with.
type queued struct {
	raw      json.RawMessage
	revision string
}

const (
	// MaxRequestBytes caps one evaluation request, so a single decision
	// always fits in a batch the control plane accepts.
	MaxRequestBytes = 64 << 10
	// maxBatchBytes keeps a batch well under the control plane's 1 MiB
	// body limit; maxBatchDecisions matches its per-batch cap.
	maxBatchBytes     = 768 << 10
	maxBatchDecisions = 1000
)

// New returns a PDP that has not synced yet; it refuses to decide until
// the first Sync succeeds.
func New(cfg Config) *PDP {
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 10 * time.Second
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 6 * cfg.SyncInterval
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
	}
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	return &PDP{cfg: cfg, engine: policy.New(), client: c}
}

// Run syncs and flushes until ctx is done.
func (p *PDP) Run(ctx context.Context) {
	syncT := time.NewTicker(p.cfg.SyncInterval)
	flushT := time.NewTicker(p.cfg.FlushInterval)
	defer syncT.Stop()
	defer flushT.Stop()
	if err := p.Sync(ctx); err != nil {
		slog.Warn("local pdp: initial bundle sync failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			// Best effort: ship what is buffered before exiting.
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = p.Flush(flushCtx)
			cancel()
			return
		case <-syncT.C:
			if err := p.Sync(ctx); err != nil {
				slog.Warn("local pdp: bundle sync failed", "err", err)
			}
		case <-flushT.C:
			if err := p.Flush(ctx); err != nil {
				slog.Warn("local pdp: decision flush failed", "err", err)
			}
		}
	}
}

// Sync fetches the bundle and loads it if it changed.
func (p *PDP) Sync(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(p.cfg.ServerURL, "/")+"/v1/policy/bundle", nil)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.revision != "" {
		req.Header.Set("If-None-Match", `"`+p.revision+`"`)
	}
	p.mu.Unlock()
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch bundle: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		p.mu.Lock()
		p.synced = time.Now()
		p.mu.Unlock()
		return nil
	case http.StatusOK:
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("fetch bundle: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var b policy.Bundle
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&b); err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}
	if err := p.engine.LoadBundle(b); err != nil {
		return err
	}
	p.mu.Lock()
	p.revision = b.Revision
	p.synced = time.Now()
	p.mu.Unlock()
	return nil
}

// ErrUnavailable is returned when the PDP must not decide.
var ErrUnavailable = errors.New("local pdp unavailable")

// Evaluate decides locally and queues the decision for the audit chain.
func (p *PDP) Evaluate(req policy.EvalRequest) (policy.EvalResponse, error) {
	p.mu.Lock()
	synced, waiting := p.synced, len(p.pending)
	p.mu.Unlock()
	if synced.IsZero() || time.Since(synced) > p.cfg.MaxAge {
		return policy.EvalResponse{}, fmt.Errorf("%w: the policy bundle has not synced within %s", ErrUnavailable, p.cfg.MaxAge)
	}
	if waiting >= p.cfg.BufferSize {
		return policy.EvalResponse{}, fmt.Errorf("%w: %d decisions are waiting to be recorded", ErrUnavailable, waiting)
	}
	// The engine reports the revision it decided with, so a sync racing
	// this call cannot mislabel the decision.
	resp, rev, err := p.engine.EvaluateRevision(req)
	if err != nil {
		return policy.EvalResponse{}, err
	}
	raw, err := json.Marshal(decision{ID: newID(), DecidedAt: time.Now().UTC(), Request: req, Response: resp})
	if err != nil {
		return policy.EvalResponse{}, err
	}
	p.mu.Lock()
	p.pending = append(p.pending, queued{raw: raw, revision: rev})
	p.mu.Unlock()
	return resp, nil
}

// Flush ships queued decisions in batches; on a failed batch it keeps
// that batch and everything after it for the next attempt.
func (p *PDP) Flush(ctx context.Context) error {
	for {
		p.mu.Lock()
		if len(p.pending) == 0 {
			p.mu.Unlock()
			return nil
		}
		// A batch carries one bundle revision and stays under the
		// control plane's body and count limits.
		rev := p.pending[0].revision
		n, size := 0, 0
		for n < len(p.pending) && n < maxBatchDecisions && p.pending[n].revision == rev {
			if n > 0 && size+len(p.pending[n].raw)+1 > maxBatchBytes {
				break
			}
			size += len(p.pending[n].raw) + 1
			n++
		}
		batch := make([]json.RawMessage, n)
		for i := range batch {
			batch[i] = p.pending[i].raw
		}
		p.mu.Unlock()

		body, err := json.Marshal(map[string]any{"bundle_revision": rev, "decisions": batch})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.cfg.ServerURL, "/")+"/v1/audit/decisions", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := p.client.Do(req)
		if err != nil {
			return fmt.Errorf("ship decisions: %w", err)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("ship decisions: %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		p.mu.Lock()
		p.pending = p.pending[n:]
		p.mu.Unlock()
	}
}

// Status reports the bundle revision, when it last synced, and how
// many decisions wait to be recorded.
func (p *PDP) Status() (revision string, synced time.Time, pending int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision, p.synced, len(p.pending)
}

// Handler serves POST /access/v1/evaluation and GET /healthz.
func (p *PDP) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /access/v1/evaluation", func(w http.ResponseWriter, r *http.Request) {
		var req policy.EvalRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBytes)).Decode(&req); err != nil {
			code := http.StatusBadRequest
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				code = http.StatusRequestEntityTooLarge
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		resp, err := p.Evaluate(req)
		switch {
		case errors.Is(err, ErrUnavailable):
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		default:
			writeJSON(w, http.StatusOK, resp)
		}
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		rev, synced, pending := p.Status()
		writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "synced_at": synced, "pending_decisions": pending})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
