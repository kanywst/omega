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
	// TrustDomain, when set, is the only trust domain a bundle may be
	// for; a bundle for another one, or for none, is refused.
	TrustDomain string
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
	// reserved counts decisions being made that already hold a buffer
	// slot, so concurrent callers cannot overrun BufferSize.
	reserved int
	// dropped counts decisions discarded after the control plane
	// rejected them, until it has recorded that they were lost.
	dropped int
	// batchCap shrinks while the control plane rejects batches, to
	// isolate the decision it will not accept.
	batchCap int
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
	if p.cfg.TrustDomain != "" && b.Directory.TrustDomain != p.cfg.TrustDomain {
		return fmt.Errorf("bundle is for trust domain %q, not %q", b.Directory.TrustDomain, p.cfg.TrustDomain)
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
	// Check freshness and take a buffer slot in one step, so concurrent
	// callers cannot all pass the check and overrun the buffer.
	p.mu.Lock()
	synced, waiting := p.synced, len(p.pending)+p.reserved
	if synced.IsZero() || time.Since(synced) > p.cfg.MaxAge {
		p.mu.Unlock()
		return policy.EvalResponse{}, fmt.Errorf("%w: the policy bundle has not synced within %s", ErrUnavailable, p.cfg.MaxAge)
	}
	if waiting >= p.cfg.BufferSize {
		p.mu.Unlock()
		return policy.EvalResponse{}, fmt.Errorf("%w: %d decisions are waiting to be recorded", ErrUnavailable, waiting)
	}
	p.reserved++
	p.mu.Unlock()
	queuedOK := false
	defer func() {
		if !queuedOK {
			p.mu.Lock()
			p.reserved--
			p.mu.Unlock()
		}
	}()
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
	p.reserved--
	p.mu.Unlock()
	queuedOK = true
	return resp, nil
}

// Flush ships queued decisions in batches; on a failed batch it keeps
// that batch and everything after it for the next attempt.
func (p *PDP) Flush(ctx context.Context) error {
	for {
		p.mu.Lock()
		if len(p.pending) == 0 && p.dropped == 0 {
			p.mu.Unlock()
			return nil
		}
		limit := maxBatchDecisions
		if p.batchCap > 0 {
			limit = p.batchCap
		}
		dropped := p.dropped
		// A batch carries one bundle revision and stays under the
		// control plane's body and count limits.
		rev := ""
		if len(p.pending) > 0 {
			rev = p.pending[0].revision
		}
		n, size := 0, 0
		// A pending loss report goes out on its own, so a rejected
		// decision can never hold it back.
		for dropped == 0 && n < len(p.pending) && n < limit && p.pending[n].revision == rev {
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

		body, err := json.Marshal(map[string]any{"bundle_revision": rev, "decisions": batch, "dropped": dropped})
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
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			// The control plane says how many of the batch it recorded
			// before failing; drop those, so a retry does not record
			// them twice.
			var partial struct {
				Recorded int `json:"recorded"`
			}
			if json.Unmarshal(msg, &partial) == nil && partial.Recorded > 0 && partial.Recorded < n {
				p.mu.Lock()
				p.pending = p.pending[partial.Recorded:]
				p.mu.Unlock()
			}
			// A batch the control plane cannot accept as sent would block
			// the queue forever. Halve the batch until the rejected
			// decision is alone, then drop just that one, loudly, and
			// have the control plane record that a decision was lost.
			// Any other refusal, such as 403 for an agent that is not a
			// decision recorder, keeps the batch, so the PDP fails closed
			// once the buffer fills.
			if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusRequestEntityTooLarge) && n > 0 {
				left := n
				if partial.Recorded > 0 && partial.Recorded < n {
					left -= partial.Recorded
				}
				p.mu.Lock()
				if left > 1 {
					p.batchCap = (left + 1) / 2
				} else {
					slog.Error("local pdp: control plane rejected a decision; dropping it", "status", resp.StatusCode, "body", strings.TrimSpace(string(msg)))
					p.pending = p.pending[1:]
					p.dropped++
					p.batchCap = 0
				}
				p.mu.Unlock()
				continue
			}
			return fmt.Errorf("ship decisions: %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		p.mu.Lock()
		p.pending = p.pending[n:]
		p.dropped -= dropped
		p.batchCap = 0
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
