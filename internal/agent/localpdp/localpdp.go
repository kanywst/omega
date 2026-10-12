// Package localpdp is the node agent's local policy decision point. It
// keeps a copy of the control plane's policy bundle, answers AuthZEN
// evaluations from it on the node, and ships every decision back to the
// control plane's audit chain.
package localpdp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
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
	// TrustDomain is the only trust domain a bundle may be for; a
	// bundle for another one, or for none, is refused, and without it
	// no bundle is loaded at all.
	TrustDomain string
	// BundleKey, when set, is the control plane's bundle signing key: a
	// bundle without a valid signature from it is refused.
	BundleKey *ecdsa.PublicKey
	// SpoolPath, when set, is a file every decision is written and
	// synced to before it is answered, so decisions survive a crash of
	// the agent; RestoreSpool reloads them at start.
	SpoolPath string
}

// PDP evaluates locally against the last synced bundle.
type PDP struct {
	cfg    Config
	engine *policy.Engine
	client *http.Client

	mu       sync.Mutex
	revision string
	issuedAt time.Time // newest signed bundle loaded
	synced   time.Time
	pending  []queued
	// reserved counts decisions being made that already hold a buffer
	// slot, so concurrent callers cannot overrun BufferSize.
	reserved int
	// droppedIDs are decisions discarded after the control plane
	// rejected them, until it has recorded the loss under lossID, which
	// stays the same across retries so a reader can dedupe the report.
	droppedIDs []string
	lossID     string
	// dropStreak counts drops since a decision was last recorded, and
	// dropTimes when each recent drop happened.
	dropStreak int
	dropTimes  []time.Time
	// droppedDigests holds a SHA-256 of each dropped decision, request
	// and response included, so the loss stays attributable.
	droppedDigests []string
	// batchCap shrinks while the control plane rejects batches, to
	// isolate the decision it will not accept.
	batchCap int

	// spoolMu serialises spool writes; take it before mu.
	spoolMu sync.Mutex
	spool   *os.File
}

// spoolEntry is one line of the spool file.
type spoolEntry struct {
	ID       string          `json:"id"`
	Revision string          `json:"revision"`
	Decision json.RawMessage `json:"decision"`
}

// RestoreSpool opens the spool and requeues every decision in it: ones
// answered before a crash or restart that never reached the control
// plane. Call it once, before serving. Without SpoolPath it does nothing.
func (p *PDP) RestoreSpool() error {
	if p.cfg.SpoolPath == "" {
		return nil
	}
	p.spoolMu.Lock()
	defer p.spoolMu.Unlock()
	// #nosec G304 -- operator-supplied --decision-spool path.
	raw, err := os.ReadFile(p.cfg.SpoolPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read decision spool: %w", err)
	}
	var restored []queued
	lines := bytes.Split(raw, []byte("\n"))
	last := len(lines) - 1
	for last >= 0 && len(bytes.TrimSpace(lines[last])) == 0 {
		last--
	}
	for i, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e spoolEntry
		if err := json.Unmarshal(line, &e); err != nil {
			if i == last {
				// A torn last line is what a crash mid-write leaves; its
				// decision was never answered, so it is safe to skip.
				slog.Warn("local pdp: skipping a torn last line in the decision spool", "line", i+1, "err", err)
				continue
			}
			// Anywhere else it is an answered decision that would never
			// reach the chain: refuse to start rather than lose it quietly.
			return fmt.Errorf("decision spool line %d is unreadable: %w", i+1, err)
		}
		restored = append(restored, queued{id: e.ID, raw: e.Decision, revision: e.Revision})
	}
	if t, err := p.loadIssuedAt(); err != nil {
		return err
	} else if !t.IsZero() {
		p.mu.Lock()
		p.issuedAt = t
		p.mu.Unlock()
	}
	p.mu.Lock()
	p.pending = append(restored, p.pending...)
	p.mu.Unlock()
	if len(restored) > 0 {
		slog.Info("local pdp: requeued decisions from the spool", "decisions", len(restored))
	}
	return p.rewriteSpoolLocked()
}

// spoolDecision writes q to the spool and syncs it. Callers hold spoolMu.
func (p *PDP) spoolDecision(q queued) error {
	line, err := json.Marshal(spoolEntry{ID: q.id, Revision: q.revision, Decision: q.raw})
	if err != nil {
		return err
	}
	st, err := p.spool.Stat()
	if err != nil {
		return fmt.Errorf("stat decision spool: %w", err)
	}
	werr := writeSync(p.spool, append(line, '\n'))
	if werr == nil {
		return nil
	}
	// The decision is answered with an error, so none of its bytes may
	// stay: a partial line would merge with the next one and take an
	// answered decision with it, and a synced-but-failed line would
	// requeue a decision nobody received. Cut back to where it started,
	// or rebuild the file from what is pending.
	if terr := p.spool.Truncate(st.Size()); terr != nil {
		if rerr := p.rewriteSpoolLocked(); rerr != nil {
			return fmt.Errorf("%w; and the spool could not be repaired: %v", werr, rerr)
		}
	}
	return werr
}

// spoolFile is the part of *os.File the spool writes through; tests swap
// in one that fails.
type spoolFile interface {
	Write([]byte) (int, error)
	Sync() error
}

var writeSync = func(f spoolFile, b []byte) error {
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write decision spool: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync decision spool: %w", err)
	}
	return nil
}

// rewriteSpoolLocked replaces the spool with what is still pending.
// Callers hold spoolMu.
func (p *PDP) rewriteSpoolLocked() error {
	p.mu.Lock()
	pending := slices.Clone(p.pending)
	p.mu.Unlock()
	tmp := p.cfg.SpoolPath + ".tmp"
	// #nosec G304 -- derived from the operator-supplied spool path.
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("rewrite decision spool: %w", err)
	}
	w := bufio.NewWriter(f)
	for _, q := range pending {
		line, err := json.Marshal(spoolEntry{ID: q.id, Revision: q.revision, Decision: q.raw})
		if err != nil {
			_ = f.Close()
			return err
		}
		_, _ = w.Write(append(line, '\n'))
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return fmt.Errorf("rewrite decision spool: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("rewrite decision spool: %w", err)
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.cfg.SpoolPath); err != nil {
		return fmt.Errorf("rewrite decision spool: %w", err)
	}
	if p.spool != nil {
		_ = p.spool.Close()
	}
	// #nosec G304 -- operator-supplied --decision-spool path.
	p.spool, err = os.OpenFile(p.cfg.SpoolPath, os.O_APPEND|os.O_WRONLY, 0o600)
	return err
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
	id       string
	raw      json.RawMessage
	revision string
}

// maxDropStreak is how many decisions in a row may be dropped as
// rejected before the PDP stops dropping and fails closed: one bad
// decision is isolated, a control plane rejecting everything is not
// allowed to empty the queue unrecorded.
const maxDropStreak = 3

// maxDropsPerHour bounds drops over time too, so a control plane that
// rejects every other batch cannot have decisions discarded without
// limit.
const maxDropsPerHour = 10

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
	// With a signing key every refresh must be a signed 200: a 304 carries
	// no signature, so honouring it would let whoever answers the poll
	// keep the agent on a stale bundle past --policy-max-age.
	p.mu.Lock()
	if p.revision != "" && p.cfg.BundleKey == nil {
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
		if p.cfg.BundleKey != nil {
			return errors.New("fetch bundle: unsigned 304 when a signed bundle is required")
		}
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
	if p.cfg.TrustDomain == "" {
		return errors.New("no trust domain configured: refusing to load a bundle that cannot be checked")
	}
	if b.Directory.TrustDomain != p.cfg.TrustDomain {
		return fmt.Errorf("bundle is for trust domain %q, not %q", b.Directory.TrustDomain, p.cfg.TrustDomain)
	}
	if p.cfg.BundleKey != nil {
		if err := policy.CheckRevision(b); err != nil {
			return err
		}
		if err := policy.VerifyBundle(b, p.cfg.BundleKey); err != nil {
			return err
		}
		// A validly signed bundle can still be an old one replayed: refuse
		// one issued before the newest already loaded, or too long ago to
		// be current.
		p.mu.Lock()
		newest := p.issuedAt
		p.mu.Unlock()
		if b.IssuedAt.Before(newest) {
			return fmt.Errorf("bundle issued at %s is older than the one already loaded (%s)", b.IssuedAt, newest)
		}
		if age := time.Since(b.IssuedAt); age > p.cfg.MaxAge {
			return fmt.Errorf("bundle was issued %s ago, longer than --policy-max-age", age.Round(time.Second))
		}
		if ahead := time.Until(b.IssuedAt); ahead > maxClockSkew {
			return fmt.Errorf("bundle is issued %s in the future; check the clocks", ahead.Round(time.Second))
		}
	}
	if err := p.engine.LoadBundle(b); err != nil {
		return err
	}
	p.mu.Lock()
	p.revision = b.Revision
	advanced := b.IssuedAt.After(p.issuedAt)
	if advanced {
		p.issuedAt = b.IssuedAt
	}
	p.synced = time.Now()
	p.mu.Unlock()
	if advanced {
		p.saveIssuedAt(b.IssuedAt)
	}
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
	id := newID()
	raw, err := json.Marshal(decision{ID: id, DecidedAt: time.Now().UTC(), Request: req, Response: resp})
	if err != nil {
		return policy.EvalResponse{}, err
	}
	q := queued{id: id, raw: raw, revision: rev}
	if p.cfg.SpoolPath != "" {
		// On disk before it is answered: a crash after this point loses
		// nothing; a failed write answers an error instead of a decision.
		p.spoolMu.Lock()
		defer p.spoolMu.Unlock()
		if p.spool == nil {
			return policy.EvalResponse{}, errors.New("decision spool is not open")
		}
		if err := p.spoolDecision(q); err != nil {
			return policy.EvalResponse{}, err
		}
	}
	p.mu.Lock()
	p.pending = append(p.pending, q)
	p.reserved--
	p.mu.Unlock()
	queuedOK = true
	return resp, nil
}

// Flush ships queued decisions in batches; on a failed batch it keeps
// that batch and everything after it for the next attempt.
func (p *PDP) Flush(ctx context.Context) error {
	err := p.flush(ctx)
	if p.cfg.SpoolPath != "" {
		p.spoolMu.Lock()
		if serr := p.rewriteSpoolLocked(); serr != nil && err == nil {
			err = serr
		}
		p.spoolMu.Unlock()
	}
	return err
}

func (p *PDP) flush(ctx context.Context) error {
	for {
		p.mu.Lock()
		if len(p.pending) == 0 && len(p.droppedIDs) == 0 {
			p.mu.Unlock()
			return nil
		}
		limit := maxBatchDecisions
		if p.batchCap > 0 {
			limit = p.batchCap
		}
		droppedIDs, droppedDigests, lossID := slices.Clone(p.droppedIDs), slices.Clone(p.droppedDigests), p.lossID
		// A batch carries one bundle revision and stays under the
		// control plane's body and count limits.
		rev := ""
		if len(p.pending) > 0 {
			rev = p.pending[0].revision
		}
		n, size := 0, 0
		// A pending loss report goes out on its own, so a rejected
		// decision can never hold it back.
		for len(droppedIDs) == 0 && n < len(p.pending) && n < limit && p.pending[n].revision == rev {
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

		payload := map[string]any{"bundle_revision": rev, "decisions": batch}
		if len(droppedIDs) > 0 {
			payload["dropped"], payload["dropped_ids"], payload["dropped_digests"], payload["loss_id"] = len(droppedIDs), droppedIDs, droppedDigests, lossID
		}
		body, err := json.Marshal(payload)
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
				switch {
				case left > 1:
					p.batchCap = (left + 1) / 2
				case p.dropStreak >= maxDropStreak || p.recentDrops() >= maxDropsPerHour:
					// Too many rejections in a row: this is the control
					// plane, not one decision. Keep the queue; fail closed.
					p.mu.Unlock()
					return fmt.Errorf("ship decisions: %d rejected in a row, not dropping more: %d %s", p.dropStreak, resp.StatusCode, strings.TrimSpace(string(msg)))
				default:
					slog.Error("local pdp: control plane rejected a decision; dropping it", "id", p.pending[0].id, "status", resp.StatusCode, "body", strings.TrimSpace(string(msg)))
					if p.lossID == "" {
						p.lossID = newID()
					}
					p.droppedIDs = append(p.droppedIDs, p.pending[0].id)
					sum := sha256.Sum256(p.pending[0].raw)
					p.droppedDigests = append(p.droppedDigests, hex.EncodeToString(sum[:]))
					p.dropTimes = append(p.dropTimes, time.Now())
					p.pending = p.pending[1:]
					p.dropStreak++
					p.batchCap = 0
				}
				p.mu.Unlock()
				continue
			}
			return fmt.Errorf("ship decisions: %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
		}
		p.mu.Lock()
		p.pending = p.pending[n:]
		if len(droppedIDs) > 0 {
			p.droppedIDs = p.droppedIDs[len(droppedIDs):]
			p.droppedDigests = p.droppedDigests[len(droppedDigests):]
			if len(p.droppedIDs) == 0 {
				p.lossID = ""
			}
		}
		if n > 0 {
			p.dropStreak = 0
		}
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
		// A malformed request is the caller's fault (400); any other
		// failure to decide is ours (500). Neither returns a decision.
		if err := policy.Validate(req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		resp, err := p.Evaluate(req)
		switch {
		case errors.Is(err, ErrUnavailable):
			w.Header().Set("Retry-After", "5")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		case err != nil:
			slog.Error("local pdp: evaluation failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "evaluation failed"})
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

// recentDrops counts drops in the last hour. Callers hold p.mu.
func (p *PDP) recentDrops() int {
	cut := time.Now().Add(-time.Hour)
	keep := p.dropTimes[:0]
	for _, t := range p.dropTimes {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	p.dropTimes = keep
	return len(keep)
}

// maxClockSkew is how far in the future a signed bundle's issue time may
// be, to absorb clock differences between the agent and the control plane.
const maxClockSkew = time.Minute

// issuedAtPath keeps the newest signed bundle's issue time next to the
// spool, so a restarted agent still refuses older bundles.
func (p *PDP) issuedAtPath() string { return p.cfg.SpoolPath + ".bundle-issued-at" }

func (p *PDP) loadIssuedAt() (time.Time, error) {
	// #nosec G304 -- derived from the operator-supplied spool path.
	raw, err := os.ReadFile(p.issuedAtPath())
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("read bundle high-water mark: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(raw)))
	if err != nil {
		// A power loss can leave it empty. Losing it only narrows replay
		// protection to --policy-max-age until the next sync, so start.
		slog.Warn("local pdp: ignoring an unreadable bundle high-water mark", "err", err)
		return time.Time{}, nil
	}
	return t, nil
}

// saveIssuedAt records t when a spool is configured, synced before the
// rename so a power loss leaves the old or the new value. Called without
// mu held. A failure only weakens replay protection after a restart, so
// it is logged.
func (p *PDP) saveIssuedAt(t time.Time) {
	if p.cfg.SpoolPath == "" {
		return
	}
	if err := writeFileSync(p.issuedAtPath(), []byte(t.UTC().Format(time.RFC3339Nano))); err != nil {
		slog.Warn("local pdp: could not save the bundle high-water mark", "err", err)
	}
}

// writeFileSync writes data to path through a synced temporary file and
// a rename.
func writeFileSync(path string, data []byte) error {
	tmp := path + ".tmp"
	// #nosec G304 -- derived from the operator-supplied spool path.
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
