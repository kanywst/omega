package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/kanywst/omega/internal/server/storage"
)

// PumpConfig tunes the polling cadence of Pump. Defaults are chosen so
// a busy server (10s of events/sec) flushes within ~1s and an idle one
// stays cheap.
type PumpConfig struct {
	BatchSize    int
	PollInterval time.Duration
}

// Pump reads new audit events out of the store on a timer and hands
// them to one Forwarder. Watermark advancement is per-Forwarder so
// running multiple Pumps against the same store (e.g. webhook + OTLP)
// is independent - a slow or broken sink only blocks its own delivery.
type Pump struct {
	store *storage.Store
	fwd   Forwarder
	cfg   PumpConfig
}

// NewPump validates cfg and returns a ready-to-Run pump. Defaults:
// batch 100 events at a time, poll every second.
func NewPump(store *storage.Store, fwd Forwarder, cfg PumpConfig) *Pump {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Second
	}
	return &Pump{store: store, fwd: fwd, cfg: cfg}
}

// Run blocks until ctx is canceled. On every tick it asks the store
// for events with seq > watermark, forwards them, and (only on
// success) advances the watermark. Failures are logged but never
// terminal - the next tick retries the same range so the chain
// remains the source of truth even if the sink is temporarily down.
func (p *Pump) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.PollInterval)
	defer t.Stop()
	// Drain immediately so a server restart with a backlog flushes
	// before the first tick wait.
	p.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.tick(ctx)
		}
	}
}

func (p *Pump) tick(ctx context.Context) {
	// Followers must not forward - the leader is the single source of
	// delivery so receivers don't see two copies of the same event.
	// SQLite and Postgres-without-leader-election always report leader,
	// so non-HA deployments are unaffected.
	if !p.store.IsLeader() {
		return
	}
	since, err := p.store.AuditForwardSeq(ctx, p.fwd.Name())
	if err != nil {
		slog.Warn("audit forward: watermark read failed", "forwarder", p.fwd.Name(), "err", err)
		return
	}
	events, err := p.store.ListAudit(ctx, since, p.cfg.BatchSize)
	if err != nil {
		slog.Warn("audit forward: list failed", "forwarder", p.fwd.Name(), "since", since, "err", err)
		return
	}
	if len(events) == 0 {
		return
	}
	if err := p.fwd.Forward(ctx, events); err != nil {
		slog.Warn("audit forward: send failed", "forwarder", p.fwd.Name(), "count", len(events), "err", err)
		return
	}
	last := events[len(events)-1].Seq
	if err := p.store.SetAuditForwardSeq(ctx, p.fwd.Name(), last); err != nil {
		slog.Warn("audit forward: watermark write failed", "forwarder", p.fwd.Name(), "seq", last, "err", err)
		return
	}
	slog.Info("audit forward: delivered", "forwarder", p.fwd.Name(), "count", len(events), "seq_high", last)
}
