package llm

import (
	"context"
	"sync"
	"time"
)

// ReachabilityWatcher polls the LLM endpoint at a fixed interval and
// caches the last result. /readyz reads the cache instead of probing
// on every call so a busy load balancer can't turn the readiness gate
// into an LLM DoS amplifier.
//
// The cached state is "fresh" only when the last probe completed less
// than staleMultiplier * interval ago; if the polling goroutine dies
// or the host wedges, Ready() falls to false and /readyz starts
// returning 503 so traffic gets shifted off.
type ReachabilityWatcher struct {
	client   ChatCompleter
	interval time.Duration

	mu        sync.RWMutex
	reachable bool
	lastCheck time.Time

	stop chan struct{}
	done chan struct{}
}

// staleMultiplier is how many intervals can elapse before we treat the
// cached state as unusable. Set to 3 so a single missed tick (slow
// probe, paused goroutine) doesn't flip readiness, but a stuck
// watcher does.
const staleMultiplier = 3

const defaultHealthcheckInterval = 30 * time.Second

// NewReachabilityWatcher builds a watcher. Call Start to begin
// polling; Stop to shut it down cleanly.
func NewReachabilityWatcher(client ChatCompleter, interval time.Duration) *ReachabilityWatcher {
	if interval <= 0 {
		interval = defaultHealthcheckInterval
	}
	return &ReachabilityWatcher{
		client:   client,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start kicks off the background polling goroutine. The first probe
// runs synchronously inside the goroutine so Ready() reflects real
// state shortly after Start returns instead of returning false during
// the warm-up.
func (w *ReachabilityWatcher) Start() {
	go w.loop()
}

// Stop signals the goroutine to exit and blocks until it does.
func (w *ReachabilityWatcher) Stop() {
	select {
	case <-w.stop:
		// already closed
	default:
		close(w.stop)
	}
	<-w.done
}

// Ready returns true when the last probe succeeded and was recent
// enough not to be considered stale.
func (w *ReachabilityWatcher) Ready() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.lastCheck.IsZero() {
		return false
	}
	if time.Since(w.lastCheck) > w.interval*staleMultiplier {
		return false
	}
	return w.reachable
}

func (w *ReachabilityWatcher) loop() {
	defer close(w.done)
	w.probeOnce()
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
			w.probeOnce()
		}
	}
}

func (w *ReachabilityWatcher) probeOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), w.interval)
	defer cancel()
	err := w.client.Probe(ctx)
	w.mu.Lock()
	w.reachable = err == nil
	w.lastCheck = time.Now()
	w.mu.Unlock()
}
