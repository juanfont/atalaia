package llm

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// probeCounter is a ChatCompleter whose Probe behavior is controlled
// by an atomic state, so the test can flip "LLM reachable" mid-run.
type probeCounter struct {
	calls atomic.Int64
	fail  atomic.Bool
}

func (p *probeCounter) Complete(context.Context, ChatRequest) (ChatResponse, error) {
	return ChatResponse{}, nil
}

func (p *probeCounter) Probe(context.Context) error {
	p.calls.Add(1)
	if p.fail.Load() {
		return errors.New("simulated outage")
	}
	return nil
}

func TestReachabilityWatcher_StartProbesImmediately(t *testing.T) {
	pc := &probeCounter{}
	w := NewReachabilityWatcher(pc, 100*time.Millisecond)
	w.Start()
	defer w.Stop()

	// First probe runs synchronously inside the goroutine; wait a beat
	// for the goroutine to schedule it.
	if err := waitFor(50*time.Millisecond, func() bool { return w.Ready() }); err != nil {
		t.Fatalf("watcher never reported ready: %v", err)
	}
	if pc.calls.Load() < 1 {
		t.Errorf("expected at least one probe by now, got %d", pc.calls.Load())
	}
}

func TestReachabilityWatcher_FlipsToNotReadyOnFailure(t *testing.T) {
	pc := &probeCounter{}
	w := NewReachabilityWatcher(pc, 50*time.Millisecond)
	w.Start()
	defer w.Stop()

	if err := waitFor(200*time.Millisecond, func() bool { return w.Ready() }); err != nil {
		t.Fatalf("watcher never reported ready: %v", err)
	}

	pc.fail.Store(true)
	if err := waitFor(300*time.Millisecond, func() bool { return !w.Ready() }); err != nil {
		t.Fatalf("watcher did not flip to not-ready after failures: %v", err)
	}

	pc.fail.Store(false)
	if err := waitFor(300*time.Millisecond, func() bool { return w.Ready() }); err != nil {
		t.Fatalf("watcher did not recover after failure cleared: %v", err)
	}
}

func TestReachabilityWatcher_StaleCacheFailsClosed(t *testing.T) {
	pc := &probeCounter{}
	interval := 60 * time.Millisecond
	w := NewReachabilityWatcher(pc, interval)
	w.Start()
	if err := waitFor(150*time.Millisecond, func() bool { return w.Ready() }); err != nil {
		t.Fatalf("watcher never reported ready: %v", err)
	}
	w.Stop() // freeze the cache without further updates

	// Cache was just refreshed; should still read ready.
	if !w.Ready() {
		t.Errorf("expected Ready() == true immediately after Stop, got false")
	}

	// Sleep past staleMultiplier * interval. After that, even a true
	// last result must read as not ready, because the watcher hasn't
	// verified in too long.
	time.Sleep(interval*staleMultiplier + 50*time.Millisecond)
	if w.Ready() {
		t.Errorf("expected Ready() == false after staleness threshold, got true")
	}
}

func TestReachabilityWatcher_StopIsIdempotent(t *testing.T) {
	w := NewReachabilityWatcher(&probeCounter{}, 50*time.Millisecond)
	w.Start()
	w.Stop()
	w.Stop() // must not panic
}

func waitFor(d time.Duration, pred func() bool) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pred() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pred() {
		return nil
	}
	return errors.New("timeout")
}
