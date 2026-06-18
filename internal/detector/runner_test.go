package detector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// blockingDetector blocks inside Scan until release is closed (or ctx
// is done), tracking peak concurrency so a test can assert the
// semaphore bounds it.
type blockingDetector struct {
	name    string
	release <-chan struct{}
	current *int32
	peak    *int32
}

func (b *blockingDetector) Name() string { return b.name }

func (b *blockingDetector) Scan(ctx context.Context, _ []byte) ([]Finding, error) {
	n := atomic.AddInt32(b.current, 1)
	for {
		p := atomic.LoadInt32(b.peak)
		if n <= p || atomic.CompareAndSwapInt32(b.peak, p, n) {
			break
		}
	}
	defer atomic.AddInt32(b.current, -1)
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, nil
}

func blockers(n int, release <-chan struct{}, current, peak *int32) []Detector {
	dets := make([]Detector, n)
	for i := range dets {
		dets[i] = &blockingDetector{
			name:    "d" + string(rune('a'+i)),
			release: release,
			current: current,
			peak:    peak,
		}
	}
	return dets
}

func TestRun_SemaphoreBoundsConcurrency(t *testing.T) {
	const limit = 2
	sem := make(chan struct{}, limit)
	release := make(chan struct{})
	var current, peak int32

	done := make(chan struct{})
	go func() {
		Run(context.Background(), nil, blockers(6, release, &current, &peak), sem)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond) // let the first wave grab slots and block
	if got := atomic.LoadInt32(&peak); got > limit {
		t.Errorf("peak concurrency %d exceeded limit %d", got, limit)
	}
	close(release)
	<-done

	if got := atomic.LoadInt32(&peak); got != limit {
		t.Errorf("final peak concurrency = %d, want exactly %d", got, limit)
	}
}

func TestRun_NilSemaphoreUnbounded(t *testing.T) {
	const n = 5
	release := make(chan struct{})
	var current, peak int32

	done := make(chan struct{})
	go func() {
		Run(context.Background(), nil, blockers(n, release, &current, &peak), nil)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	close(release)
	<-done

	if got := atomic.LoadInt32(&peak); got != n {
		t.Errorf("nil semaphore should let all %d run; peak = %d", n, got)
	}
}

func TestRun_CtxCancelTurnsAwayQueuedScans(t *testing.T) {
	// One slot held by a blocker; the rest queue. Cancelling the
	// context should make the queued detectors error with ctx.Err()
	// without ever entering Scan.
	// Pre-fill the only slot from the test, so no detector can acquire.
	// Both detectors queue; cancelling the context is then the only way
	// their acquire select can resolve, so neither enters Scan.
	sem := make(chan struct{}, 1)
	sem <- struct{}{}

	var entered int32
	queued := detectorFunc{name: "queued", fn: func(context.Context) ([]Finding, error) {
		atomic.AddInt32(&entered, 1)
		return nil, nil
	}}

	ctx, cancel := context.WithCancel(context.Background())
	var errs map[string]error
	done := make(chan struct{})
	go func() {
		_, errs = Run(ctx, nil, []Detector{queued}, sem)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond) // queued is now parked at the full semaphore
	cancel()
	<-done

	if atomic.LoadInt32(&entered) != 0 {
		t.Error("queued detector entered Scan despite cancel; should have been turned away at the semaphore")
	}
	if !errors.Is(errs["queued"], context.Canceled) {
		t.Errorf("queued detector error = %v, want context.Canceled", errs["queued"])
	}
}

// detectorFunc adapts a func to the Detector interface for tests.
type detectorFunc struct {
	name string
	fn   func(ctx context.Context) ([]Finding, error)
}

func (d detectorFunc) Name() string                                          { return d.name }
func (d detectorFunc) Scan(ctx context.Context, _ []byte) ([]Finding, error) { return d.fn(ctx) }
