package llm

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/juanfont/atalaia/internal/metrics"
)

// ErrQueueFull is returned by Semaphore.Acquire when the total depth
// (running + waiting) is at or above queue_max. The API handler maps
// this to HTTP 503.
var ErrQueueFull = errors.New("llm queue full")

// Semaphore bounds concurrent LLM calls. Size N is set by
// llm.max_inflight. queueMax caps total depth (running + waiting)
// per llm.queue_max — anything past that is rejected immediately.
//
// QueueDepth and Inflight are read by the metrics layer in milestone 6.
type Semaphore struct {
	slots    chan struct{}
	queueMax int
	depth    int64
}

func NewSemaphore(maxInflight, queueMax int) *Semaphore {
	if maxInflight < 1 {
		maxInflight = 1
	}
	return &Semaphore{
		slots:    make(chan struct{}, maxInflight),
		queueMax: queueMax,
	}
}

// Acquire reserves one slot. If the queue is already full, it returns
// ErrQueueFull without waiting. Otherwise it blocks until a slot is
// free or ctx is cancelled. queue_depth and inflight gauges are kept
// in sync as a side effect.
func (s *Semaphore) Acquire(ctx context.Context) error {
	if s.queueMax > 0 && atomic.LoadInt64(&s.depth) >= int64(s.queueMax) {
		return ErrQueueFull
	}
	atomic.AddInt64(&s.depth, 1)
	metrics.LLMQueueDepth.Inc()
	select {
	case s.slots <- struct{}{}:
		metrics.LLMInflight.Inc()
		return nil
	case <-ctx.Done():
		atomic.AddInt64(&s.depth, -1)
		metrics.LLMQueueDepth.Dec()
		return ctx.Err()
	}
}

// TryAcquire takes a slot only if one is free, waiting at most wait
// for one to open, and never while another caller is queued in
// Acquire. It is the deep read's admission path.
//
// The difference from Acquire is the whole point: a refused TryAcquire
// is never a waiter. It does not bump depth, so it cannot push an
// Acquire caller past queue_max, and it yields to anyone already
// queued. Adjudication owns the queue; the deep read borrows idle
// capacity and steps aside the moment there is contention. Under load
// that means the deep read defers instead of turning the shallow
// result into a 503.
func (s *Semaphore) TryAcquire(ctx context.Context, wait time.Duration) bool {
	if s.waiters() > 0 {
		return false
	}
	if wait <= 0 {
		select {
		case s.slots <- struct{}{}:
		default:
			return false
		}
	} else {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case s.slots <- struct{}{}:
		case <-timer.C:
			return false
		case <-ctx.Done():
			return false
		}
	}
	// A waiter may have queued while we were waiting for the slot. It
	// has priority: hand the slot straight back rather than jump ahead.
	if s.waiters() > 0 {
		<-s.slots
		return false
	}
	atomic.AddInt64(&s.depth, 1)
	metrics.LLMQueueDepth.Inc()
	metrics.LLMInflight.Inc()
	return true
}

// waiters is how many Acquire callers are queued for a slot right now.
func (s *Semaphore) waiters() int64 {
	w := atomic.LoadInt64(&s.depth) - int64(len(s.slots))
	if w < 0 {
		return 0
	}
	return w
}

func (s *Semaphore) Release() {
	<-s.slots
	atomic.AddInt64(&s.depth, -1)
	metrics.LLMInflight.Dec()
	metrics.LLMQueueDepth.Dec()
}

// QueueDepth returns the current total depth (running + waiting).
func (s *Semaphore) QueueDepth() int64 { return atomic.LoadInt64(&s.depth) }

// Inflight returns the number of currently running calls.
func (s *Semaphore) Inflight() int { return len(s.slots) }
