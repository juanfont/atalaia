package llm

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSemaphore_AcquireRelease(t *testing.T) {
	s := NewSemaphore(2, 10)
	if err := s.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if got := s.Inflight(); got != 1 {
		t.Errorf("Inflight=%d, want 1", got)
	}
	s.Release()
	if got := s.Inflight(); got != 0 {
		t.Errorf("post-Release Inflight=%d, want 0", got)
	}
	if got := s.QueueDepth(); got != 0 {
		t.Errorf("post-Release QueueDepth=%d, want 0", got)
	}
}

func TestSemaphore_QueueFull(t *testing.T) {
	// queue_max == max_inflight so the very next Acquire after the
	// first one trips the depth check and returns ErrQueueFull without
	// ever touching the slot channel — no goroutine timing required.
	s := NewSemaphore(1, 1)
	if err := s.Acquire(context.Background()); err != nil {
		t.Fatalf("first Acquire: %v", err)
	}
	defer s.Release()

	err := s.Acquire(context.Background())
	if !errors.Is(err, ErrQueueFull) {
		t.Errorf("got %v, want ErrQueueFull", err)
	}
}

func TestSemaphore_CtxCancel(t *testing.T) {
	s := NewSemaphore(1, 10)
	_ = s.Acquire(context.Background())
	defer s.Release()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := s.Acquire(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ctx-cancelled Acquire: got %v, want DeadlineExceeded", err)
	}
	if got := s.QueueDepth(); got != 1 {
		t.Errorf("QueueDepth after cancel=%d, want 1 (the running call)", got)
	}
}

// TryAcquire is the deep read's admission path. It must never queue:
// a busy slot means "not now", not "wait your turn", so the deep read
// cannot occupy queue_max capacity that adjudication needs.
func TestSemaphore_TryAcquire_FreeSlot(t *testing.T) {
	s := NewSemaphore(1, 16)
	if !s.TryAcquire(context.Background(), 0) {
		t.Fatal("a free slot must be taken immediately")
	}
	if s.Inflight() != 1 {
		t.Errorf("Inflight = %d, want 1", s.Inflight())
	}
	s.Release()
	if s.Inflight() != 0 || s.QueueDepth() != 0 {
		t.Errorf("after Release: inflight=%d depth=%d, want 0/0", s.Inflight(), s.QueueDepth())
	}
}

func TestSemaphore_TryAcquire_BusySlotDoesNotWaitOrQueue(t *testing.T) {
	s := NewSemaphore(1, 16)
	if err := s.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Release()

	start := time.Now()
	if s.TryAcquire(context.Background(), 0) {
		t.Fatal("busy slot with zero wait must be refused")
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Errorf("zero-wait TryAcquire blocked for %v", time.Since(start))
	}
	if s.QueueDepth() != 1 {
		t.Errorf("a refused TryAcquire must not count as a waiter: depth=%d, want 1", s.QueueDepth())
	}
}

// Even with a wait budget, a slot must not be taken while an Acquire
// caller is queued for it: those are adjudications, and the deep read
// yields to them. Otherwise the wait could jump the queue.
func TestSemaphore_TryAcquire_YieldsToWaiters(t *testing.T) {
	s := NewSemaphore(1, 16)
	if err := s.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}

	waiting := make(chan struct{})
	go func() {
		close(waiting)
		_ = s.Acquire(context.Background()) // blocks: slot is held
		s.Release()
	}()
	<-waiting
	// Let the goroutine register as a waiter (depth 2 = 1 running + 1 waiting).
	deadline := time.Now().Add(time.Second)
	for s.QueueDepth() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.QueueDepth() != 2 {
		t.Fatalf("test setup: depth=%d, want 2", s.QueueDepth())
	}

	start := time.Now()
	got := s.TryAcquire(context.Background(), 500*time.Millisecond)
	if got {
		t.Fatal("must not take a slot while an Acquire caller is waiting for it")
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Errorf("should refuse immediately when waiters exist, took %v", time.Since(start))
	}
	s.Release() // lets the waiter through and finish
}

func TestSemaphore_TryAcquire_BoundedWaitSucceeds(t *testing.T) {
	s := NewSemaphore(1, 16)
	if err := s.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		s.Release()
	}()

	if !s.TryAcquire(context.Background(), 500*time.Millisecond) {
		t.Fatal("slot freed within the wait budget must be taken")
	}
	s.Release()
}
