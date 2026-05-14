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
