package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLimitBoundaryAndDistinctReasons(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	l := NewMemoryLimiter(Policy{MaxFailures: 5, Lockout: time.Minute,
		ThrottleAfter: 3, ThrottleDelay: time.Second, Window: 10 * time.Minute})
	ctx := context.Background()

	// Failures 1-2: admitted but counted.
	for i := 1; i <= 2; i++ {
		st, reason, err := l.RecordFailure(ctx, "bob", fmt.Sprintf("ev-%d", i), t0)
		if err != nil || reason != ReasonNone {
			t.Fatalf("failure %d: reason=%v err=%v", i, reason, err)
		}
		t.Logf("input=failure#%d basis=counter=%d rule=none -> state failures=%d", i, i, st.Failures)
	}
	// Failure 3: throttle reason, not lockout.
	_, reason, _ := l.RecordFailure(ctx, "bob", "ev-3", t0)
	if reason != ReasonThrottled {
		t.Fatalf("want throttled, got %v", reason)
	}
	if r, _ := l.Check(ctx, "bob", t0); r != ReasonThrottled {
		t.Fatalf("Check want throttled, got %v", r)
	}
	t.Logf("input=failure#3 basis=failures>=ThrottleAfter(3) rule=throttle -> reason=%s (distinct from lock)", reason)
	// Failure 4 remains throttle.
	_, reason, _ = l.RecordFailure(ctx, "bob", "ev-4", t0)
	if reason != ReasonThrottled {
		t.Fatalf("want throttled, got %v", reason)
	}
	// Failure 5 crosses the threshold exactly once: locked.
	st, reason, _ := l.RecordFailure(ctx, "bob", "ev-5", t0)
	if reason != ReasonLocked {
		t.Fatalf("want locked, got %v", reason)
	}
	if r, _ := l.Check(ctx, "bob", t0); r != ReasonLocked {
		t.Fatalf("Check want locked, got %v", r)
	}
	t.Logf("input=failure#5 basis=failures>=MaxFailures(5) rule=lockout until=%s", st.LockedUntil)

	// Lock expiry clears counters.
	if r, _ := l.Check(ctx, "bob", t0.Add(61*time.Second)); r != ReasonNone {
		t.Fatalf("after lock expiry want none, got %v", r)
	}
}

func TestIdempotentEventReplay(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	l := NewMemoryLimiter(Policy{MaxFailures: 3, Lockout: time.Minute, ThrottleAfter: 2, Window: time.Minute})
	ctx := context.Background()
	l.RecordFailure(ctx, "carol", "dup-1", t0)
	l.RecordFailure(ctx, "carol", "dup-1", t0) // replay must not double count
	l.RecordFailure(ctx, "carol", "dup-1", t0)
	st, _, _ := l.RecordFailure(ctx, "carol", "dup-2", t0)
	if st.Failures != 2 {
		t.Fatalf("replay double-counted: failures=%d want 2", st.Failures)
	}
	t.Logf("input=3x replay(ev dup-1)+1 new basis=event-id dedup rule=exactly-once -> failures=%d", st.Failures)
}

func TestConcurrentFailuresNoLostUpdate(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	l := NewMemoryLimiter(Policy{MaxFailures: 50, Lockout: time.Minute, ThrottleAfter: 1000, Window: time.Minute})
	ctx := context.Background()
	var wg sync.WaitGroup
	lockCrossings := make(chan Reason, 50)
	var mu sync.Mutex
	crossed := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, reason, err := l.RecordFailure(ctx, "hot", fmt.Sprintf("c-%d", i), t0)
			if err != nil {
				t.Errorf("err %v", err)
				return
			}
			if reason == ReasonLocked {
				lockCrossings <- reason
				mu.Lock()
				crossed++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	st, _ := l.StateAt(ctx, "hot", t0)
	if st.Failures != 50 {
		t.Fatalf("lost update: failures=%d want 50", st.Failures)
	}
	if crossed != 1 {
		t.Fatalf("threshold crossed %d times, want exactly 1", crossed)
	}
	t.Logf("input=50 concurrent failures basis=single-mutex counter rule=no-lost-update -> failures=%d, lock crossings=%d",
		st.Failures, crossed)
}
