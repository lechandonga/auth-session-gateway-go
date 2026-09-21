package ratelimit

import (
	"context"
	"sync"
	"time"
)

type entry struct {
	failures    []time.Time
	lockedUntil time.Time
}

// MemoryLimiter is a concurrency-safe in-memory Limiter. Every mutation is
// performed under one mutex, so concurrent failed attempts are counted
// exactly once each (no lost updates) and the threshold can only be crossed
// by exactly one call. Event IDs make replays idempotent.
type MemoryLimiter struct {
	mu     sync.Mutex
	policy Policy
	data   map[string]*entry
	seen   map[string]struct{}
}

// NewMemoryLimiter constructs a limiter with the given policy.
func NewMemoryLimiter(p Policy) *MemoryLimiter {
	if p.MaxFailures <= 0 {
		p = DefaultPolicy()
	}
	return &MemoryLimiter{policy: p, data: map[string]*entry{}, seen: map[string]struct{}{}}
}

// trim must be called with mu held. It evicts failures outside the rolling
// window and clears an expired lock.
func (l *MemoryLimiter) trim(e *entry, now time.Time) {
	if !e.lockedUntil.IsZero() && !now.Before(e.lockedUntil) {
		e.lockedUntil = time.Time{}
		e.failures = nil
		return
	}
	cutoff := now.Add(-l.policy.Window)
	kept := e.failures[:0]
	for _, t := range e.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.failures = kept
}

func (l *MemoryLimiter) Check(ctx context.Context, key string, now time.Time) (Reason, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.data[key]
	if e == nil {
		return ReasonNone, nil
	}
	l.trim(e, now)
	if !e.lockedUntil.IsZero() {
		return ReasonLocked, nil
	}
	if l.policy.ThrottleAfter > 0 && len(e.failures) >= l.policy.ThrottleAfter {
		return ReasonThrottled, nil
	}
	return ReasonNone, nil
}

func (l *MemoryLimiter) RecordFailure(ctx context.Context, key, eventID string, now time.Time) (State, Reason, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// Idempotency: a replayed event never counts twice.
	if eventID != "" {
		if _, ok := l.seen[eventID]; ok {
			return l.snapshot(key, now), ReasonNone, nil
		}
		l.seen[eventID] = struct{}{}
	}
	e := l.data[key]
	if e == nil {
		e = &entry{}
		l.data[key] = e
	}
	l.trim(e, now)
	e.failures = append(e.failures, now)
	reason := ReasonNone
	if len(e.failures) >= l.policy.MaxFailures {
		e.lockedUntil = now.Add(l.policy.Lockout)
		reason = ReasonLocked
	} else if l.policy.ThrottleAfter > 0 && len(e.failures) >= l.policy.ThrottleAfter {
		reason = ReasonThrottled
	}
	st := l.snapshot(key, now)
	return st, reason, nil
}

func (l *MemoryLimiter) RecordSuccess(ctx context.Context, key, eventID string, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if eventID != "" {
		if _, ok := l.seen[eventID]; ok {
			return nil
		}
		l.seen[eventID] = struct{}{}
	}
	delete(l.data, key)
	return nil
}

func (l *MemoryLimiter) StateAt(ctx context.Context, key string, now time.Time) (State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.snapshot(key, now), nil
}

// snapshot must be called with mu held.
func (l *MemoryLimiter) snapshot(key string, now time.Time) State {
	e := l.data[key]
	if e == nil {
		return State{}
	}
	l.trim(e, now)
	st := State{Failures: len(e.failures), LockedUntil: e.lockedUntil}
	if n := len(e.failures); n > 0 {
		st.LastFailure = e.failures[n-1]
	}
	return st
}
