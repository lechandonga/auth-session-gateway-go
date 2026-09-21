package auth

import (
	"sync"
	"time"
)

// RateLimiter is a fixed-window counter keyed by client IP. Each key allows
// exactly Capacity requests per Window; the (Capacity+1)th within the window
// is rejected. All accounting happens under one mutex, so concurrent
// requests are never under-counted.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*rlBucket
	Capacity int
	Window   time.Duration
	now      func() time.Time
}

type rlBucket struct {
	count       int
	windowStart time.Time
}

func NewRateLimiter(capacity int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:  map[string]*rlBucket{},
		Capacity: capacity,
		Window:   window,
		now:      time.Now,
	}
}

// Allow atomically consumes one request slot. On rejection retryAfter is the
// time remaining until the window resets.
func (r *RateLimiter) Allow(key string) (allowed bool, retryAfter time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	b := r.buckets[key]
	if b == nil || now.Sub(b.windowStart) >= r.Window {
		// New window: first request is always admitted.
		r.buckets[key] = &rlBucket{count: 1, windowStart: now}
		return true, 0
	}
	if b.count >= r.Capacity {
		return false, r.Window - now.Sub(b.windowStart)
	}
	b.count++
	return true, 0
}

// Reset clears one key (used by tests/admin).
func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.buckets, key)
}
