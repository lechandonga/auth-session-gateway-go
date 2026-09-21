// Package ratelimit implements failed-attempt lockout with distinct reasons.
package ratelimit

import (
	"context"
	"errors"
	"time"
)

// Reason distinguishes why an authentication request was refused.
type Reason string

const (
	ReasonNone        Reason = ""
	ReasonLocked      Reason = "locked"       // threshold reached, account locked
	ReasonThrottled   Reason = "throttled"    // within penalty cooldown window
	ReasonRateLimited Reason = "rate_limited" // global/IP request rate exceeded
)

// Policy configures attempt counting and lockout behavior.
type Policy struct {
	// MaxFailures is the number of failures before lockout.
	MaxFailures int
	// Lockout is the lock duration after threshold is reached.
	Lockout time.Duration
	// ThrottleAfter starts throttling after this many failures within Window.
	ThrottleAfter int
	// ThrottleDelay is the artificial delay/refusal window when throttled.
	ThrottleDelay time.Duration
	// Window is the rolling window for counting failures.
	Window time.Duration
}

// DefaultPolicy returns a reasonable default policy.
func DefaultPolicy() Policy {
	return Policy{
		MaxFailures:   5,
		Lockout:       15 * time.Minute,
		ThrottleAfter: 3,
		ThrottleDelay: 2 * time.Second,
		Window:        10 * time.Minute,
	}
}

// ErrRefused is returned when the limiter refuses an attempt.
var ErrRefused = errors.New("ratelimit: attempt refused")

// State is the observable state for one key.
type State struct {
	Failures    int
	LockedUntil time.Time
	LastFailure time.Time
}

// Limiter tracks failed attempts per key (username/IP) and decides admission.
type Limiter interface {
	// Check reports whether an attempt is admitted at time now; the Reason
	// explains a refusal. It does not mutate counters.
	Check(ctx context.Context, key string, now time.Time) (Reason, error)
	// RecordFailure records a failed attempt (idempotent per eventID).
	RecordFailure(ctx context.Context, key, eventID string, now time.Time) (State, Reason, error)
	// RecordSuccess resets failure counters (idempotent per eventID).
	RecordSuccess(ctx context.Context, key, eventID string, now time.Time) error
	// StateAt returns the current state for a key.
	StateAt(ctx context.Context, key string, now time.Time) (State, error)
}
