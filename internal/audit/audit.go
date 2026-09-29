// Package audit records authentication and security events with
// deduplication so replay cannot double-lock or double-count.
package audit

import (
	"context"
	"errors"
	"time"
)

// EventType enumerates audited security events.
type EventType string

const (
	EventLoginSuccess        EventType = "login_success"
	EventLoginFailure        EventType = "login_failure"
	EventLockout             EventType = "lockout"
	EventThrottle            EventType = "throttled"
	EventRefresh             EventType = "refresh"
	EventRefreshReuse        EventType = "refresh_reuse"
	EventRevoke              EventType = "revoke"
	EventKeyRotation         EventType = "key_rotation"
	EventKeyRetired          EventType = "key_retired"
	EventAccessDenied        EventType = "access_denied"
	EventAccessAllowed       EventType = "access_allowed"
	EventCSRFFailure         EventType = "csrf_failure"
	EventSessionRevoked      EventType = "session_revoked"
	EventSessionRevokeDenied EventType = "session_revoke_denied"
	EventSessionEvicted      EventType = "session_evicted"
	EventSessionListed       EventType = "session_listed"
)

// Event is one structured security event. Sensitive fields must be masked.
type Event struct {
	EventID    string // idempotency key
	Type       EventType
	OccurredAt time.Time
	Principal  string
	SessionID  string
	Reason     string
	Details    map[string]string
}

// Critical marks events that must never be silently dropped.
func (e Event) Critical() bool {
	switch e.Type {
	case EventLockout, EventRefreshReuse, EventRevoke, EventAccessDenied,
		EventSessionRevoked, EventSessionRevokeDenied, EventSessionEvicted:
		return true
	}
	return false
}

// Sink persists/dispatches events.
type Sink interface {
	// Record stores an event. Replaying the same EventID is a no-op and
	// returns true in duplicate.
	Record(ctx context.Context, e Event) (duplicate bool, err error)
	// List returns recorded events in chronological order.
	List(ctx context.Context) ([]Event, error)
	// Seen reports whether an event ID was already recorded.
	Seen(ctx context.Context, eventID string) (bool, error)
}

var ErrSink = errors.New("audit: sink failure")
