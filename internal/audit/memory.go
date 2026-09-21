package audit

import (
	"context"
	"sync"
)

// MemorySink is a concurrency-safe in-memory Sink. Replayed EventIDs are
// deduplicated, so a retried report cannot cause a second lockout/count in
// upstream components that key mutations off audited events.
type MemorySink struct {
	mu     sync.Mutex
	seen   map[string]struct{}
	events []Event
}

// NewMemorySink constructs an empty MemorySink.
func NewMemorySink() *MemorySink {
	return &MemorySink{seen: map[string]struct{}{}}
}

func (s *MemorySink) Record(ctx context.Context, e Event) (bool, error) {
	if e.EventID == "" {
		return false, ErrSink
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[e.EventID]; ok {
		// Duplicate replay: accepted as no-op, never applied twice.
		return true, nil
	}
	s.seen[e.EventID] = struct{}{}
	// Mask any detail values tagged sensitive.
	if e.Details != nil {
		cp := make(map[string]string, len(e.Details))
		for k, v := range e.Details {
			if isSensitiveKey(k) {
				v = "***REDACTED***"
			}
			cp[k] = v
		}
		e.Details = cp
	}
	s.events = append(s.events, e)
	return false, nil
}

func (s *MemorySink) List(ctx context.Context) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out, nil
}

func (s *MemorySink) Seen(ctx context.Context, eventID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.seen[eventID]
	return ok, nil
}

// CriticalEvents returns recorded critical events (revoke, lockout, reuse,
// access denied) in chronological order.
func (s *MemorySink) CriticalEvents(ctx context.Context) ([]Event, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, e := range all {
		if e.Critical() {
			out = append(out, e)
		}
	}
	return out, nil
}

func isSensitiveKey(k string) bool {
	switch k {
	case "password", "secret", "token", "access_token", "refresh_token", "password_hash":
		return true
	}
	return false
}
