// Package audit records security-relevant events. Recording is idempotent
// per DedupKey: replayed/duplicate reports (e.g. a revoke retried over the
// network) never create duplicate entries and therefore can never drive
// duplicate decrements or duplicate lockouts.
package audit

import (
	"sync"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

type Logger struct {
	mu     sync.Mutex
	events []model.AuditEvent
	seen   map[string]int // DedupKey -> index+1 in events
}

func NewLogger() *Logger { return &Logger{seen: map[string]int{}} }

// Record stores an event. When ev.DedupKey is non-empty and was already
// recorded, the stored event is returned with recorded=false and NOTHING is
// appended. A zero OccurredAt is stamped server-side. The stored event is a
// copy so later mutation by the caller cannot change history.
func (l *Logger) Record(ev model.AuditEvent) (stored model.AuditEvent, recorded bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now()
	}
	if ev.DedupKey != "" {
		if idx, ok := l.seen[ev.DedupKey]; ok {
			return l.events[idx-1], false
		}
	}
	if ev.Details == nil {
		ev.Details = map[string]string{}
	} else {
		cp := make(map[string]string, len(ev.Details))
		for k, v := range ev.Details {
			cp[k] = v
		}
		ev.Details = cp
	}
	l.events = append(l.events, ev)
	if ev.DedupKey != "" {
		l.seen[ev.DedupKey] = len(l.events)
	}
	return ev, true
}

// List returns a defensive copy of all events in recording order.
func (l *Logger) List() []model.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]model.AuditEvent, len(l.events))
	for i, ev := range l.events {
		out[i] = ev
	}
	return out
}

// ByType returns events of a given type (defensive copy).
func (l *Logger) ByType(t string) []model.AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []model.AuditEvent
	for _, ev := range l.events {
		if ev.Type == t {
			out = append(out, ev)
		}
	}
	return out
}

// Count returns the number of distinct recorded events.
func (l *Logger) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}
