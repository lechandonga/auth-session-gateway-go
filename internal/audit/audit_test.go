package audit

import (
	"context"
	"testing"
	"time"
)

func TestIdempotentRecordAndMasking(t *testing.T) {
	ctx := context.Background()
	s := NewMemorySink()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	ev := Event{EventID: "e1", Type: EventLockout, OccurredAt: t0, Principal: "bob",
		Details: map[string]string{"password": "hunter2", "reason": "locked"}}
	dup, err := s.Record(ctx, ev)
	if err != nil || dup {
		t.Fatalf("first record dup=%v err=%v", dup, err)
	}
	for i := 0; i < 5; i++ {
		dup, err := s.Record(ctx, ev)
		if err != nil || !dup {
			t.Fatalf("replay %d dup=%v err=%v", i, dup, err)
		}
	}
	events, _ := s.List(ctx)
	if len(events) != 1 {
		t.Fatalf("replays created %d events, want 1", len(events))
	}
	if events[0].Details["password"] != "***REDACTED***" {
		t.Fatalf("sensitive detail leaked: %v", events[0].Details)
	}
	if !events[0].Critical() {
		t.Fatal("lockout must be critical")
	}
	seen, _ := s.Seen(ctx, "e1")
	if !seen {
		t.Fatal("Seen should report e1")
	}
	t.Logf("input=1 record + 5 replays basis=EventID dedup rule=stored-once; password masked -> events=%d", len(events))

	// Empty EventID is rejected so events cannot silently collapse.
	if _, err := s.Record(ctx, Event{Type: EventAccessDenied}); err == nil {
		t.Fatal("event without ID must fail")
	}
	crit, _ := s.CriticalEvents(ctx)
	if len(crit) != 1 {
		t.Fatalf("critical events = %d", len(crit))
	}
	t.Log("input=critical filter basis=type set {lockout,reuse,revoke,denied} rule=never silently dropped")
}
