package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	asess "github.com/lechandonga/auth-session-gateway-go/internal/session"
)

// TestServiceSessionListRevokeAndEviction covers multi-device management at
// the service facade: independent sessions, listing, targeted revocation
// with isolation/ownership distinctions, and LRU capacity eviction audit.
func TestServiceSessionListRevokeAndEviction(t *testing.T) {
	h := newHarness(t, ratelimitPolicyForTest())
	ctx := context.Background()

	t1, err := h.svc.LoginWithLabel(ctx, "alice", "correct horse", "10.0.0.1", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	t2, err := h.svc.LoginWithLabel(ctx, "alice", "correct horse", "10.0.0.2", "phone")
	if err != nil {
		t.Fatal(err)
	}
	list, err := h.svc.ListSessions(ctx, "u1", t1.SessionID, h.now)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v err %v, want 2 sessions", list, err)
	}
	currents := 0
	for _, info := range list {
		if info.Current {
			currents++
			if info.ID != t1.SessionID {
				t.Fatalf("current = %s want %s", info.ID, t1.SessionID)
			}
		}
	}
	if currents != 1 {
		t.Fatalf("current sessions marked = %d want 1", currents)
	}
	t.Logf("input=two logins basis=one session per login rule=2 active devices labels=%q,%q",
		list[0].Label, list[1].Label)

	// Owner revokes the laptop; the phone keeps working.
	if err := h.svc.RevokeSession(ctx, "u1", t1.SessionID, h.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.Authenticate(ctx, t1.AccessToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("revoked device auth = %v", err)
	}
	if _, _, err := h.svc.Authenticate(ctx, t2.AccessToken); err != nil {
		t.Fatalf("other device must stay live: %v", err)
	}
	// Repeat revoke is reported as already revoked, no second audit record.
	if err := h.svc.RevokeSession(ctx, "u1", t1.SessionID, h.now); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("repeat revoke = %v", err)
	}
	events, _ := h.sink.List(ctx)
	var revokes, denies int
	for _, e := range events {
		switch e.Type {
		case "revoke":
			revokes++
		case "revoke_denied":
			denies++
		}
	}
	if revokes != 1 {
		t.Fatalf("revoke events = %d want 1 (no double count)", revokes)
	}
	t.Log("input=revoke laptop twice basis=idempotent EventID rule=one revoke, phone unaffected")

	// Cross-user attempt: distinct not-found vs not-owner, session intact.
	tb, err := h.svc.LoginWithLabel(ctx, "alice", "correct horse", "10.0.0.3", "x")
	_ = tb
	// Create a second user via direct harness addition is unavailable; use
	// a fresh service user by issuing through the same store is identity
	// scoped, so simulate with an actor id that never logged in.
	if err := h.svc.RevokeSession(ctx, "attacker", t2.SessionID, h.now); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("cross-user = %v want ErrNotOwner", err)
	}
	if err := h.svc.RevokeSession(ctx, "u1", "does-not-exist", h.now); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing = %v want ErrSessionNotFound", err)
	}
	if _, _, err := h.svc.Authenticate(ctx, t2.AccessToken); err != nil {
		t.Fatalf("denied attempts must not harm live session: %v", err)
	}
	deniesAfter := 0
	evs, _ := h.sink.List(ctx)
	for _, e := range evs {
		if e.Type == "revoke_denied" {
			deniesAfter++
		}
	}
	if deniesAfter != 2 {
		t.Fatalf("revoke_denied = %d want 2", deniesAfter)
	}
	t.Log("input=revoke other's then nonexistent basis=ownership/existence rule=403-class vs 404-class distinct, audit each, session untouched")
}

func TestServiceCapacityEvictionAudited(t *testing.T) {
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	cur := base
	h := newHarnessWithCap(t, 2, &cur)
	ctx := context.Background()
	old, err := h.svc.LoginWithLabel(ctx, "alice", "correct horse", "p1", "old")
	if err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(time.Minute)
	newer, err := h.svc.LoginWithLabel(ctx, "alice", "correct horse", "p2", "newer")
	if err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(time.Minute)
	// Third login evicts the oldest (old).
	_, err = h.svc.LoginWithLabel(ctx, "alice", "correct horse", "p3", "newest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Refresh(ctx, old.RefreshToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("evicted refresh = %v want revoked", err)
	}
	if _, err := h.svc.Refresh(ctx, newer.RefreshToken); err != nil {
		t.Fatalf("survivor refresh = %v", err)
	}
	var evictions int
	evs, _ := h.sink.List(ctx)
	for _, e := range evs {
		if e.Type == "session_evicted" {
			if e.SessionID != old.SessionID {
				t.Fatalf("evicted %s want %s", e.SessionID, old.SessionID)
			}
			evictions++
		}
	}
	if evictions != 1 {
		t.Fatalf("eviction events = %d want 1", evictions)
	}
	t.Log("input=3 logins cap=2 basis=LRU LastActiveAt rule=oldest evicted, credentials dead immediately, one audit event")
}

func TestServiceIdleAndAbsoluteDistinction(t *testing.T) {
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	cur := base
	h := newHarnessWithTimeouts(t, 10*time.Minute, 30*time.Minute, &cur)
	ctx := context.Background()
	tok, err := h.svc.Login(ctx, "alice", "correct horse", "p")
	if err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(10 * time.Minute)
	if _, err := h.svc.Refresh(ctx, tok.RefreshToken); !errors.Is(err, ErrSessionIdle) {
		t.Fatalf("idle refresh = %v want ErrSessionIdle", err)
	}
	t.Log("input=refresh at idle deadline basis=IdleDeadline rule=ErrSessionIdle distinct from absolute")

	cur = base
	tok2, _ := h.svc.Login(ctx, "alice", "correct horse", "p")
	cur = cur.Add(30 * time.Minute)
	if _, err := h.svc.Refresh(ctx, tok2.RefreshToken); !errors.Is(err, ErrSessionAbsolute) {
		t.Fatalf("absolute refresh = %v want ErrSessionAbsolute", err)
	}
	t.Log("input=refresh at absolute cap basis=AbsoluteDeadline rule=ErrSessionAbsolute, sliding cannot break it")
	_ = asess.RevokeIdle
}
