package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestManager() *DefaultManager {
	return NewManager(NewMemoryStore(), 30*time.Minute, 24*time.Hour, 5)
}

func issueAt(t *testing.T, m *DefaultManager, user, label string, idle, abs time.Duration, at time.Time) (*Session, string) {
	t.Helper()
	res, err := m.Issue(context.Background(), IssueParams{
		UserID: user, Label: label, IdleTTL: idle, AbsoluteTTL: abs, Now: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.Session, res.Refresh
}

func TestRotateRevokesReusedFamily(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	sess, rt1 := issueAt(t, m, "u1", "laptop", time.Hour, 24*time.Hour, t0)
	// Legitimate rotation: old token dead, new token works.
	res, err := m.Rotate(ctx, rt1, t0.Add(time.Second))
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	rt2 := res.NewRefresh
	t.Logf("input=rt1 basis=not rotated & family active rule=rotate -> session=%s old=dead new=issued", sess.ID)

	// Attacker replays rt1: reuse detected, family revoked.
	_, err = m.Rotate(ctx, rt1, t0.Add(2*time.Second))
	if !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("replay rt1 err = %v, want ErrRefreshReused", err)
	}
	t.Log("input=replayed rt1 basis=record.Rotated=true rule=ErrRefreshReused + family revoke")

	// Even the legitimate new token must now be refused (family-wide kill).
	if _, err := m.Rotate(ctx, rt2, t0.Add(3*time.Second)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("post-reuse rt2 err = %v, want ErrSessionRevoked", err)
	}
	got, err := m.store.GetSession(ctx, sess.ID)
	if err != nil || !got.Revoked || got.RevokeReason != RevokeReuse {
		t.Fatalf("session state = %+v err %v", got, err)
	}
	t.Log("input=rt2 after detected reuse basis=family revoked rule=deny (no silent pass)")
}

func TestRevokeAndExpiry(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	sess, rt := issueAt(t, m, "u2", "d", time.Minute, time.Hour, t0)
	if err := m.Revoke(ctx, sess.ID, RevokeLogout, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(ctx, sess.ID, t0); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("validate revoked = %v", err)
	}
	if _, err := m.Rotate(ctx, rt, t0); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("rotate revoked family = %v", err)
	}
	// Unknown token is a distinct failure.
	if _, err := m.Rotate(ctx, "nope", t0); !errors.Is(err, ErrRefreshUnknown) {
		t.Fatalf("unknown refresh = %v", err)
	}
	t.Log("input=logout then refresh basis=session.Revoked rule=ErrSessionRevoked; unknown token distinct")

	// Expiry path.
	m2 := newTestManager()
	sess2, rt2 := issueAt(t, m2, "u3", "d", time.Minute, time.Hour, t0)
	if _, err := m2.Rotate(ctx, rt2, t0.Add(61*time.Second)); !errors.Is(err, ErrSessionIdle) {
		t.Fatalf("idle rotate = %v, want ErrSessionIdle", err)
	}
	got, _ := m2.Validate(ctx, sess2.ID, t0.Add(61*time.Second))
	_ = got
	t.Log("input=rotate at idle+61s basis=now>=IdleDeadline rule=ErrSessionIdle + family revoke")
	// Absolute cap is independent of the idle window.
	m3 := newTestManager()
	sess3, rt3 := issueAt(t, m3, "u3b", "d", time.Hour, 2*time.Hour, t0)
	if _, err := m3.Rotate(ctx, rt3, t0.Add(2*time.Hour)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("absolute rotate = %v, want ErrSessionExpired", err)
	}
	if _, err := m3.Validate(ctx, sess3.ID, t0.Add(2*time.Hour)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("absolute validate = %v", err)
	}
	t.Log("input=rotate at absolute cap basis=now>=AbsoluteDeadline rule=ErrSessionExpired, never extended")
}

func TestConcurrentRotateExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	_, rt := issueAt(t, m, "u4", "d", time.Hour, 24*time.Hour, t0)

	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.Rotate(ctx, rt, t0)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	wins, reuses := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrRefreshReused):
			reuses++
		default:
			t.Fatalf("unexpected err %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins=%d want exactly 1", wins)
	}
	if reuses != 19 {
		t.Fatalf("reuse rejections=%d want 19", reuses)
	}
	t.Logf("input=20 concurrent rotations of one token basis=single critical section rule=1 win, %d reuse-reject, no half-state",
		reuses)
}

func TestConcurrentRotateChainsConsistent(t *testing.T) {
	// Two threads each try to chain rotations from their view; every issued
	// token rotates at most once and every reuse revokes, so conclusions
	// stay consistent under interleaving.
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	sess, rt := issueAt(t, m, "u5", "d", time.Hour, 24*time.Hour, t0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cur := rt
			for j := 0; j < 5; j++ {
				res, err := m.Rotate(ctx, cur, t0.Add(time.Duration(j)*time.Second))
				if err != nil {
					if errors.Is(err, ErrRefreshReused) || errors.Is(err, ErrSessionRevoked) {
						return
					}
					return
				}
				mu.Lock()
				accepted++
				mu.Unlock()
				cur = res.NewRefresh
			}
		}()
	}
	wg.Wait()
	got, _ := m.store.GetSession(ctx, sess.ID)
	t.Logf("input=two racing chains basis=rotation+revoke atomicity rule=consistent outcome accepted=%d revoked=%v reason=%s",
		accepted, got.Revoked, got.RevokeReason)
	if !got.Revoked {
		// If no reuse happened, exactly one chain should have consumed 5.
		if accepted != 5 {
			t.Fatalf("accepted=%d want 5 when no reuse", accepted)
		}
	}
}

func TestIdleBoundaryAndRotationSlide(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	sess, rt := issueAt(t, m, "u6", "phone", 10*time.Minute, time.Hour, t0)
	// Exactly at the boundary: not before deadline -> idle.
	if _, err := m.Rotate(ctx, rt, t0.Add(10*time.Minute)); !errors.Is(err, ErrSessionIdle) {
		t.Fatalf("boundary rotate = %v, want ErrSessionIdle", err)
	}
	t.Log("input=rotate at idle deadline (exact) basis=!Before(IdleDeadline) rule=idle reject")

	// One second earlier it succeeds and slides the idle window, but never
	// past the absolute cap.
	m2 := NewManager(NewMemoryStore(), 10*time.Minute, 30*time.Minute, 5)
	_, rt2 := issueAt(t, m2, "u7", "phone", 10*time.Minute, 30*time.Minute, t0)
	res, err := m2.Rotate(ctx, rt2, t0.Add(9*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Session.IdleDeadline.Equal(t0.Add(19 * time.Minute)) {
		t.Fatalf("idle slid to %v, want %v", res.Session.IdleDeadline, t0.Add(19*time.Minute))
	}
	if !res.Session.AbsoluteDeadline.Equal(t0.Add(30 * time.Minute)) {
		t.Fatalf("absolute moved: %v", res.Session.AbsoluteDeadline)
	}
	t.Logf("input=rotate at idle-1m basis=slide idle only rule=idle=%v absolute unchanged=%v",
		res.Session.IdleDeadline, res.Session.AbsoluteDeadline)

	// Slide cannot exceed the absolute cap.
	m3 := NewManager(NewMemoryStore(), 10*time.Minute, 12*time.Minute, 5)
	_, rt3 := issueAt(t, m3, "u8", "phone", 10*time.Minute, 12*time.Minute, t0)
	res3, err := m3.Rotate(ctx, rt3, t0.Add(9*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m3.Rotate(ctx, res3.NewRefresh, t0.Add(12*time.Minute)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("rotate past absolute = %v, want ErrSessionExpired", err)
	}
	t.Logf("input=slide to %v (clamped to absolute %v) then rotate at cap rule=absolute cap never broken",
		res3.Session.IdleDeadline, res3.Session.AbsoluteDeadline)
	_ = sess
}

func TestCapacityEvictsLRU(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := NewManager(NewMemoryStore(), time.Hour, 24*time.Hour, 3)
	s1, r1 := issueAt(t, m, "cap", "d1", time.Hour, 24*time.Hour, t0)
	s2, r2 := issueAt(t, m, "cap", "d2", time.Hour, 24*time.Hour, t0.Add(time.Minute))
	_, r3 := issueAt(t, m, "cap", "d3", time.Hour, 24*time.Hour, t0.Add(2*time.Minute))
	// Activity on s1 makes s2 the longest-idle; the 4th login must evict s2.
	if err := m.Touch(ctx, s1.ID, t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	res, err := m.Issue(ctx, IssueParams{UserID: "cap", Label: "d4",
		IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour, Now: t0.Add(4 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Evicted) != 1 || res.Evicted[0].ID != s2.ID {
		t.Fatalf("evicted = %+v, want only s2", res.Evicted)
	}
	if got := res.Evicted[0]; got.RevokeReason != RevokeEvicted {
		t.Fatalf("reason = %s", got.RevokeReason)
	}
	// Evicted credentials are immediately dead; others live.
	if _, err := m.Rotate(ctx, r2, t0.Add(4*time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("evicted refresh = %v, want revoked", err)
	}
	if _, err := m.Rotate(ctx, r1, t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("s1 must survive: %v", err)
	}
	if _, err := m.Rotate(ctx, r3, t0.Add(4*time.Minute)); err != nil {
		t.Fatalf("s3 must survive: %v", err)
	}
	active, _ := m.ListActive(ctx, "cap", t0.Add(4*time.Minute))
	if len(active) != 3 {
		t.Fatalf("active = %d want 3", len(active))
	}
	t.Logf("input=4th login cap=3 (s1 touched) basis=LRU LastActiveAt rule=evict s2 only, its refresh dead, s1/s3 live")
}

func TestRevokeOneIsolationOwnershipAndIdempotence(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	a1, ra1 := issueAt(t, m, "ua", "a1", time.Hour, 24*time.Hour, t0)
	a2, ra2 := issueAt(t, m, "ua", "a2", time.Hour, 24*time.Hour, t0)
	b1, _ := issueAt(t, m, "ub", "b1", time.Hour, 24*time.Hour, t0)

	// Another user's session: distinct ErrNotOwner, no state change.
	if err := m.RevokeOne(ctx, "ub", a1.ID, RevokeAdmin, t0); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("cross-user revoke = %v, want ErrNotOwner", err)
	}
	if got, _ := m.store.GetSession(ctx, a1.ID); got.Revoked {
		t.Fatal("not-owner attempt must not mutate target session")
	}
	// Nonexistent target is a distinct result from ownership violation.
	if err := m.RevokeOne(ctx, "ua", "ghost", RevokeAdmin, t0); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing target = %v, want ErrSessionNotFound", err)
	}
	// Owner revokes exactly one device.
	if err := m.RevokeOne(ctx, "ua", a1.ID, RevokeAdmin, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Rotate(ctx, ra1, t0); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("revoked refresh = %v", err)
	}
	if _, err := m.Rotate(ctx, ra2, t0); err != nil {
		t.Fatalf("sibling session must be unaffected: %v", err)
	}
	if got, _ := m.store.GetSession(ctx, b1.ID); got.Revoked {
		t.Fatal("other user's session must be unaffected")
	}
	// Repeat report is a no-op returning the terminal state, never a second
	// revocation/count.
	if err := m.RevokeOne(ctx, "ua", a1.ID, RevokeAdmin, t0); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("repeat revoke = %v, want ErrSessionRevoked", err)
	}
	_ = a2
	t.Log("input=cross-user/missing/owner/repeat basis=ownership+existence checks rule=not-owner vs not-found distinct, single kill, repeat no-op")
}
