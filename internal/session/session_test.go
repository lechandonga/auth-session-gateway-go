package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestManager() *DefaultManager {
	return NewManager(NewMemoryStore(), Options{IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour})
}

func issue(ctx context.Context, m *DefaultManager, user string, now time.Time) (*Session, string) {
	sess, rt, _, err := m.Issue(ctx, IssueParams{UserID: user, Peer: "1.2.3.4", UserAgent: "ua-" + user}, now)
	if err != nil {
		panic(err)
	}
	return sess, rt
}

func TestRotateRevokesReusedFamily(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	sess, rt1 := issue(ctx, m, "u1", t0)
	res, err := m.Rotate(ctx, rt1, t0.Add(time.Second))
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	rt2 := res.NewRefresh
	if !res.Session.IdleExpiresAt.Equal(t0.Add(time.Second + time.Hour)) {
		t.Fatalf("idle window did not slide to %v, got %v", t0.Add(time.Hour+time.Second), res.Session.IdleExpiresAt)
	}
	if !res.Session.AbsoluteExpiresAt.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("absolute cap moved: %v", res.Session.AbsoluteExpiresAt)
	}
	t.Logf("input=rt1 basis=not rotated & family active rule=rotate, idle slides, absolute fixed -> session=%s", sess.ID)

	_, err = m.Rotate(ctx, rt1, t0.Add(2*time.Second))
	if !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("replay rt1 err = %v, want ErrRefreshReused", err)
	}
	t.Log("input=replayed rt1 basis=record.Rotated=true rule=ErrRefreshReused + family revoke")

	if _, err := m.Rotate(ctx, rt2, t0.Add(3*time.Second)); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("post-reuse rt2 err = %v, want ErrSessionRevoked", err)
	}
	got, err := m.store.GetSession(ctx, sess.ID)
	if err != nil || !got.Revoked || got.RevokeReason != RevokeReuse {
		t.Fatalf("session state = %+v err %v", got, err)
	}
	t.Log("input=rt2 after reuse basis=family revoked rule=ErrSessionRevoked (no silent pass)")
}

func TestRevokeAndExpiry(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	sess, rt := issue(ctx, m, "u2", t0)
	if _, err := m.RevokeForUser(ctx, "u2", sess.ID, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(ctx, sess.ID, t0); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("validate revoked = %v", err)
	}
	if _, err := m.Rotate(ctx, rt, t0); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("rotate revoked family = %v", err)
	}
	if _, err := m.Rotate(ctx, "nope", t0); !errors.Is(err, ErrRefreshUnknown) {
		t.Fatalf("unknown refresh = %v", err)
	}
	t.Log("input=targeted revoke then refresh basis=session.Revoked rule=ErrSessionRevoked; unknown distinct")

	// Idle expiry: rotate slides the idle window but not the absolute cap.
	m2 := NewManager(NewMemoryStore(), Options{IdleTTL: time.Minute, AbsoluteTTL: time.Hour})
	_, rt2 := issue(ctx, m2, "u3", t0)
	res2, err := m2.Rotate(ctx, rt2, t0.Add(30*time.Second))
	if err != nil {
		t.Fatalf("rotate within idle: %v", err)
	}
	if _, err := m2.Rotate(ctx, res2.NewRefresh, t0.Add(91*time.Second)); !errors.Is(err, ErrSessionIdle) {
		t.Fatalf("idle expiry err = %v, want ErrSessionIdle", err)
	}
	t.Log("input=new refresh at +91s basis=slid idle deadline +90s rule=ErrSessionIdle distinct from absolute")

	// Fresh token chain: prove idle vs absolute are distinct.
	m3 := NewManager(NewMemoryStore(), Options{IdleTTL: time.Minute, AbsoluteTTL: 2 * time.Minute})
	s3, r3 := issue(ctx, m3, "u4", t0)
	_, err3 := m3.Rotate(ctx, r3, t0.Add(61*time.Second))
	if !errors.Is(err3, ErrSessionIdle) {
		t.Fatalf("idle expiry err = %v, want ErrSessionIdle", err3)
	}
	got, _ := m3.store.GetSession(ctx, s3.ID)
	if got.RevokeReason != RevokeIdle {
		t.Fatalf("reason = %s want idle_expired", got.RevokeReason)
	}
	m4 := NewManager(NewMemoryStore(), Options{IdleTTL: 10 * time.Minute, AbsoluteTTL: time.Minute})
	s4, r4 := issue(ctx, m4, "u5", t0)
	_, err4 := m4.Rotate(ctx, r4, t0.Add(61*time.Second))
	if !errors.Is(err4, ErrSessionAbsolute) {
		t.Fatalf("absolute expiry err = %v, want ErrSessionAbsolute", err4)
	}
	got4, _ := m4.store.GetSession(ctx, s4.ID)
	if got4.RevokeReason != RevokeAbsolute {
		t.Fatalf("reason = %s want absolute_expired", got4.RevokeReason)
	}
	t.Log("input=rotate past idle vs past absolute basis=ExpiryKind rule=two distinct errors + reasons")
}

func TestTouchSlidesIdleOnly(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := NewManager(NewMemoryStore(), Options{IdleTTL: time.Minute, AbsoluteTTL: 2 * time.Minute})
	sess, _ := issue(ctx, m, "u6", t0)
	if _, err := m.Touch(ctx, sess.ID, t0.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, _ := m.store.GetSession(ctx, sess.ID)
	if !got.IdleExpiresAt.Equal(t0.Add(90 * time.Second)) {
		t.Fatalf("idle not slid: %v", got.IdleExpiresAt)
	}
	if !got.AbsoluteExpiresAt.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("absolute moved: %v", got.AbsoluteExpiresAt)
	}
	t.Log("input=touch +30s basis=activity rule=idle->+90s, absolute stays +120s")
}

func TestConcurrentRotateExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	_, rt := issue(ctx, m, "u7", t0)

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
	if wins != 1 || reuses != 19 {
		t.Fatalf("wins=%d reuses=%d want 1/19", wins, reuses)
	}
	t.Logf("input=20 concurrent rotations basis=single critical section rule=1 win, %d reuse", reuses)
}

func TestRevokeForUserOwnershipAndIdempotency(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	a, _ := issue(ctx, m, "ua", t0)
	b, _ := issue(ctx, m, "ub", t0)
	if _, err := m.RevokeForUser(ctx, "ub", a.ID, t0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-user revoke err=%v want ErrForbidden", err)
	}
	if got, _ := m.store.GetSession(ctx, a.ID); got.Revoked {
		t.Fatal("forbidden revoke must not touch the target session")
	}
	out, err := m.RevokeForUser(ctx, "ua", a.ID, t0)
	if err != nil || !out.Revoked {
		t.Fatalf("owner revoke = %+v %v", out, err)
	}
	out2, err := m.RevokeForUser(ctx, "ua", a.ID, t0.Add(time.Second))
	if err != nil || out2.Revoked || !out2.AlreadyRevoked {
		t.Fatalf("repeat revoke must be idempotent no-op: %+v %v", out2, err)
	}
	if _, err := m.RevokeForUser(ctx, "ua", "missing", t0); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing target err=%v want ErrSessionNotFound", err)
	}
	// B's session must be unaffected.
	if got, _ := m.store.GetSession(ctx, b.ID); !got.Active(t0.Add(time.Second)) {
		t.Fatal("other devices must be unaffected by targeted revoke")
	}
	t.Log("input=cross-user/owner/repeat/missing revokes basis=ownership+idempotency rule=403-like/200/gone/404-like; siblings live")
}

func TestCapacityEvictionLRU(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := NewManager(NewMemoryStore(), Options{IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour, MaxPerUser: 2})
	s1, _ := issue(ctx, m, "u9", t0)
	s2, _ := issue(ctx, m, "u9", t0.Add(time.Second))
	// Activity on s2, then touch s1: s2 is now least-recently-active.
	if _, err := m.Touch(ctx, s2.ID, t0.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Touch(ctx, s1.ID, t0.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	s3, _, evicted, err := m.Issue(ctx, IssueParams{UserID: "u9"}, t0.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(evicted) != 1 || evicted[0].ID != s2.ID {
		t.Fatalf("evicted = %+v want only s2 %s", evicted, s2.ID)
	}
	got2, _ := m.store.GetSession(ctx, s2.ID)
	if !got2.Revoked || got2.RevokeReason != RevokeEvicted {
		t.Fatalf("victim state = %+v", got2)
	}
	got1, _ := m.store.GetSession(ctx, s1.ID)
	if !got1.Active(t0.Add(30 * time.Second)) {
		t.Fatal("most-recently-active session must survive")
	}
	got3, _ := m.store.GetSession(ctx, s3.ID)
	if !got3.Active(t0.Add(30 * time.Second)) {
		t.Fatal("new session must be active")
	}
	list, _ := m.List(ctx, "u9", t0.Add(30*time.Second))
	if len(list) != 2 {
		t.Fatalf("active sessions=%d want 2", len(list))
	}
	t.Logf("input=3rd login cap=2 basis=LastActiveAt LRU rule=evict %s only; %s,%s active", s2.ID, s1.ID, s3.ID)
}
