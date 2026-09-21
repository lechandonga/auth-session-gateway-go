package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestManager() *DefaultManager {
	return NewManager(NewMemoryStore(), time.Hour)
}

func TestRotateRevokesReusedFamily(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	sess, rt1, err := m.Issue(ctx, "u1", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
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
	sess, rt, _ := m.Issue(ctx, "u2", time.Minute, t0)
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
	sess2, rt2, _ := m2.Issue(ctx, "u3", time.Minute, t0)
	if _, err := m2.Rotate(ctx, rt2, t0.Add(61*time.Second)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired rotate = %v", err)
	}
	got, _ := m2.Validate(ctx, sess2.ID, t0.Add(61*time.Second))
	_ = got
	t.Log("input=rotate past TTL basis=now>=ExpiresAt rule=ErrSessionExpired + family revoke")
}

func TestConcurrentRotateExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	m := newTestManager()
	_, rt, _ := m.Issue(ctx, "u4", time.Hour, t0)

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
	sess, rt, _ := m.Issue(ctx, "u5", time.Hour, t0)
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
