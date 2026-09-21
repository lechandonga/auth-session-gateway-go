package store

import (
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

func TestLockoutRegisterFailureBoundaries(t *testing.T) {
	s := NewLockoutStore()
	now := time.Unix(100, 0)
	threshold, window, lock := 3, time.Minute, 5*time.Minute

	f, locked, _ := s.RegisterFailure("u", now, threshold, window, lock)
	if f != 1 || locked {
		t.Fatalf("first failure: f=%d locked=%v", f, locked)
	}
	f, locked, _ = s.RegisterFailure("u", now.Add(time.Second), threshold, window, lock)
	if f != 2 || locked {
		t.Fatalf("second: f=%d locked=%v", f, locked)
	}
	f, locked, until := s.RegisterFailure("u", now.Add(2*time.Second), threshold, window, lock)
	if f != 3 || !locked || !until.Equal(now.Add(2*time.Second+lock)) {
		t.Fatalf("third must lock exactly now: f=%d locked=%v until=%v", f, locked, until)
	}
	// Further failures while locked do not inflate count nor re-fire lock.
	f, lockedNow, _ := s.RegisterFailure("u", now.Add(3*time.Second), threshold, window, lock)
	if f != 3 || lockedNow {
		t.Fatalf("post-lock failures: f=%d lockedNow=%v", f, lockedNow)
	}
	isL, _ := s.IsLocked("u", now.Add(4*time.Second))
	if !isL {
		t.Fatal("should still be locked")
	}
	isL, _ = s.IsLocked("u", now.Add(2*time.Second+lock+time.Second))
	if isL {
		t.Fatal("lock must expire")
	}
	// After expiry, a new failure starts from a clean slate.
	f, locked, _ = s.RegisterFailure("u", now.Add(10*time.Minute), threshold, window, lock)
	if f != 1 || locked {
		t.Fatalf("post-expiry count must restart: f=%d locked=%v", f, locked)
	}
	t.Log("INPUT 锁定窗口内/后的失败序列 -> 判定依据 locked 单次翻转+过期重建 -> 命中规则 计数不膨胀、锁定不重复")
}

func TestSlidingWindowPurge(t *testing.T) {
	s := NewLockoutStore()
	now := time.Unix(0, 0)
	s.RegisterFailure("u", now, 5, time.Minute, time.Minute)
	s.RegisterFailure("u", now.Add(time.Second), 5, time.Minute, time.Minute)
	f, _, _ := s.RegisterFailure("u", now.Add(2*time.Minute), 5, time.Minute, time.Minute)
	if f != 1 {
		t.Fatalf("stale failures must be purged, got %d", f)
	}
}

func TestConcurrentFailures(t *testing.T) {
	s := NewLockoutStore()
	now := time.Unix(0, 0)
	var wg sync.WaitGroup
	locks := 0
	var mu sync.Mutex
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, lockedNow, _ := s.RegisterFailure("u", now, 10, time.Hour, time.Hour)
			if lockedNow {
				mu.Lock()
				locks++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	st, _ := s.State("u")
	if st.Failures != 10 {
		t.Fatalf("want failures capped at threshold 10, got %d", st.Failures)
	}
	if locks != 1 {
		t.Fatalf("exactly one locker under 100 concurrent failures, got %d", locks)
	}
	t.Logf("INPUT 100 并发失败(阈值10) -> 判定依据 互斥计数 -> 命中规则 failures=%d lockedNow 次数=%d", st.Failures, locks)
}

func TestSessionAndRefreshFamilyRevoke(t *testing.T) {
	ss := NewSessionStore()
	rs := NewRefreshStore()
	now := time.Unix(0, 0)
	s1 := &model.Session{ID: "s1", FamilyID: "f1"}
	s2 := &model.Session{ID: "s2", FamilyID: "f1"}
	s3 := &model.Session{ID: "s3", FamilyID: "f2"}
	for _, s := range []*model.Session{s1, s2, s3} {
		if err := ss.Put(s); err != nil {
			t.Fatal(err)
		}
	}
	ids := ss.RevokeFamily("f1", now, "reuse")
	if len(ids) != 2 {
		t.Fatalf("family revoke must hit 2 sessions, got %v", ids)
	}
	// Idempotent: second call revokes nothing new.
	if again := ss.RevokeFamily("f1", now, "reuse"); len(again) != 0 {
		t.Fatalf("repeat family revoke must report no new IDs, got %v", again)
	}
	// Single revoke reports changed=true once.
	changed, err := ss.Revoke("s3", now, "logout")
	if err != nil || !changed {
		t.Fatalf("first single revoke: changed=%v err=%v", changed, err)
	}
	changed, _ = ss.Revoke("s3", now, "logout")
	if changed {
		t.Fatal("second single revoke must report changed=false")
	}
	// Refresh tokens: CAS rotation single winner.
	rec := &model.RefreshTokenRecord{Hash: "h1", FamilyID: "f1"}
	if err := rs.Put(rec); err != nil {
		t.Fatal(err)
	}
	if err := rs.MarkRotated("h1", now); err != nil {
		t.Fatal(err)
	}
	if err := rs.MarkRotated("h1", now); err != model.ErrTokenRotated {
		t.Fatalf("second rotation must fail, got %v", err)
	}
	if !rs.MarkReuse("h1") {
		t.Fatal("first reuse observer must win")
	}
	if rs.MarkReuse("h1") {
		t.Fatal("second reuse observer must not win")
	}
	rs.RevokeFamily("f1")
	got, _ := rs.Get("h1")
	if !got.Revoked {
		t.Fatal("family revoke must flag records")
	}
	t.Log("INPUT 家族撤销/重复撤销/CAS轮换/复用首报 -> 判定依据 changed 与 first 单次语义 -> 命中规则 幂等且单赢家")
}
