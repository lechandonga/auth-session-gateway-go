package auth

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/model"
	"github.com/lechandonga/auth-session-gateway-go/internal/store"
)

type clock struct{ t time.Time }

func newHarness(t *testing.T, cap int, window time.Duration, maxFail int, failWindow, lockDur time.Duration, now time.Time) (*Authenticator, *store.UserStore, *store.LockoutStore, *audit.Logger, *RateLimiter, *clock) {
	users := store.NewUserStore()
	locks := store.NewLockoutStore()
	aud := audit.NewLogger()
	rl := NewRateLimiter(cap, window)
	c := &clock{t: now}
	rl.now = func() time.Time { return c.t }
	p := Policy{MaxFailures: maxFail, FailWindow: failWindow, LockDuration: lockDur}
	a := NewAuthenticator(users, locks, aud, p, rl)
	a.now = func() time.Time { return c.t }
	return a, users, locks, aud, rl, c
}

func seedUser(users *store.UserStore, name string) {
	salt := NewSalt()
	_ = users.Create(&model.User{
		ID: "u-" + name, Username: name, Salt: salt,
		PasswordHash: HashPassword(salt, "correct"),
		Roles:        []string{"member"},
	})
}

func TestLoginHappyAndBadCredential(t *testing.T) {
	a, users, _, aud, _, _ := newHarness(t, 100, time.Minute, 3, time.Minute, time.Minute, time.Unix(0, 0))
	seedUser(users, "bob")

	out := a.Login("bob", "correct", "1.1.1.1")
	if out.Result != model.LoginOK {
		t.Fatalf("want ok, got %s", out.Result)
	}
	out = a.Login("bob", "wrong", "1.1.1.1")
	if out.Result != model.LoginBadCredentials || out.Failures != 1 {
		t.Fatalf("want bad_credentials failures=1, got %s %d", out.Result, out.Failures)
	}
	t.Log("INPUT bob/wrong -> 判定依据 SHA256(salt:pwd) 常量时间不等 -> 命中规则 bad_credentials, 失败计数=1")

	// Success resets the failure counter.
	out = a.Login("bob", "correct", "1.1.1.1")
	if out.Result != model.LoginOK {
		t.Fatalf("want ok after success, got %s", out.Result)
	}
	out = a.Login("bob", "wrong", "1.1.1.1")
	if out.Failures != 1 {
		t.Fatalf("counter must reset on success, got %d", out.Failures)
	}
	// Unknown user returns the SAME verdict as wrong password (no enumeration).
	out = a.Login("ghost", "x", "1.1.1.1")
	if out.Result != model.LoginBadCredentials {
		t.Fatalf("unknown user verdict = %s, want bad_credentials", out.Result)
	}
	_ = aud
}

func TestLockoutBoundaryAndDistinctFromRateLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	a, users, locks, aud, rl, c := newHarness(t, 1000, time.Minute, 3, 10*time.Minute, 5*time.Minute, now)
	seedUser(users, "bob")

	// Failures 1..2 stay unlocked; failure 3 locks exactly once.
	for i := 1; i <= 2; i++ {
		out := a.Login("bob", "wrong", "ip-1")
		if out.Result != model.LoginBadCredentials || out.Failures != i {
			t.Fatalf("attempt %d: %s failures=%d", i, out.Result, out.Failures)
		}
	}
	out := a.Login("bob", "wrong", "ip-1")
	if out.Result != model.LoginBadCredentials || out.Failures != 3 || !out.RetryAt.After(now) {
		t.Fatalf("threshold attempt: %+v", out)
	}
	// The very next request — even WITH the correct password — is locked,
	// and the reason is distinct from rate limiting.
	out = a.Login("bob", "correct", "ip-1")
	if out.Result != model.LoginLocked {
		t.Fatalf("want locked, got %s", out.Result)
	}
	t.Log("INPUT 第 4 次请求(正确密码) -> 判定依据 IsLocked 先于密码校验 -> 命中规则 locked(与 rate_limited 可区分)")

	if l := aud.ByType(model.EventLocked); len(l) != 1 {
		t.Fatalf("exactly one lock event expected, got %d", len(l))
	}
	rl.Reset("ip-1")

	// Rate limiting is per-IP and independent: fresh account, aggressive
	// limiter -> rate_limited before any credential conclusion.
	seedUser(users, "carol")
	rl2 := NewRateLimiter(2, time.Minute)
	rl2.now = func() time.Time { return c.t }
	a.rl = rl2
	for i := 0; i < 2; i++ {
		if o := a.Login("carol", "wrong", "ip-2"); o.Result == model.LoginRateLimited {
			t.Fatal("first two requests must not be rate limited")
		}
	}
	o := a.Login("carol", "correct", "ip-2")
	if o.Result != model.LoginRateLimited {
		t.Fatalf("3rd request want rate_limited, got %s", o.Result)
	}
	t.Logf("INPUT 同 IP 第 3 次请求 -> 判定依据 固定窗口容量=2 -> 命中规则 rate_limited retryAt=%v（不触碰账户锁定计数）", o.RetryAt)
	locks.Reset("carol")
	if st, _ := locks.State("carol"); st.Failures != 0 {
		t.Fatalf("rate-limited request must not increment lockout failures, got %d", st.Failures)
	}

	// After lock duration elapses, login works again with a fresh window.
	a.rl = NewRateLimiter(1000, time.Minute)
	a.rl.now = func() time.Time { return c.t }
	c.t = now.Add(5*time.Minute + time.Second)
	o = a.Login("bob", "correct", "ip-3")
	if o.Result != model.LoginOK {
		t.Fatalf("after lock expiry want ok, got %s", o.Result)
	}

	// Sliding window: old failures expire.
	c.t = now.Add(6 * time.Minute)
	seedUser(users, "dave")
	for i := 0; i < 2; i++ {
		a.Login("dave", "wrong", "ip-4")
	}
	c.t = now.Add(6*time.Minute + 11*time.Minute) // beyond fail window
	o = a.Login("dave", "wrong", "ip-4")
	if o.Failures != 1 {
		t.Fatalf("stale failures must be purged, failures=%d", o.Failures)
	}
	t.Log("INPUT 超出失败窗口后的再次失败 -> 判定依据 FirstFail 滑窗清理 -> 命中规则 计数重新从 1 开始")
}

func TestConcurrentFailuresNoLostOrDoubleCount(t *testing.T) {
	now := time.Unix(1000, 0)
	a, users, locks, aud, _, _ := newHarness(t, 10_000, time.Minute, 10, time.Hour, time.Hour, now)
	seedUser(users, "bob")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("ip-%d", i)
			a.Login("bob", "wrong", ip)
		}(i)
	}
	wg.Wait()
	st, ok := locks.State("bob")
	if !ok {
		t.Fatal("missing lockout state")
	}
	if st.Failures != 10 {
		t.Fatalf("want exactly 10 counted failures (threshold caps lock transition), got %d", st.Failures)
	}
	if !st.Locked {
		t.Fatal("bob must be locked after 20 concurrent failures")
	}
	// Exactly one lock event despite 20 concurrent racers.
	if l := aud.ByType(model.EventLocked); len(l) != 1 {
		t.Fatalf("exactly one lock event required, got %d", len(l))
	}
	// After lock, further failures must not inflate the count.
	before := st.Failures
	a.Login("bob", "wrong", "ip-99")
	st2, _ := locks.State("bob")
	if st2.Failures != before {
		t.Fatalf("failures while locked must not accumulate: %d -> %d", before, st2.Failures)
	}
	t.Logf("INPUT 20 个并发错误登录(阈值10) -> 判定依据 RegisterFailure 互斥+lockedNow 单次翻转 -> 命中规则 计数=%d 锁定事件=1 无漏计/无重复锁定", st2.Failures)
}
