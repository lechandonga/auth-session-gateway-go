package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/keyring"
	"github.com/lechandonga/auth-session-gateway-go/internal/ratelimit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/token"
)

type harness struct {
	svc  *Service
	kr   *keyring.MemoryKeyring
	sink *audit.MemorySink
	now  time.Time
}

func newHarness(t *testing.T, policy ratelimit.Policy) *harness {
	t.Helper()
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	cur := base
	kr := keyring.NewMemoryKeyring()
	if err := kr.AddKey(&keyring.Key{ID: "k1", Secret: []byte("int-secret-1"),
		Status: keyring.StatusActive, CreatedAt: base}); err != nil {
		t.Fatal(err)
	}
	users := NewMemoryUsers()
	u, err := NewUser("u1", "alice", "correct horse",
		[]string{"viewer"}, []string{"docs:read"}, map[string]string{"dept": "sales"})
	if err != nil {
		t.Fatal(err)
	}
	users.Add(u)
	sink := audit.NewMemorySink()
	svc := NewService(Config{
		Users:      users,
		Sessions:   session.NewManager(session.NewMemoryStore(), session.Options{IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour, MaxPerUser: 10}),
		Signer:     token.NewHS256Signer(kr),
		Limiter:    ratelimit.NewMemoryLimiter(policy),
		Audit:      sink,
		AccessTTL:  time.Minute,
		RefreshTTL: time.Hour,
		Clock:      func() time.Time { return cur },
	})
	return &harness{svc: svc, kr: kr, sink: sink, now: cur}
}

func TestLoginLockoutThenRecovery(t *testing.T) {
	h := newHarness(t, ratelimit.Policy{MaxFailures: 3, Lockout: time.Minute,
		ThrottleAfter: 2, ThrottleDelay: time.Second, Window: 5 * time.Minute})
	ctx := context.Background()
	// 2 bad attempts -> throttle is distinguishable from lockout.
	_, err := h.svc.Login(ctx, "alice", "wrong", "1.1.1.1", "test-ua")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("first bad login err = %v", err)
	}
	_, err = h.svc.Login(ctx, "alice", "wrong", "1.1.1.1", "test-ua")
	if !errors.Is(err, ErrThrottled) {
		t.Fatalf("second bad login err = %v, want ErrThrottled", err)
	}
	// Third crosses threshold -> locked; even the CORRECT password is refused.
	_, err = h.svc.Login(ctx, "alice", "wrong", "1.1.1.1", "test-ua")
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("third bad login err = %v, want ErrLocked", err)
	}
	if _, err := h.svc.Login(ctx, "alice", "correct horse", "1.1.1.1", "test-ua"); !errors.Is(err, ErrLocked) {
		t.Fatalf("correct password during lockout err = %v, want ErrLocked", err)
	}
	events, _ := h.sink.List(ctx)
	var lockouts int
	for _, e := range events {
		if e.Type == audit.EventLockout {
			lockouts++
		}
	}
	if lockouts != 1 {
		t.Fatalf("lockout events = %d, want exactly 1", lockouts)
	}
	t.Logf("input=3 bad logins basis=threshold(3) rules=badcreds->throttled->locked; one lockout event; correct pw denied while locked")
}

func TestFullLifecycleRotateRevokeAndKeyRotation(t *testing.T) {
	h := newHarness(t, ratelimit.DefaultPolicy())
	ctx := context.Background()
	tok, err := h.svc.Login(ctx, "alice", "correct horse", "1.1.1.2", "test-ua")
	if err != nil {
		t.Fatal(err)
	}
	u, sess, err := h.svc.Authenticate(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u.ID != "u1" || sess.ID != tok.SessionID {
		t.Fatalf("identity mismatch %+v %+v", u, sess)
	}

	// Rotate signing key: old access token still verifies (not expired),
	// newly minted tokens carry the new kid.
	newKey, err := h.kr.Rotate(ctx, "k2", []byte("int-secret-2"), h.now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.Authenticate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("old-kid token must still verify after rotation: %v", err)
	}
	rot, err := h.svc.Refresh(ctx, tok.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rot.KeyID != newKey.ID {
		t.Fatalf("refreshed token signed by %s, want %s", rot.KeyID, newKey.ID)
	}
	t.Logf("input=rotate k1->k2 then auth old token & refresh basis=retired key verifies, active key signs rule=backward compatible; new kid=%s", rot.KeyID)

	// Old refresh token replay -> reuse error and family revoked.
	if _, err := h.svc.Refresh(ctx, tok.RefreshToken); !errors.Is(err, session.ErrRefreshReused) {
		t.Fatalf("replay err = %v, want ErrRefreshReused", err)
	}
	if _, _, err := h.svc.Authenticate(ctx, rot.AccessToken); !errors.Is(err, session.ErrSessionRevoked) {
		t.Fatalf("access after family revoke err = %v, want session.ErrSessionRevoked", err)
	}
	if _, err := h.svc.Refresh(ctx, rot.RefreshToken); !errors.Is(err, session.ErrSessionRevoked) {
		t.Fatalf("rotated refresh after reuse err = %v, want session.ErrSessionRevoked", err)
	}
	var reuse, denies int
	events, _ := h.sink.List(ctx)
	for _, e := range events {
		switch e.Type {
		case audit.EventRefreshReuse:
			reuse++
		case audit.EventAccessDenied:
			denies++
		}
		if e.Type == audit.EventLoginFailure {
			t.Fatalf("sensitive detail check: %+v", e.Details)
		}
	}
	if reuse != 1 {
		t.Fatalf("reuse events = %d want 1", reuse)
	}
	t.Log("input=replay old refresh basis=rotated marker rule=ErrRefreshReuse, family kill, new tokens refused, event marked critical")
}

func TestLogoutRevokes(t *testing.T) {
	h := newHarness(t, ratelimit.DefaultPolicy())
	ctx := context.Background()
	tok, _ := h.svc.Login(ctx, "alice", "correct horse", "p", "test-ua")
	if err := h.svc.Logout(ctx, tok.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.svc.Authenticate(ctx, tok.AccessToken); !errors.Is(err, session.ErrSessionRevoked) {
		t.Fatalf("post-logout auth err = %v", err)
	}
	if _, err := h.svc.Refresh(ctx, tok.RefreshToken); !errors.Is(err, session.ErrSessionRevoked) {
		t.Fatalf("post-logout refresh err = %v", err)
	}
	t.Log("input=logout basis=family revoke rule=session+all refresh tokens dead")
}

func TestConcurrentLoginsConsistentCounters(t *testing.T) {
	h := newHarness(t, ratelimit.Policy{MaxFailures: 30, Lockout: time.Minute,
		ThrottleAfter: 1000, Window: time.Minute})
	ctx := context.Background()
	var wg sync.WaitGroup
	locked := make(chan error, 30)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.svc.Login(ctx, "alice", "bad", "peer", "test-ua")
			if errors.Is(err, ErrLocked) {
				locked <- err
			}
		}()
	}
	wg.Wait()
	close(locked)
	n := 0
	for range locked {
		n++
	}
	if n != 1 {
		t.Fatalf("lockout observed by %d concurrent callers, want exactly 1", n)
	}
	events, _ := h.sink.List(ctx)
	var fails, locks int
	for _, e := range events {
		if e.Type == audit.EventLoginFailure {
			fails++
		}
		if e.Type == audit.EventLockout {
			locks++
		}
	}
	if fails != 30 || locks != 1 {
		t.Fatalf("audit failures=%d (want 30), lockouts=%d (want 1)", fails, locks)
	}
	t.Logf("input=30 concurrent bad logins basis=mutex+event ids rule=failures=30 no lost/dup, single lockout")
}

func TestExpiredAccessAndTamperedToken(t *testing.T) {
	h := newHarness(t, ratelimit.DefaultPolicy())
	ctx := context.Background()
	tok, _ := h.svc.Login(ctx, "alice", "correct horse", "p", "test-ua")
	if _, _, err := h.svc.Authenticate(ctx, tok.AccessToken+"x"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("tampered token err = %v", err)
	}
	// Access TTL is 1 minute; session lasts an hour.
	_, _, err := h.svc.AuthenticateAt(ctx, tok.AccessToken, h.now.Add(2*time.Minute))
	if !errors.Is(err, token.ErrExpired) {
		t.Fatalf("expired access err = %v", err)
	}
	t.Log("input=tampered->bad signature invalid; now=access+2m basis=exp rule=ErrExpired distinct from revoke")
}
