package auth

import (
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/keyring"
	"github.com/lechandonga/auth-session-gateway-go/internal/ratelimit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/token"
)

func ratelimitPolicyForTest() ratelimit.Policy {
	return ratelimit.DefaultPolicy()
}

func newHarnessWithCap(t *testing.T, cap int, cur *time.Time) *harness {
	return newHarnessConfigured(t, time.Hour, 24*time.Hour, cap, cur)
}

func newHarnessWithTimeouts(t *testing.T, idle, abs time.Duration, cur *time.Time) *harness {
	return newHarnessConfigured(t, idle, abs, 10, cur)
}

func newHarnessConfigured(t *testing.T, idle, abs time.Duration, cap int, cur *time.Time) *harness {
	t.Helper()
	kr := keyring.NewMemoryKeyring()
	if err := kr.AddKey(&keyring.Key{ID: "k1", Secret: []byte("int-secret-1"),
		Status: keyring.StatusActive, CreatedAt: *cur}); err != nil {
		t.Fatal(err)
	}
	users := NewMemoryUsers()
	u, err := NewUser("u1", "alice", "correct horse",
		[]string{"viewer"}, []string{"docs:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	users.Add(u)
	sink := audit.NewMemorySink()
	svc := NewService(Config{
		Users:       users,
		Sessions:    session.NewManager(session.NewMemoryStore(), idle, abs, cap),
		Signer:      token.NewHS256Signer(kr),
		Limiter:     ratelimit.NewMemoryLimiter(ratelimit.DefaultPolicy()),
		Audit:       sink,
		AccessTTL:   time.Minute,
		RefreshTTL:  abs,
		IdleTTL:     idle,
		AbsoluteTTL: abs,
		MaxSessions: cap,
		Clock:       func() time.Time { return *cur },
	})
	return &harness{svc: svc, kr: kr, sink: sink, now: *cur}
}
