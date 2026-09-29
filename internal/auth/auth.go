// Package auth composes credential verification, lockout, session
// management, token issuance and auditing into an authentication service.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/ratelimit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/token"
)

var (
	// ErrBadCredentials indicates username/password verification failed.
	ErrBadCredentials = errors.New("auth: bad credentials")
	// ErrLocked indicates the account is locked due to failed attempts.
	ErrLocked = errors.New("auth: account locked")
	// ErrThrottled indicates the attempt is delayed/refused by rate policy.
	ErrThrottled = errors.New("auth: throttled")
	// ErrInvalidToken indicates an access/refresh token is unusable.
	ErrInvalidToken = errors.New("auth: invalid token")
	// ErrSessionIdle indicates the session exceeded its idle window.
	ErrSessionIdle = errors.New("auth: session idle timeout")
	// ErrSessionAbsolute indicates the session reached its absolute cap.
	ErrSessionAbsolute = errors.New("auth: session absolute timeout")
	// ErrSessionNotFound indicates the targeted session does not exist.
	ErrSessionNotFound = errors.New("auth: session not found")
	// ErrNotOwner indicates the caller does not own the targeted session.
	ErrNotOwner = errors.New("auth: not the session owner")
	// ErrSessionRevoked indicates the session was revoked/evicted.
	ErrSessionRevoked = errors.New("auth: session revoked")
)

// User is a stored principal.
type User struct {
	ID           string
	Username     string
	PasswordHash []byte
	Roles        []string
	Scopes       []string
	Attributes   map[string]string
}

// CredentialStore looks up users.
type CredentialStore interface {
	ByLogin(ctx context.Context, username string) (*User, error)
}

// verifier is implemented by MemoryUsers.
type verifier interface {
	Verify(username, password string) (*User, bool)
}

// LoginTokens carries issued credentials.
type LoginTokens struct {
	AccessToken      string
	RefreshToken     string
	SessionID        string
	KeyID            string
	ExpiresAt        time.Time
	IdleDeadline     time.Time
	AbsoluteDeadline time.Time
}

// Clock allows tests to control time.
type Clock func() time.Time

// Config holds service dependencies and tunables.
type Config struct {
	Users       CredentialStore
	Sessions    session.Manager
	Signer      token.Signer
	Limiter     ratelimit.Limiter
	Audit       audit.Sink
	AccessTTL   time.Duration
	RefreshTTL  time.Duration
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	MaxSessions int
	Clock       Clock
}

// Service is the authentication facade.
type Service struct {
	cfg Config
}

// NewService constructs an authentication Service from a Config.
func NewService(cfg Config) *Service {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 24 * time.Hour
	}
	return &Service{cfg: cfg}
}

func newEventID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
}

// ClockNow exposes the service clock for HTTP handlers that need the same
// controlled time in tests.
func (s *Service) ClockNow() time.Time { return s.cfg.Clock() }

func (s *Service) hashRefresh(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SessionView is the session data exposed after authentication.
type SessionView struct {
	ID       string
	FamilyID string
	UserID   string
	Roles    []string
	Scopes   []string
}

func (s *Service) emit(ctx context.Context, ev audit.Event) {
	if s.cfg.Audit != nil {
		_, _ = s.cfg.Audit.Record(ctx, ev)
	}
}
