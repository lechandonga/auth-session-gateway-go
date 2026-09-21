// Package session manages server-side sessions and rotating refresh tokens.
package session

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrSessionNotFound indicates no session matched the lookup.
	ErrSessionNotFound = errors.New("session: not found")
	// ErrSessionRevoked indicates the session (or its family) was revoked.
	ErrSessionRevoked = errors.New("session: revoked")
	// ErrSessionExpired indicates the session reached its expiry.
	ErrSessionExpired = errors.New("session: expired")
	// ErrRefreshUnknown indicates the refresh token was never issued.
	ErrRefreshUnknown = errors.New("session: unknown refresh token")
	// ErrRefreshReused indicates a rotated token was replayed; the family is invalidated.
	ErrRefreshReused = errors.New("session: refresh token reuse detected")
)

// RevokeReason explains why a session/family was revoked.
type RevokeReason string

const (
	RevokeNone    RevokeReason = ""
	RevokeLogout  RevokeReason = "logout"
	RevokeReuse   RevokeReason = "refresh_reuse"
	RevokeAdmin   RevokeReason = "admin"
	RevokeExpired RevokeReason = "expired"
)

// Session is a server-side authenticated session.
type Session struct {
	ID           string
	FamilyID     string
	UserID       string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Revoked      bool
	RevokeReason RevokeReason
	RevokedAt    time.Time
}

// Active reports whether the session is usable at time now.
func (s *Session) Active(now time.Time) bool {
	if s.Revoked {
		return false
	}
	return now.Before(s.ExpiresAt)
}

// RefreshRecord stores metadata for one issued refresh token.
type RefreshRecord struct {
	// TokenHash is SHA-256 of the opaque refresh token.
	TokenHash string
	SessionID string
	FamilyID  string
	// Rotated is true once this token was exchanged for a new one.
	Rotated bool
	// Invalidated is true when revocation killed a still-current token
	// without a rotation (distinct from normal rotation).
	Invalidated bool
	RotatedAt   time.Time
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// RotateResult is the outcome of an atomic refresh-token rotation.
type RotateResult struct {
	Session    *Session
	NewRefresh string
	OldRecord  *RefreshRecord
}

// Store is the persistence boundary for sessions and refresh tokens.
type Store interface {
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	GetSessionByFamily(ctx context.Context, familyID string) (*Session, error)
	RevokeFamily(ctx context.Context, familyID string, reason RevokeReason, now time.Time) error
	RevokeSession(ctx context.Context, id string, reason RevokeReason, now time.Time) error

	// PutRefresh stores a new refresh record.
	PutRefresh(ctx context.Context, r *RefreshRecord) error
	// GetRefresh returns the record for a token hash.
	GetRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error)
}

// Manager performs atomic session/refresh operations.
type Manager interface {
	// Issue creates a session and its first refresh token atomically.
	Issue(ctx context.Context, userID string, ttl time.Duration, now time.Time) (*Session, string, error)
	// Rotate atomically exchanges a refresh token; replays invalidate the family.
	Rotate(ctx context.Context, rawRefresh string, now time.Time) (*RotateResult, error)
	// Revoke invalidates a session (and family) for logout/admin reasons.
	Revoke(ctx context.Context, sessionID string, reason RevokeReason, now time.Time) error
	// Validate checks a session exists and is active.
	Validate(ctx context.Context, sessionID string, now time.Time) (*Session, error)
}
