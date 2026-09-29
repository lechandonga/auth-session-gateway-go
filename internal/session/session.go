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
	// ErrSessionIdle indicates the session exceeded its inactivity window.
	ErrSessionIdle = errors.New("session: idle timeout")
	// ErrSessionAbsoluteExpired indicates the session reached its hard cap.
	ErrSessionExpired = errors.New("session: expired")
	// ErrRefreshUnknown indicates the refresh token was never issued.
	ErrRefreshUnknown = errors.New("session: unknown refresh token")
	// ErrRefreshReused indicates a rotated token was replayed; the family is invalidated.
	ErrRefreshReused = errors.New("session: refresh token reuse detected")
	// ErrNotOwner indicates a caller targeted another user's session.
	ErrNotOwner = errors.New("session: not the session owner")
)

// RevokeReason explains why a session/family was revoked.
type RevokeReason string

const (
	RevokeNone     RevokeReason = ""
	RevokeLogout   RevokeReason = "logout"
	RevokeReuse    RevokeReason = "refresh_reuse"
	RevokeAdmin    RevokeReason = "admin"
	RevokeIdle     RevokeReason = "idle_timeout"
	RevokeAbsolute RevokeReason = "absolute_timeout"
	RevokeEvicted  RevokeReason = "capacity_eviction"
)

// Session is a server-side authenticated session.
type Session struct {
	ID       string
	FamilyID string
	UserID   string
	// Label is a caller-supplied recognisable source marker (device, UA).
	Label        string
	CreatedAt    time.Time
	LastActiveAt time.Time
	// IdleDeadline is the inactivity cutoff; rotation pushes it forward.
	IdleDeadline time.Time
	// AbsoluteDeadline is the hard lifetime cap, never extended.
	AbsoluteDeadline time.Time
	Revoked          bool
	RevokeReason     RevokeReason
	RevokedAt        time.Time
}

// Active reports whether the session is usable at time now.
func (s *Session) Active(now time.Time) bool {
	if s.Revoked {
		return false
	}
	return now.Before(s.IdleDeadline) && now.Before(s.AbsoluteDeadline)
}

// ExpiryReason classifies why a non-active session is dead.
func (s *Session) ExpiryReason(now time.Time) error {
	if !now.Before(s.AbsoluteDeadline) {
		return ErrSessionExpired
	}
	if !now.Before(s.IdleDeadline) {
		return ErrSessionIdle
	}
	return nil
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
	Invalidated  bool
	RotatedAt    time.Time
	CreatedAt    time.Time
	IdleDeadline time.Time
}

// RotateResult is the outcome of an atomic refresh-token rotation.
type RotateResult struct {
	Session    *Session
	NewRefresh string
	OldRecord  *RefreshRecord
}

// IssueParams controls a new session's lifetime and identity markers.
type IssueParams struct {
	UserID      string
	Label       string
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	Now         time.Time
}

// IssueResult carries the issued session, its first refresh token and any
// sessions evicted to honour the per-user capacity limit.
type IssueResult struct {
	Session *Session
	Refresh string
	Evicted []*Session
}

// Store is the persistence boundary for sessions and refresh tokens.
type Store interface {
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	GetSessionByFamily(ctx context.Context, familyID string) (*Session, error)
	RevokeFamily(ctx context.Context, familyID string, reason RevokeReason, now time.Time) error
	// RevokeSession invalidates exactly one session, not its neighbours.
	RevokeSession(ctx context.Context, id string, reason RevokeReason, now time.Time) error
	// ListUserSessions returns the user's sessions in any order.
	ListUserSessions(ctx context.Context, userID string) ([]*Session, error)
	// EvictLRU revokes the oldest-by-last-activity active sessions of
	// userID except keep, until at most keep-1 remain; caller decides count.
	EvictLRU(ctx context.Context, userID string, keep int, reason RevokeReason, now time.Time) ([]*Session, error)

	// PutRefresh stores a new refresh record.
	PutRefresh(ctx context.Context, r *RefreshRecord) error
	// GetRefresh returns the record for a token hash.
	GetRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error)
}

// Manager performs atomic session/refresh operations.
type Manager interface {
	// Issue creates a session and its first refresh token atomically.
	Issue(ctx context.Context, p IssueParams) (*IssueResult, error)
	// Rotate atomically exchanges a refresh token; replays invalidate the family.
	Rotate(ctx context.Context, rawRefresh string, now time.Time) (*RotateResult, error)
	// Revoke invalidates a session (and family) for logout/admin reasons.
	Revoke(ctx context.Context, sessionID string, reason RevokeReason, now time.Time) error
	// RevokeOne invalidates exactly one session after an ownership check.
	// ErrSessionNotFound and ErrNotOwner stay distinguishable.
	RevokeOne(ctx context.Context, actorUserID, sessionID string, reason RevokeReason, now time.Time) error
	// ListActive returns a user's currently active sessions.
	ListActive(ctx context.Context, userID string, now time.Time) ([]*Session, error)
	// Validate checks a session exists and is active.
	Validate(ctx context.Context, sessionID string, now time.Time) (*Session, error)
	// Touch records activity on an active session without changing the
	// absolute deadline; it is a no-op for dead sessions.
	Touch(ctx context.Context, sessionID string, now time.Time) error
}
