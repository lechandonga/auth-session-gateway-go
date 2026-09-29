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
	ErrSessionIdle = errors.New("session: idle expired")
	// ErrSessionAbsolute indicates the session reached its absolute lifetime cap.
	ErrSessionAbsolute = errors.New("session: absolute expired")
	// ErrRefreshUnknown indicates the refresh token was never issued.
	ErrRefreshUnknown = errors.New("session: unknown refresh token")
	// ErrRefreshReused indicates a rotated token was replayed; the family is invalidated.
	ErrRefreshReused = errors.New("session: refresh token reuse detected")
	// ErrForbidden indicates the caller does not own the target session.
	ErrForbidden = errors.New("session: not the session owner")
)

// ReuseDetailed wraps ErrRefreshReused with the affected family ID so
// callers can make repeated reports of the same event idempotent.
type ReuseDetailed struct{ FamilyID string }

func (e *ReuseDetailed) Error() string        { return ErrRefreshReused.Error() }
func (e *ReuseDetailed) Is(target error) bool { return target == ErrRefreshReused }

// RevokeReason explains why a session/family was revoked.
type RevokeReason string

const (
	RevokeNone     RevokeReason = ""
	RevokeLogout   RevokeReason = "logout"
	RevokeReuse    RevokeReason = "refresh_reuse"
	RevokeAdmin    RevokeReason = "admin"
	RevokeTarget   RevokeReason = "targeted"
	RevokeIdle     RevokeReason = "idle_expired"
	RevokeAbsolute RevokeReason = "absolute_expired"
	RevokeEvicted  RevokeReason = "capacity_eviction"
)

// Session is a server-side authenticated session.
type Session struct {
	ID        string
	FamilyID  string
	UserID    string
	CreatedAt time.Time
	// IdleExpiresAt slides forward on activity/rotation; AbsoluteExpiresAt
	// is the hard lifetime cap fixed at creation.
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	LastActiveAt      time.Time
	Peer              string
	UserAgent         string
	Revoked           bool
	RevokeReason      RevokeReason
	RevokedAt         time.Time
}

// ExpiryKind reports which lifetime boundary was crossed at time now.
func (s *Session) ExpiryKind(now time.Time) RevokeReason {
	if !now.Before(s.AbsoluteExpiresAt) {
		return RevokeAbsolute
	}
	if !now.Before(s.IdleExpiresAt) {
		return RevokeIdle
	}
	return RevokeNone
}

// Active reports whether the session is usable at time now.
func (s *Session) Active(now time.Time) bool {
	if s.Revoked {
		return false
	}
	return s.ExpiryKind(now) == RevokeNone
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
	Invalidated       bool
	RotatedAt         time.Time
	CreatedAt         time.Time
	AbsoluteExpiresAt time.Time
}

// RotateResult is the outcome of an atomic refresh-token rotation.
type RotateResult struct {
	Session    *Session
	NewRefresh string
	OldRecord  *RefreshRecord
}

// RevokeOutcome reports what a targeted revocation did.
type RevokeOutcome struct {
	// Revoked is true when this call performed the revocation.
	Revoked bool
	// AlreadyRevoked is true when the session existed but was dead already
	// (revoked or expired); the call is an idempotent no-op.
	AlreadyRevoked bool
	Session        *Session
}

// Store is the persistence boundary for sessions and refresh tokens.
type Store interface {
	CreateSession(ctx context.Context, s *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	GetSessionByFamily(ctx context.Context, familyID string) (*Session, error)
	RevokeFamily(ctx context.Context, familyID string, reason RevokeReason, now time.Time) error
	RevokeSession(ctx context.Context, id string, reason RevokeReason, now time.Time) error
	ListSessionsByUser(ctx context.Context, userID string) ([]*Session, error)
	// AllSessions returns every stored session (capacity management).
	AllSessions(ctx context.Context) ([]*Session, error)

	// PutRefresh stores a new refresh record.
	PutRefresh(ctx context.Context, r *RefreshRecord) error
	// GetRefresh returns the record for a token hash.
	GetRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error)
}

// Manager performs atomic session/refresh operations.
type Manager interface {
	// Issue creates a session and its first refresh token atomically.
	Issue(ctx context.Context, p IssueParams, now time.Time) (*Session, string, []*Session, error)
	// Rotate atomically exchanges a refresh token; replays invalidate the family.
	Rotate(ctx context.Context, rawRefresh string, now time.Time) (*RotateResult, error)
	// Revoke invalidates a session (and family) for logout/admin reasons.
	Revoke(ctx context.Context, sessionID string, reason RevokeReason, now time.Time) error
	// RevokeForUser revokes a session only if it belongs to requesterID;
	// ownership, existence and liveness are distinguishable.
	RevokeForUser(ctx context.Context, requesterID, sessionID string, now time.Time) (*RevokeOutcome, error)
	// Validate checks a session exists and is active.
	Validate(ctx context.Context, sessionID string, now time.Time) (*Session, error)
	// Touch marks activity, sliding only the idle window.
	Touch(ctx context.Context, sessionID string, now time.Time) (*Session, error)
	// List returns a user's active sessions, newest first.
	List(ctx context.Context, userID string, now time.Time) ([]*Session, error)
}

// IssueParams carries session creation inputs.
type IssueParams struct {
	UserID    string
	Peer      string
	UserAgent string
}
