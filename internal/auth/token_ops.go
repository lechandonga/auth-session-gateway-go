package auth

import (
	"context"
	"errors"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/token"
)

// userByIDer is optionally supported by credential stores.
type userByIDer interface {
	ByID(id string) (*User, bool)
}

// Authenticate verifies an access token cryptographically, confirms its
// session is still alive (revoked/expired sessions never pass, even with an
// unexpired signature) and returns the principal plus a session view.
func (s *Service) Authenticate(ctx context.Context, accessToken string) (*User, *SessionView, error) {
	now := s.cfg.Clock()
	claims, _, err := s.cfg.Signer.Verify(ctx, accessToken, now)
	if err != nil {
		if errors.Is(err, token.ErrExpired) {
			return nil, nil, token.ErrExpired
		}
		return nil, nil, ErrInvalidToken
	}
	if claims.TokenType != "access" {
		return nil, nil, ErrInvalidToken
	}
	u, view, err := s.authenticateClaims(ctx, claims)
	if err != nil {
		return nil, nil, err
	}
	// Successful use counts as activity and pushes the idle window only via
	// LastActiveAt tracking; the idle deadline itself moves on refresh.
	_ = s.cfg.Sessions.Touch(ctx, view.ID, now)
	return u, view, nil
}

// Logout cryptographically validates the token to name the session, then
// revokes the whole session family so every related refresh token dies.
func (s *Service) Logout(ctx context.Context, accessToken string) error {
	now := s.cfg.Clock()
	claims, _, err := s.cfg.Signer.Verify(ctx, accessToken, now)
	if err != nil {
		// Expired token still names a session; allow logout if the SID exists.
		if !errors.Is(err, token.ErrExpired) {
			return ErrInvalidToken
		}
	}
	if claims == nil || claims.SessionID == "" {
		return ErrInvalidToken
	}
	if err := s.cfg.Sessions.Revoke(ctx, claims.SessionID, session.RevokeLogout, now); err != nil {
		return err
	}
	s.emit(ctx, audit.Event{
		EventID: "revoke:" + claims.SessionID, Type: audit.EventRevoke, OccurredAt: now,
		Principal: claims.Subject, SessionID: claims.SessionID,
		Details: map[string]string{"reason": string(session.RevokeLogout)},
	})
	return nil
}

// Refresh atomically rotates a refresh token. A replay of an old token is
// recognized as reuse, revokes its family and emits a critical event.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginTokens, error) {
	now := s.cfg.Clock()
	res, err := s.cfg.Sessions.Rotate(ctx, refreshToken, now)
	if err != nil {
		return nil, s.mapSessionError(ctx, err, now)
	}
	var u *User
	if byID, ok := s.cfg.Users.(userByIDer); ok {
		u, _ = byID.ByID(res.Session.UserID)
	}
	if u == nil {
		u = &User{ID: res.Session.UserID}
	}
	expires := now.Add(s.cfg.AccessTTL)
	access, kid, err := s.cfg.Signer.Issue(ctx, token.Claims{
		Subject:    u.ID,
		SessionID:  res.Session.ID,
		FamilyID:   res.Session.FamilyID,
		Roles:      u.Roles,
		Scope:      u.Scopes,
		Attributes: u.Attributes,
		ExpiresAt:  expires.Unix(),
		TokenType:  "access",
	}, now)
	if err != nil {
		return nil, err
	}
	s.emit(ctx, audit.Event{
		EventID: newEventID("rot"), Type: audit.EventRefresh, OccurredAt: now,
		Principal: u.ID, SessionID: res.Session.ID, Details: map[string]string{"kid": kid},
	})
	return &LoginTokens{
		AccessToken:      access,
		RefreshToken:     res.NewRefresh,
		SessionID:        res.Session.ID,
		KeyID:            kid,
		ExpiresAt:        expires,
		IdleDeadline:     res.Session.IdleDeadline,
		AbsoluteDeadline: res.Session.AbsoluteDeadline,
	}, nil
}

// mapSessionError translates session-layer failures into distinct auth
// errors and emits the corresponding audit record. Reuse is reported with a
// stable per-token-hash event ID so the same replayed token is never
// double-counted; the family kill itself happens exactly once in the
// session manager.
func (s *Service) mapSessionError(ctx context.Context, err error, now time.Time) error {
	switch {
	case errors.Is(err, session.ErrRefreshReused):
		s.emit(ctx, audit.Event{
			EventID: newEventID("reuse"), Type: audit.EventRefreshReuse, OccurredAt: now,
			Details: map[string]string{"token": "***REDACTED***"},
		})
		return session.ErrRefreshReused
	case errors.Is(err, session.ErrSessionIdle):
		return ErrSessionIdle
	case errors.Is(err, session.ErrSessionExpired):
		return ErrSessionAbsolute
	case errors.Is(err, session.ErrSessionRevoked):
		return ErrSessionRevoked
	case errors.Is(err, session.ErrSessionNotFound), errors.Is(err, session.ErrRefreshUnknown):
		return ErrInvalidToken
	default:
		return ErrInvalidToken
	}
}

// SessionInfo is the non-sensitive per-session view returned to owners.
type SessionInfo struct {
	ID               string    `json:"session_id"`
	Label            string    `json:"label"`
	CreatedAt        time.Time `json:"created_at"`
	LastActiveAt     time.Time `json:"last_active_at"`
	IdleDeadline     time.Time `json:"idle_deadline"`
	AbsoluteDeadline time.Time `json:"absolute_deadline"`
	Current          bool      `json:"current,omitempty"`
}

// ListSessions returns the caller's active sessions.
func (s *Service) ListSessions(ctx context.Context, userID, currentSessionID string, now time.Time) ([]SessionInfo, error) {
	active, err := s.cfg.Sessions.ListActive(ctx, userID, now)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(active))
	for _, sess := range active {
		out = append(out, SessionInfo{
			ID: sess.ID, Label: sess.Label, CreatedAt: sess.CreatedAt,
			LastActiveAt: sess.LastActiveAt, IdleDeadline: sess.IdleDeadline,
			AbsoluteDeadline: sess.AbsoluteDeadline,
			Current:          sess.ID == currentSessionID,
		})
	}
	return out, nil
}

// RevokeSession revokes one of the caller's own sessions. Not-found,
// ownership violation, already-revoked and expired are distinct outcomes;
// every attempt is audited, and repeat reports cannot double-revoke.
func (s *Service) RevokeSession(ctx context.Context, actorUserID, sessionID string, now time.Time) error {
	err := s.cfg.Sessions.RevokeOne(ctx, actorUserID, sessionID, session.RevokeAdmin, now)
	switch {
	case err == nil:
		s.emit(ctx, audit.Event{
			EventID: "revokeone:" + sessionID, Type: audit.EventRevoke, OccurredAt: now,
			Principal: actorUserID, SessionID: sessionID,
			Details: map[string]string{"reason": string(session.RevokeAdmin)},
		})
		return nil
	case errors.Is(err, session.ErrNotOwner):
		s.emit(ctx, audit.Event{
			EventID: newEventID("revdeny"), Type: audit.EventRevokeDenied, OccurredAt: now,
			Principal: actorUserID, SessionID: sessionID,
			Details: map[string]string{"reason": "not_owner"},
		})
		return ErrNotOwner
	case errors.Is(err, session.ErrSessionNotFound):
		// Do not attribute an attempt against a nonexistent session to a
		// victim; record against the actor without touching any session.
		s.emit(ctx, audit.Event{
			EventID: newEventID("revdeny"), Type: audit.EventRevokeDenied, OccurredAt: now,
			Principal: actorUserID, SessionID: sessionID,
			Details: map[string]string{"reason": "not_found"},
		})
		return ErrSessionNotFound
	case errors.Is(err, session.ErrSessionIdle):
		return ErrSessionIdle
	case errors.Is(err, session.ErrSessionExpired):
		return ErrSessionAbsolute
	case errors.Is(err, session.ErrSessionRevoked):
		return ErrSessionRevoked
	default:
		return ErrInvalidToken
	}
}

// authenticateClaims resolves a principal/session view from verified claims.
func (s *Service) authenticateClaims(ctx context.Context, claims *token.Claims) (*User, *SessionView, error) {
	now := s.cfg.Clock()
	sess, err := s.cfg.Sessions.Validate(ctx, claims.SessionID, now)
	if err != nil {
		// A family killed by reuse presents to access-token callers as a
		// revoked session; only refresh-token replays emit reuse events.
		if errors.Is(err, session.ErrRefreshReused) {
			return nil, nil, ErrSessionRevoked
		}
		return nil, nil, s.mapSessionError(ctx, err, now)
	}
	var u *User
	if byID, ok := s.cfg.Users.(userByIDer); ok {
		u, _ = byID.ByID(claims.Subject)
	}
	if u == nil {
		u = &User{ID: claims.Subject, Roles: claims.Roles, Scopes: claims.Scope, Attributes: claims.Attributes}
	}
	view := &SessionView{ID: sess.ID, FamilyID: sess.FamilyID, UserID: sess.UserID,
		Roles: claims.Roles, Scopes: claims.Scope}
	return u, view, nil
}

// AuthenticateAt authenticates against an explicitly supplied time, which
// lets callers/tests reason about expiry independently of the clock.
func (s *Service) AuthenticateAt(ctx context.Context, accessToken string, at time.Time) (*User, *SessionView, error) {
	claims, _, err := s.cfg.Signer.Verify(ctx, accessToken, at)
	if err != nil {
		if errors.Is(err, token.ErrExpired) {
			return nil, nil, token.ErrExpired
		}
		return nil, nil, ErrInvalidToken
	}
	return s.authenticateClaims(ctx, claims)
}
