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
// unexpired signature), slides the session idle window and returns the
// principal plus a session view.
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
	return s.authenticateClaims(ctx, claims)
}

// Logout cryptographically validates the token to name the session, then
// revokes the whole session family so every related refresh token dies.
// Logout is idempotent: a session already dead still clears client state.
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
	sess, err := s.cfg.Sessions.Validate(ctx, claims.SessionID, now)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return ErrInvalidToken
		}
		// Already revoked/expired: idempotent success.
		return nil
	}
	if err := s.cfg.Sessions.Revoke(ctx, sess.ID, session.RevokeLogout, now); err != nil {
		return err
	}
	s.emit(ctx, audit.Event{
		EventID: "revoke:" + sess.ID, Type: audit.EventRevoke, OccurredAt: now,
		Principal: claims.Subject, SessionID: sess.ID,
		Details: map[string]string{"reason": string(session.RevokeLogout)},
	})
	return nil
}

// Refresh atomically rotates a refresh token. The returned error keeps the
// underlying session cause distinguishable: reuse, revoked, idle/absolute
// expiry and unknown token never collapse into one generic failure.
func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginTokens, error) {
	now := s.cfg.Clock()
	res, err := s.cfg.Sessions.Rotate(ctx, refreshToken, now)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrRefreshReused):
			eventID := newEventID("reuse")
			var rd *session.ReuseDetailed
			if errors.As(err, &rd) && rd.FamilyID != "" {
				eventID = "reuse-family:" + rd.FamilyID
			}
			s.emit(ctx, audit.Event{
				EventID: eventID, Type: audit.EventRefreshReuse, OccurredAt: now,
				Details: map[string]string{"refresh_token": "***REDACTED***"},
			})
			return nil, session.ErrRefreshReused
		case errors.Is(err, session.ErrSessionRevoked):
			return nil, session.ErrSessionRevoked
		case errors.Is(err, session.ErrSessionIdle):
			return nil, session.ErrSessionIdle
		case errors.Is(err, session.ErrSessionAbsolute):
			return nil, session.ErrSessionAbsolute
		default:
			return nil, ErrInvalidToken
		}
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
		AccessToken:       access,
		RefreshToken:      res.NewRefresh,
		SessionID:         res.Session.ID,
		KeyID:             kid,
		ExpiresAt:         expires,
		IdleExpiresAt:     res.Session.IdleExpiresAt,
		AbsoluteExpiresAt: res.Session.AbsoluteExpiresAt,
	}, nil
}

// authenticateClaims resolves a principal/session view from verified claims
// and slides the idle window. Revocation and the two expiry kinds remain
// distinct errors.
func (s *Service) authenticateClaims(ctx context.Context, claims *token.Claims) (*User, *SessionView, error) {
	now := s.cfg.Clock()
	sess, err := s.cfg.Sessions.Touch(ctx, claims.SessionID, now)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrSessionRevoked):
			return nil, nil, session.ErrSessionRevoked
		case errors.Is(err, session.ErrSessionIdle):
			return nil, nil, session.ErrSessionIdle
		case errors.Is(err, session.ErrSessionAbsolute):
			return nil, nil, session.ErrSessionAbsolute
		default:
			return nil, nil, ErrInvalidToken
		}
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
	return s.authenticateClaimsAt(ctx, claims, at)
}

func (s *Service) authenticateClaimsAt(ctx context.Context, claims *token.Claims, at time.Time) (*User, *SessionView, error) {
	sess, err := s.cfg.Sessions.Validate(ctx, claims.SessionID, at)
	if err != nil {
		switch {
		case errors.Is(err, session.ErrSessionRevoked):
			return nil, nil, session.ErrSessionRevoked
		case errors.Is(err, session.ErrSessionIdle):
			return nil, nil, session.ErrSessionIdle
		case errors.Is(err, session.ErrSessionAbsolute):
			return nil, nil, session.ErrSessionAbsolute
		default:
			return nil, nil, ErrInvalidToken
		}
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

// SessionInfo is a non-sensitive view of one active session.
type SessionInfo struct {
	ID                string    `json:"session_id"`
	CreatedAt         time.Time `json:"created_at"`
	LastActiveAt      time.Time `json:"last_active_at"`
	IdleExpiresAt     time.Time `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
	Peer              string    `json:"peer"`
	UserAgent         string    `json:"user_agent"`
	Current           bool      `json:"current"`
}

// ListSessions returns the caller's active sessions with recognisable
// provenance marks.
func (s *Service) ListSessions(ctx context.Context, userID, currentSessionID string) ([]SessionInfo, error) {
	now := s.cfg.Clock()
	list, err := s.cfg.Sessions.List(ctx, userID, now)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(list))
	for _, sess := range list {
		out = append(out, SessionInfo{
			ID: sess.ID, CreatedAt: sess.CreatedAt, LastActiveAt: sess.LastActiveAt,
			IdleExpiresAt: sess.IdleExpiresAt, AbsoluteExpiresAt: sess.AbsoluteExpiresAt,
			Peer: sess.Peer, UserAgent: sess.UserAgent, Current: sess.ID == currentSessionID,
		})
	}
	return out, nil
}

// RevokeTarget revokes one of the caller's own sessions. Not-found,
// ownership violation, already-dead and fresh revoke are all distinct.
func (s *Service) RevokeTarget(ctx context.Context, requesterID, sessionID string) (revoked bool, err error) {
	now := s.cfg.Clock()
	out, rerr := s.cfg.Sessions.RevokeForUser(ctx, requesterID, sessionID, now)
	if rerr != nil {
		switch {
		case errors.Is(rerr, session.ErrSessionNotFound):
			return false, session.ErrSessionNotFound
		case errors.Is(rerr, session.ErrForbidden):
			s.emit(ctx, audit.Event{
				EventID: newEventID("revdeny"), Type: audit.EventSessionRevokeDenied, OccurredAt: now,
				Principal: requesterID, SessionID: sessionID,
				Details: map[string]string{"reason": "not_owner"},
			})
			return false, ErrSessionDenied
		default:
			return false, rerr
		}
	}
	if out.Revoked {
		s.emit(ctx, audit.Event{
			EventID: "trevoke:" + sessionID, Type: audit.EventSessionRevoked, OccurredAt: now,
			Principal: requesterID, SessionID: sessionID,
			Details: map[string]string{"reason": string(session.RevokeTarget)},
		})
	}
	return out.Revoked, nil
}
