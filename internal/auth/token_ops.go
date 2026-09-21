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
	return s.authenticateClaims(ctx, claims)
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
		if errors.Is(err, session.ErrRefreshReused) {
			s.emit(ctx, audit.Event{
				EventID: newEventID("reuse"), Type: audit.EventRefreshReuse, OccurredAt: now,
				Details: map[string]string{"token": "***REDACTED***"},
			})
			return nil, session.ErrRefreshReused
		}
		return nil, ErrInvalidToken
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
		AccessToken:  access,
		RefreshToken: res.NewRefresh,
		SessionID:    res.Session.ID,
		KeyID:        kid,
		ExpiresAt:    expires,
	}, nil
}

// authenticateClaims resolves a principal/session view from verified claims.
func (s *Service) authenticateClaims(ctx context.Context, claims *token.Claims) (*User, *SessionView, error) {
	now := s.cfg.Clock()
	sess, err := s.cfg.Sessions.Validate(ctx, claims.SessionID, now)
	if err != nil {
		return nil, nil, ErrInvalidToken
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
