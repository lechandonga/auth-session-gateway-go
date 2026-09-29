package auth

import (
	"context"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/csrf"
	"github.com/lechandonga/auth-session-gateway-go/internal/ratelimit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/token"
)

// Login verifies credentials, applies the lockout/throttle policy and
// issues an access/refresh token pair bound to a new independent session.
//
// Lockout and throttle are reported via distinct errors (ErrLocked vs
// ErrThrottled). Counter mutation and lock transition happen inside the
// limiter's single critical section, so concurrent attempts cannot skip the
// threshold nor cross it twice. Each failure carries a unique event ID,
// making retried requests idempotent rather than double-counted.
func (s *Service) Login(ctx context.Context, username, password, peer string) (*LoginTokens, error) {
	return s.LoginWithLabel(ctx, username, password, peer, "")
}

// LoginWithLabel is Login with a client-supplied device/source label. When
// the per-account active-session cap is exceeded the longest-idle sessions
// are evicted atomically with login: their credentials are dead the instant
// the new session appears, and each eviction gets its own audit event.
func (s *Service) LoginWithLabel(ctx context.Context, username, password, peer, label string) (*LoginTokens, error) {
	now := s.cfg.Clock()
	key := "login:" + username
	eventID := newEventID("fail")

	if reason, err := s.cfg.Limiter.Check(ctx, key, now); err != nil {
		return nil, err
	} else if reason == ratelimit.ReasonLocked {
		// Idempotent per lock window: repeated attempts during the same
		// lockout never create duplicate lockout events (and cannot
		// re-trigger any downstream lock action).
		st, _ := s.cfg.Limiter.StateAt(ctx, key, now)
		s.emit(ctx, audit.Event{
			EventID: "lock:" + key + ":" + itoa64(st.LockedUntil.UnixNano()),
			Type:    audit.EventLockout, OccurredAt: now,
			Principal: username, Details: map[string]string{"phase": "check", "peer": peer},
		})
		return nil, ErrLocked
	}

	v, ok := s.cfg.Users.(verifier)
	var u *User
	if ok {
		u, ok = v.Verify(username, password)
	} else {
		found, ferr := s.cfg.Users.ByLogin(ctx, username)
		if ferr == nil && verifyPassword(found.PasswordHash, password) {
			u, ok = found, true
		}
	}
	if !ok || u == nil {
		st, reason, err := s.cfg.Limiter.RecordFailure(ctx, key, eventID, now)
		if err != nil {
			return nil, err
		}
		details := map[string]string{
			"username": csrf.Sanitize(username),
			"peer":     peer,
			"failures": itoa(st.Failures),
			"password": csrf.Mask("password", password),
		}
		s.emit(ctx, audit.Event{
			EventID: eventID, Type: audit.EventLoginFailure, OccurredAt: now,
			Principal: username, Details: details,
		})
		if reason == ratelimit.ReasonLocked {
			s.emit(ctx, audit.Event{
				EventID: "lock:" + key + ":" + itoa64(st.LockedUntil.UnixNano()),
				Type:    audit.EventLockout, OccurredAt: now, Principal: username,
				Details: map[string]string{"until": st.LockedUntil.Format(time.RFC3339), "peer": peer},
			})
			return nil, ErrLocked
		}
		if reason == ratelimit.ReasonThrottled {
			s.emit(ctx, audit.Event{
				EventID: newEventID("thr"), Type: audit.EventThrottle, OccurredAt: now,
				Principal: username, Details: map[string]string{"peer": peer},
			})
			return nil, ErrThrottled
		}
		return nil, ErrBadCredentials
	}

	// Success resets counters (idempotent).
	_ = s.cfg.Limiter.RecordSuccess(ctx, key, "ok:"+eventID, now)

	issue, err := s.cfg.Sessions.Issue(ctx, session.IssueParams{
		UserID:      u.ID,
		Label:       label,
		IdleTTL:     s.cfg.IdleTTL,
		AbsoluteTTL: s.cfg.AbsoluteTTL,
		Now:         now,
	})
	if err != nil {
		return nil, err
	}
	sess, rawRefresh := issue.Session, issue.Refresh
	expires := now.Add(s.cfg.AccessTTL)
	access, kid, err := s.cfg.Signer.Issue(ctx, token.Claims{
		Subject:    u.ID,
		SessionID:  sess.ID,
		FamilyID:   sess.FamilyID,
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
		EventID: "loginok:" + sess.ID, Type: audit.EventLoginSuccess, OccurredAt: now,
		Principal: u.ID, SessionID: sess.ID,
		Details: map[string]string{"kid": kid, "peer": csrf.Sanitize(peer),
			"label": csrf.Sanitize(label)},
	})
	for _, ev := range issue.Evicted {
		s.emit(ctx, audit.Event{
			EventID: "evict:" + ev.ID, Type: audit.EventSessionEvicted, OccurredAt: now,
			Principal: u.ID, SessionID: ev.ID,
			Details: map[string]string{
				"reason":         string(session.RevokeEvicted),
				"last_active_at": ev.LastActiveAt.Format(time.RFC3339),
			},
		})
	}
	return &LoginTokens{
		AccessToken:      access,
		RefreshToken:     rawRefresh,
		SessionID:        sess.ID,
		KeyID:            kid,
		ExpiresAt:        expires,
		IdleDeadline:     sess.IdleDeadline,
		AbsoluteDeadline: sess.AbsoluteDeadline,
	}, nil
}
