package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"time"
)

// DefaultManager coordinates a Store with atomic rotation semantics.
type DefaultManager struct {
	store       Store
	idleTTL     time.Duration
	absoluteTTL time.Duration
	maxSessions int
}

// NewManager constructs a DefaultManager.
func NewManager(store Store, idleTTL, absoluteTTL time.Duration, maxSessions int) *DefaultManager {
	if absoluteTTL <= 0 {
		absoluteTTL = idleTTL
	}
	if maxSessions <= 0 {
		maxSessions = 10
	}
	return &DefaultManager{store: store, idleTTL: idleTTL, absoluteTTL: absoluteTTL, maxSessions: maxSessions}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (m *DefaultManager) Issue(ctx context.Context, p IssueParams) (*IssueResult, error) {
	now := p.Now
	idleTTL := p.IdleTTL
	if idleTTL <= 0 {
		idleTTL = m.idleTTL
	}
	absoluteTTL := p.AbsoluteTTL
	if absoluteTTL <= 0 {
		absoluteTTL = m.absoluteTTL
	}
	sid, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	fam, err := randomToken(16)
	if err != nil {
		return nil, err
	}
	raw, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:               sid,
		FamilyID:         fam,
		UserID:           p.UserID,
		Label:            p.Label,
		CreatedAt:        now,
		LastActiveAt:     now,
		IdleDeadline:     now.Add(idleTTL),
		AbsoluteDeadline: now.Add(absoluteTTL),
	}
	rec := &RefreshRecord{
		TokenHash:    hashToken(raw),
		SessionID:    sid,
		FamilyID:     fam,
		CreatedAt:    now,
		IdleDeadline: sess.IdleDeadline,
	}
	// Compound mutation: capacity eviction + session + first refresh token
	// all appear under one critical section; a client can never observe the
	// new session without the evicted credentials already being dead.
	if ms, isMem := m.store.(*MemoryStore); isMem {
		ms.mu.Lock()
		defer ms.mu.Unlock()
		var evicted []*Session
		if m.maxSessions > 0 {
			evicted, err = ms.evictLRULocked(p.UserID, m.maxSessions-1, RevokeEvicted, now)
			if err != nil {
				return nil, err
			}
		}
		cp := *sess
		ms.sessions[sess.ID] = &cp
		ms.families[sess.FamilyID] = sess.ID
		cpr := *rec
		ms.refresh[rec.TokenHash] = &cpr
		out := IssueResult{Session: sess, Refresh: raw, Evicted: evicted}
		return &out, nil
	}
	// Generic store path: evict then create (best-effort two-phase for
	// non-memory backends).
	if m.maxSessions > 0 {
		if _, err := m.store.EvictLRU(ctx, p.UserID, m.maxSessions-1, RevokeEvicted, now); err != nil {
			return nil, err
		}
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return nil, err
	}
	if err := m.store.PutRefresh(ctx, rec); err != nil {
		return nil, err
	}
	return &IssueResult{Session: sess, Refresh: raw}, nil
}

func (m *DefaultManager) Rotate(ctx context.Context, rawRefresh string, now time.Time) (*RotateResult, error) {
	ms, ok := m.store.(*MemoryStore)
	if !ok {
		return nil, ErrRefreshUnknown
	}
	h := hashToken(rawRefresh)

	ms.Lock()
	defer ms.Unlock()

	rec, ok := ms.refresh[h]
	if !ok {
		return nil, ErrRefreshUnknown
	}
	sid, ok := ms.families[rec.FamilyID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	sess := ms.sessions[sid]
	// A token spent by normal rotation and presented again is always a
	// replay/theft, even if its family has since been revoked for another
	// reason: the two failure causes must stay distinguishable.
	if rec.Rotated && !rec.Invalidated {
		_ = ms.revokeFamilyLocked(rec.FamilyID, RevokeReuse, now)
		return nil, ErrRefreshReused
	}
	// Idle/absolute timeouts are distinct external outcomes. Checked before
	// the revoked marker so a session that expired is reported as expired.
	if !sess.Revoked {
		if !now.Before(sess.AbsoluteDeadline) {
			_ = ms.revokeFamilyLocked(rec.FamilyID, RevokeAbsolute, now)
			return nil, ErrSessionExpired
		}
		if !now.Before(sess.IdleDeadline) {
			_ = ms.revokeFamilyLocked(rec.FamilyID, RevokeIdle, now)
			return nil, ErrSessionIdle
		}
	}
	if sess.Revoked {
		switch sess.RevokeReason {
		case RevokeIdle:
			return nil, ErrSessionIdle
		case RevokeAbsolute:
			return nil, ErrSessionExpired
		}
		return nil, ErrSessionRevoked
	}
	// A current token invalidated out-of-band (logout/admin) with the
	// session otherwise alive is treated as revoked, not reuse.
	if rec.Invalidated {
		return nil, ErrSessionRevoked
	}

	// Atomic rotation: old token dead, new token live, in one critical
	// section. There is no observable intermediate state.
	rec.Rotated = true
	rec.RotatedAt = now
	// Rotation pushes only the idle window; the absolute cap never moves.
	sess.IdleDeadline = now.Add(m.idleTTL)
	if sess.IdleDeadline.After(sess.AbsoluteDeadline) {
		sess.IdleDeadline = sess.AbsoluteDeadline
	}
	sess.LastActiveAt = now
	newRaw, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	newRec := &RefreshRecord{
		TokenHash:    hashToken(newRaw),
		SessionID:    sess.ID,
		FamilyID:     sess.FamilyID,
		CreatedAt:    now,
		IdleDeadline: sess.IdleDeadline,
	}
	ms.refresh[newRec.TokenHash] = newRec
	out := *sess
	return &RotateResult{Session: &out, NewRefresh: newRaw, OldRecord: rec}, nil
}

func (m *DefaultManager) Revoke(ctx context.Context, sessionID string, reason RevokeReason, now time.Time) error {
	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	return m.store.RevokeFamily(ctx, sess.FamilyID, reason, now)
}

// RevokeOne revokes exactly one session after verifying ownership.
// Already-dead sessions report their terminal cause; they are never
// silently treated as a fresh success.
func (m *DefaultManager) RevokeOne(ctx context.Context, actorUserID, sessionID string, reason RevokeReason, now time.Time) error {
	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}
	if sess.UserID != actorUserID {
		return ErrNotOwner
	}
	if sess.Revoked {
		switch sess.RevokeReason {
		case RevokeIdle:
			return ErrSessionIdle
		case RevokeAbsolute:
			return ErrSessionExpired
		}
		return ErrSessionRevoked
	}
	if !now.Before(sess.AbsoluteDeadline) {
		return ErrSessionExpired
	}
	if !now.Before(sess.IdleDeadline) {
		return ErrSessionIdle
	}
	return m.store.RevokeSession(ctx, sessionID, reason, now)
}

func (m *DefaultManager) ListActive(ctx context.Context, userID string, now time.Time) ([]*Session, error) {
	all, err := m.store.ListUserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*Session, 0, len(all))
	for _, s := range all {
		if s.Active(now) {
			cp := *s
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *DefaultManager) Validate(ctx context.Context, sessionID string, now time.Time) (*Session, error) {
	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.Revoked {
		switch sess.RevokeReason {
		case RevokeIdle:
			return nil, ErrSessionIdle
		case RevokeAbsolute:
			return nil, ErrSessionExpired
		case RevokeReuse:
			// Validate names the family-kill trigger so callers can tell
			// reuse-driven revocation apart from logout/eviction.
			return nil, ErrRefreshReused
		}
		return nil, ErrSessionRevoked
	}
	if !sess.Active(now) {
		if err := sess.ExpiryReason(now); err != nil {
			return nil, err
		}
		return nil, ErrSessionExpired
	}
	return sess, nil
}

func (m *DefaultManager) Touch(ctx context.Context, sessionID string, now time.Time) error {
	ms, ok := m.store.(*MemoryStore)
	if !ok {
		return nil
	}
	ms.Lock()
	defer ms.Unlock()
	sess, ok := ms.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if !sess.Active(now) {
		return nil
	}
	sess.LastActiveAt = now
	return nil
}
