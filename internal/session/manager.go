package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// DefaultManager coordinates a Store with atomic rotation semantics.
type DefaultManager struct {
	store Store
	ttl   time.Duration
}

// NewManager constructs a DefaultManager.
func NewManager(store Store, sessionTTL time.Duration) *DefaultManager {
	return &DefaultManager{store: store, ttl: sessionTTL}
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

func (m *DefaultManager) Issue(ctx context.Context, userID string, ttl time.Duration, now time.Time) (*Session, string, error) {
	if ttl <= 0 {
		ttl = m.ttl
	}
	sid, err := randomToken(16)
	if err != nil {
		return nil, "", err
	}
	fam, err := randomToken(16)
	if err != nil {
		return nil, "", err
	}
	raw, err := randomToken(32)
	if err != nil {
		return nil, "", err
	}
	sess := &Session{
		ID:        sid,
		FamilyID:  fam,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	rec := &RefreshRecord{
		TokenHash: hashToken(raw),
		SessionID: sid,
		FamilyID:  fam,
		CreatedAt: now,
		ExpiresAt: sess.ExpiresAt,
	}
	// Compound mutation: session + first refresh token appear together.
	if ms, isMem := m.store.(*MemoryStore); isMem {
		ms.mu.Lock()
		defer ms.mu.Unlock()
		cp := *sess
		ms.sessions[sess.ID] = &cp
		ms.families[sess.FamilyID] = sess.ID
		cpr := *rec
		ms.refresh[rec.TokenHash] = &cpr
		return sess, raw, nil
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return nil, "", err
	}
	if err := m.store.PutRefresh(ctx, rec); err != nil {
		return nil, "", err
	}
	return sess, raw, nil
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
	if sess.Revoked {
		return nil, ErrSessionRevoked
	}
	if !sess.Active(now) {
		_ = ms.revokeFamilyLocked(rec.FamilyID, RevokeExpired, now)
		return nil, ErrSessionExpired
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
	newRaw, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	newRec := &RefreshRecord{
		TokenHash: hashToken(newRaw),
		SessionID: sess.ID,
		FamilyID:  sess.FamilyID,
		CreatedAt: now,
		ExpiresAt: sess.ExpiresAt,
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

func (m *DefaultManager) Validate(ctx context.Context, sessionID string, now time.Time) (*Session, error) {
	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.Revoked {
		return nil, ErrSessionRevoked
	}
	if !sess.Active(now) {
		return nil, ErrSessionExpired
	}
	return sess, nil
}
