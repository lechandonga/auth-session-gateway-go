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
	maxPerUser  int
}

// Options configures a DefaultManager.
type Options struct {
	IdleTTL     time.Duration
	AbsoluteTTL time.Duration
	MaxPerUser  int
}

// NewManager constructs a DefaultManager from Options.
func NewManager(store Store, opts Options) *DefaultManager {
	if opts.IdleTTL <= 0 {
		opts.IdleTTL = 30 * time.Minute
	}
	if opts.AbsoluteTTL <= 0 {
		opts.AbsoluteTTL = 24 * time.Hour
	}
	return &DefaultManager{
		store:       store,
		idleTTL:     opts.IdleTTL,
		absoluteTTL: opts.AbsoluteTTL,
		maxPerUser:  opts.MaxPerUser,
	}
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

func (m *DefaultManager) Issue(ctx context.Context, p IssueParams, now time.Time) (*Session, string, []*Session, error) {
	sid, err := randomToken(16)
	if err != nil {
		return nil, "", nil, err
	}
	fam, err := randomToken(16)
	if err != nil {
		return nil, "", nil, err
	}
	raw, err := randomToken(32)
	if err != nil {
		return nil, "", nil, err
	}
	sess := &Session{
		ID:                sid,
		FamilyID:          fam,
		UserID:            p.UserID,
		CreatedAt:         now,
		LastActiveAt:      now,
		IdleExpiresAt:     now.Add(m.idleTTL),
		AbsoluteExpiresAt: now.Add(m.absoluteTTL),
		Peer:              p.Peer,
		UserAgent:         p.UserAgent,
	}
	rec := &RefreshRecord{
		TokenHash:         hashToken(raw),
		SessionID:         sid,
		FamilyID:          fam,
		CreatedAt:         now,
		AbsoluteExpiresAt: sess.AbsoluteExpiresAt,
	}
	if ms, isMem := m.store.(*MemoryStore); isMem {
		ms.mu.Lock()
		defer ms.mu.Unlock()
		evicted := m.evictIfNeededLocked(ms, p.UserID, now)
		cp := *sess
		ms.sessions[sess.ID] = &cp
		ms.families[sess.FamilyID] = sess.ID
		cpr := *rec
		ms.refresh[rec.TokenHash] = &cpr
		return sess, raw, evicted, nil
	}
	if err := m.store.CreateSession(ctx, sess); err != nil {
		return nil, "", nil, err
	}
	if err := m.store.PutRefresh(ctx, rec); err != nil {
		return nil, "", nil, err
	}
	return sess, raw, nil, nil
}

// evictIfNeededLocked enforces the per-user active-session cap using the
// deterministic "least recently active first" rule. Ties are broken by
// creation time, then by ID, so the result never depends on map iteration.
// Caller must hold ms.mu.
func (m *DefaultManager) evictIfNeededLocked(ms *MemoryStore, userID string, now time.Time) []*Session {
	if m.maxPerUser <= 0 {
		return nil
	}
	var active []*Session
	for _, sess := range ms.sessions {
		if sess.UserID == userID && sess.Active(now) {
			active = append(active, sess)
		}
	}
	if len(active) < m.maxPerUser {
		return nil
	}
	sort.Slice(active, func(i, j int) bool {
		a, b := active[i], active[j]
		if !a.LastActiveAt.Equal(b.LastActiveAt) {
			return a.LastActiveAt.Before(b.LastActiveAt)
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	})
	need := len(active) - m.maxPerUser + 1
	evicted := make([]*Session, 0, need)
	for i := 0; i < need; i++ {
		victim := active[i]
		_ = ms.revokeFamilyLocked(victim.FamilyID, RevokeEvicted, now)
		cp := *victim
		evicted = append(evicted, &cp)
	}
	return evicted
}

func expiryError(kind RevokeReason) error {
	if kind == RevokeAbsolute {
		return ErrSessionAbsolute
	}
	return ErrSessionIdle
}

// revokedError keeps explicit revocation distinct from the two expiry
// kinds: crossing an expiry auto-marks a session revoked, but later lookups
// must still report the real boundary that was crossed.
func revokedError(sess *Session) error {
	switch sess.RevokeReason {
	case RevokeIdle:
		return ErrSessionIdle
	case RevokeAbsolute:
		return ErrSessionAbsolute
	default:
		return ErrSessionRevoked
	}
}

func (m *DefaultManager) expireLocked(ms *MemoryStore, sess *Session, now time.Time) error {
	kind := sess.ExpiryKind(now)
	_ = ms.revokeFamilyLocked(sess.FamilyID, kind, now)
	return expiryError(kind)
}

func (m *DefaultManager) Rotate(ctx context.Context, rawRefresh string, now time.Time) (*RotateResult, error) {
	ms, ok := m.store.(*MemoryStore)
	if !ok {
		return nil, ErrRefreshUnknown
	}
	h := hashToken(rawRefresh)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	rec, ok := ms.refresh[h]
	if !ok {
		return nil, ErrRefreshUnknown
	}
	sid, ok := ms.families[rec.FamilyID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	sess := ms.sessions[sid]
	// Reuse is checked first: a spent token replayed is always a theft
	// signal, never silently downgraded to revoked/expired.
	if rec.Rotated && !rec.Invalidated {
		// Every replay is diagnosed as reuse; the family-wide mutation
		// itself happens at most once (it is already a no-op after the
		// first replay). Audit idempotency is keyed on the family ID.
		if !sess.Revoked || sess.RevokeReason != RevokeReuse {
			_ = ms.revokeFamilyLocked(rec.FamilyID, RevokeReuse, now)
		}
		return nil, &ReuseDetailed{FamilyID: rec.FamilyID}
	}
	if sess.Revoked {
		return nil, revokedError(sess)
	}
	if kind := sess.ExpiryKind(now); kind != RevokeNone {
		return nil, m.expireLocked(ms, sess, now)
	}
	// A current token invalidated out-of-band (logout/admin/eviction) is
	// revoked, not reuse.
	if rec.Invalidated {
		return nil, ErrSessionRevoked
	}

	rec.Rotated = true
	rec.RotatedAt = now
	newRaw, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	newRec := &RefreshRecord{
		TokenHash:         hashToken(newRaw),
		SessionID:         sess.ID,
		FamilyID:          sess.FamilyID,
		CreatedAt:         now,
		AbsoluteExpiresAt: sess.AbsoluteExpiresAt,
	}
	ms.refresh[newRec.TokenHash] = newRec
	// Rotation slides only the idle window; the absolute cap never moves.
	sess.IdleExpiresAt = now.Add(m.idleTTL)
	if sess.IdleExpiresAt.After(sess.AbsoluteExpiresAt) {
		sess.IdleExpiresAt = sess.AbsoluteExpiresAt
	}
	sess.LastActiveAt = now
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

// RevokeForUser performs a targeted, idempotent revocation scoped to one
// session: not found, ownership violation, already-dead and fresh revoke
// stay distinguishable.
func (m *DefaultManager) RevokeForUser(ctx context.Context, requesterID, sessionID string, now time.Time) (*RevokeOutcome, error) {
	ms, ok := m.store.(*MemoryStore)
	if !ok {
		sess, err := m.store.GetSession(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if sess.UserID != requesterID {
			return nil, ErrForbidden
		}
		out := &RevokeOutcome{Session: sess}
		if !sess.Active(now) {
			out.AlreadyRevoked = true
			return out, nil
		}
		if err := m.store.RevokeFamily(ctx, sess.FamilyID, RevokeTarget, now); err != nil {
			return nil, err
		}
		out.Revoked = true
		out.Session, _ = m.store.GetSession(ctx, sessionID)
		return out, nil
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	sess, ok := ms.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if sess.UserID != requesterID {
		return nil, ErrForbidden
	}
	out := &RevokeOutcome{Session: sess}
	if !sess.Active(now) {
		out.AlreadyRevoked = true
		return out, nil
	}
	if err := ms.revokeFamilyLocked(sess.FamilyID, RevokeTarget, now); err != nil {
		return nil, err
	}
	out.Revoked = true
	cp := *sess
	out.Session = &cp
	return out, nil
}

func (m *DefaultManager) Validate(ctx context.Context, sessionID string, now time.Time) (*Session, error) {
	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.Revoked {
		return nil, revokedError(sess)
	}
	if kind := sess.ExpiryKind(now); kind != RevokeNone {
		return nil, expiryError(kind)
	}
	return sess, nil
}

// Touch marks activity under the store lock: validate + slide happen
// atomically, so a concurrent revocation can never be followed by a touch
// resurrecting the session.
func (m *DefaultManager) Touch(ctx context.Context, sessionID string, now time.Time) (*Session, error) {
	ms, ok := m.store.(*MemoryStore)
	if !ok {
		return m.Validate(ctx, sessionID, now)
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	sess, ok := ms.sessions[sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	if sess.Revoked {
		return nil, revokedError(sess)
	}
	if kind := sess.ExpiryKind(now); kind != RevokeNone {
		return nil, m.expireLocked(ms, sess, now)
	}
	sess.LastActiveAt = now
	until := now.Add(m.idleTTL)
	if until.After(sess.AbsoluteExpiresAt) {
		until = sess.AbsoluteExpiresAt
	}
	sess.IdleExpiresAt = until
	out := *sess
	return &out, nil
}

// List returns the user's active sessions, newest activity first.
func (m *DefaultManager) List(ctx context.Context, userID string, now time.Time) ([]*Session, error) {
	all, err := m.store.ListSessionsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]*Session, 0, len(all))
	for _, sess := range all {
		if sess.Active(now) {
			cp := *sess
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastActiveAt.Equal(out[j].LastActiveAt) {
			return out[i].LastActiveAt.After(out[j].LastActiveAt)
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}
