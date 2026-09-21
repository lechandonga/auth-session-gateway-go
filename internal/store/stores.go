// Package store provides in-memory, concurrency-safe storage for users,
// login-failure/lockout counters, sessions and refresh-token records.
package store

import (
	"sync"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

// UserStore is an in-memory user directory.
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*model.User // keyed by username
	byID  map[string]*model.User
}

func NewUserStore() *UserStore {
	return &UserStore{users: map[string]*model.User{}, byID: map[string]*model.User{}}
}

// Create inserts a user. Callers must not mutate u afterwards.
func (s *UserStore) Create(u *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[u.Username]; ok {
		return model.ErrUserExists
	}
	cp := *u
	s.users[u.Username] = &cp
	s.byID[u.ID] = &cp
	return nil
}

func (s *UserStore) Get(username string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *UserStore) GetByID(id string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *UserStore) List() []*model.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.User, 0, len(s.users))
	for _, u := range s.users {
		cp := *u
		out = append(out, &cp)
	}
	return out
}

// LockoutState tracks failed attempts and lock state per subject (username).
type LockoutState struct {
	Failures    int
	FirstFail   time.Time
	LockedUntil time.Time
	Locked      bool
}

// LockoutStore counts failures and applies lockout policy.
type LockoutStore struct {
	mu     sync.Mutex
	states map[string]*LockoutState
}

func NewLockoutStore() *LockoutStore { return &LockoutStore{states: map[string]*LockoutState{}} }

// IsLocked reports whether subject is locked at instant now. An expired lock
// is treated as unlocked (but the stored row is left untouched; it is
// reconciled on the next RegisterFailure).
func (s *LockoutStore) IsLocked(subject string, now time.Time) (bool, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[subject]
	if !ok || !st.Locked {
		return false, time.Time{}
	}
	if !now.Before(st.LockedUntil) {
		return false, st.LockedUntil
	}
	return true, st.LockedUntil
}

// RegisterFailure atomically records a failed attempt. Failures older than
// window relative to now are discarded (sliding window). When the running
// count reaches threshold the subject is locked on THIS call exactly once;
// later failures while locked return lockedNow=false so locking is never
// double-counted.
func (s *LockoutStore) RegisterFailure(subject string, now time.Time, threshold int, window, lockDur time.Duration) (failures int, lockedNow bool, until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[subject]
	if st == nil {
		st = &LockoutState{}
		s.states[subject] = st
	}
	// Expired lock: start a fresh counting window.
	if st.Locked && !now.Before(st.LockedUntil) {
		*st = LockoutState{}
	}
	if st.Locked {
		return st.Failures, false, st.LockedUntil
	}
	// Drop stale failures outside the sliding window.
	if st.Failures > 0 && now.Sub(st.FirstFail) > window {
		*st = LockoutState{}
	}
	if st.Failures == 0 {
		st.FirstFail = now
	}
	st.Failures++
	if threshold > 0 && st.Failures >= threshold {
		st.Locked = true
		st.LockedUntil = now.Add(lockDur)
		return st.Failures, true, st.LockedUntil
	}
	return st.Failures, false, time.Time{}
}

// Reset clears failure/lock state (on successful login).
func (s *LockoutStore) Reset(subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, subject)
}

// State returns a copy of the state for diagnostics/tests.
func (s *LockoutStore) State(subject string) (LockoutState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[subject]
	if !ok {
		return LockoutState{}, false
	}
	return *st, true
}

// SessionStore stores sessions.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*model.Session
}

func NewSessionStore() *SessionStore { return &SessionStore{sessions: map[string]*model.Session{}} }

func (s *SessionStore) Put(sess *model.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.sessions[sess.ID] = &cp
	return nil
}

func (s *SessionStore) Get(id string) (*model.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *sess
	return &cp, nil
}

// Revoke marks one session revoked. It is idempotent: revoking an already
// revoked session reports false (i.e. this call did not change state), so
// duplicate revoke events can be deduplicated upstream.
func (s *SessionStore) Revoke(id string, now time.Time, reason string) (changed bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false, model.ErrNotFound
	}
	if sess.Revoked {
		return false, nil
	}
	sess.Revoked = true
	sess.RevokedAt = now
	sess.RevokeReason = reason
	return true, nil
}

// RevokeFamily revokes every session sharing familyID. Concurrent/duplicate
// calls return only the IDs newly revoked by that call, so a session revoked
// concurrently by a single-session revoke is never reported twice.
func (s *SessionStore) RevokeFamily(familyID string, now time.Time, reason string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for _, sess := range s.sessions {
		if sess.FamilyID == familyID && !sess.Revoked {
			sess.Revoked = true
			sess.RevokedAt = now
			sess.RevokeReason = reason
			ids = append(ids, sess.ID)
		}
	}
	return ids
}

func (s *SessionStore) Touch(id string, now time.Time, idleExp, absExp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return model.ErrNotFound
	}
	sess.LastRefresh = now
	sess.IdleExp = idleExp
	sess.AbsoluteExp = absExp
	return nil
}

// RefreshStore stores hashed refresh-token records.
type RefreshStore struct {
	mu     sync.RWMutex
	byHash map[string]*model.RefreshTokenRecord
}

func NewRefreshStore() *RefreshStore {
	return &RefreshStore{byHash: map[string]*model.RefreshTokenRecord{}}
}

func (s *RefreshStore) Put(rec *model.RefreshTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byHash[rec.Hash]; ok {
		return model.ErrUserExists
	}
	cp := *rec
	s.byHash[rec.Hash] = &cp
	return nil
}

func (s *RefreshStore) Get(hash string) (*model.RefreshTokenRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byHash[hash]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *rec
	return &cp, nil
}

// MarkRotated CAS-flips a token to rotated. Exactly one concurrent caller
// can win (nil return); every later caller receives ErrTokenRotated.
func (s *RefreshStore) MarkRotated(hash string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byHash[hash]
	if !ok {
		return model.ErrNotFound
	}
	if rec.Rotated || rec.Revoked {
		return model.ErrTokenRotated
	}
	rec.Rotated = true
	rec.RotatedAt = now
	return nil
}

// MarkReuse flags a rotated token as having been replayed. Returns true only
// for the first observer so the family-revocation side effect fires once.
func (s *RefreshStore) MarkReuse(hash string) (first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byHash[hash]
	if !ok {
		return false
	}
	if rec.ReuseSeen {
		return false
	}
	rec.ReuseSeen = true
	return true
}

// RevokeFamily marks every token of a family revoked.
func (s *RefreshStore) RevokeFamily(familyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.byHash {
		if rec.FamilyID == familyID {
			rec.Revoked = true
		}
	}
}
