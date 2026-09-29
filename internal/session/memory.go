package session

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is a concurrency-safe in-memory Store. All multi-record
// mutations performed by the manager happen under the same mutex that this
// store exposes via lock/unlock, which keeps rotation and revocation atomic.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	families map[string]string // familyID -> sessionID
	refresh  map[string]*RefreshRecord
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: map[string]*Session{},
		families: map[string]string{},
		refresh:  map[string]*RefreshRecord{},
	}
}

// Lock/Unlock expose the store-wide lock so the manager can make compound
// operations atomic without exposing internal maps.
func (s *MemoryStore) Lock()   { s.mu.Lock() }
func (s *MemoryStore) Unlock() { s.mu.Unlock() }

func cloneSession(sess *Session) *Session {
	cp := *sess
	return &cp
}

func (s *MemoryStore) CreateSession(ctx context.Context, sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = cloneSession(sess)
	s.families[sess.FamilyID] = sess.ID
	return nil
}

func (s *MemoryStore) GetSession(ctx context.Context, id string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return cloneSession(sess), nil
}

func (s *MemoryStore) GetSessionByFamily(ctx context.Context, familyID string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.families[familyID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return cloneSession(s.sessions[id]), nil
}

// ListSessionsByUser returns all of a user's sessions (any state).
func (s *MemoryStore) ListSessionsByUser(ctx context.Context, userID string) ([]*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Session
	for _, sess := range s.sessions {
		if sess.UserID == userID {
			out = append(out, cloneSession(sess))
		}
	}
	return out, nil
}

// AllSessions returns every stored session.
func (s *MemoryStore) AllSessions(ctx context.Context) ([]*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		out = append(out, cloneSession(sess))
	}
	return out, nil
}

// RevokeFamilyLocked revokes the session belonging to familyID; the caller
// must hold s.mu when composing a compound operation.
func (s *MemoryStore) revokeFamilyLocked(familyID string, reason RevokeReason, now time.Time) error {
	id, ok := s.families[familyID]
	if !ok {
		return ErrSessionNotFound
	}
	sess := s.sessions[id]
	sess.Revoked = true
	sess.RevokeReason = reason
	sess.RevokedAt = now
	// Only still-current refresh tokens are invalidated by a revocation;
	// records already spent by normal rotation keep their Rotated marker so
	// their later replay is still diagnosed as reuse.
	for _, r := range s.refresh {
		if r.FamilyID == familyID && !r.Rotated && !r.Invalidated {
			r.Invalidated = true
			r.RotatedAt = now
		}
	}
	return nil
}

func (s *MemoryStore) RevokeFamily(ctx context.Context, familyID string, reason RevokeReason, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeFamilyLocked(familyID, reason, now)
}

func (s *MemoryStore) RevokeSession(ctx context.Context, id string, reason RevokeReason, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return ErrSessionNotFound
	}
	sess.Revoked = true
	sess.RevokeReason = reason
	sess.RevokedAt = now
	for _, r := range s.refresh {
		if r.SessionID == id && !r.Rotated && !r.Invalidated {
			r.Invalidated = true
			r.RotatedAt = now
		}
	}
	return nil
}

func (s *MemoryStore) PutRefresh(ctx context.Context, r *RefreshRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *r
	s.refresh[r.TokenHash] = &cp
	return nil
}

func (s *MemoryStore) GetRefresh(ctx context.Context, tokenHash string) (*RefreshRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.refresh[tokenHash]
	if !ok {
		return nil, ErrRefreshUnknown
	}
	cp := *r
	return &cp, nil
}

// MarkRotatedLocked flags a token as rotated; caller must hold s.mu.
func (s *MemoryStore) MarkRotatedLocked(tokenHash string, now time.Time) {
	if r, ok := s.refresh[tokenHash]; ok {
		r.Rotated = true
		r.RotatedAt = now
	}
}
