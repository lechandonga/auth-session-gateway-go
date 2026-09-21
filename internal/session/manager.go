// Package session manages login sessions, opaque refresh tokens and their
// rotation. Every state transition is performed under one manager mutex so
// concurrent rotate/revoke can never produce a half-updated state or let a
// dead token pass. Replay of an already-rotated token is detected as reuse
// and revokes the whole token family (and its session).
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/model"
	"github.com/lechandonga/auth-session-gateway-go/internal/security"
	"github.com/lechandonga/auth-session-gateway-go/internal/store"
)

type Config struct {
	AccessTokenTTL time.Duration
	RefreshTTL     time.Duration
	IdleTimeout    time.Duration
	AbsoluteTTL    time.Duration
}

func DefaultConfig() Config {
	return Config{
		AccessTokenTTL: 15 * time.Minute,
		RefreshTTL:     7 * 24 * time.Hour,
		IdleTimeout:    30 * time.Minute,
		AbsoluteTTL:    12 * time.Hour,
	}
}

type Manager struct {
	mu       sync.Mutex
	sessions *store.SessionStore
	refresh  *store.RefreshStore
	tokens   *security.TokenService
	aud      *audit.Logger
	cfg      Config
	now      func() time.Time
}

func NewManager(s *store.SessionStore, r *store.RefreshStore, t *security.TokenService, aud *audit.Logger, cfg Config) *Manager {
	return &Manager{sessions: s, refresh: r, tokens: t, aud: aud, cfg: cfg, now: time.Now}
}

// IssueResult is returned once at login. The raw refresh token and CSRF token
// are never persisted in plaintext (only a SHA-256 hash of the refresh token
// is stored).
type IssueResult struct {
	Session      *model.Session
	RefreshToken string
	AccessToken  string
	CSRFToken    string
}

func newID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("session: cannot read randomness: " + err.Error())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Issue creates a session, its first refresh token and an access token.
func (m *Manager) Issue(user *model.User, csrf *security.CSRFProtector) (*IssueResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.issueLocked(user, csrf)
}

func (m *Manager) issueLocked(user *model.User, csrf *security.CSRFProtector) (*IssueResult, error) {
	now := m.now()
	familyID := newID("fam")
	sess := &model.Session{
		ID:          newID("sess"),
		UserID:      user.ID,
		FamilyID:    familyID,
		CreatedAt:   now,
		LastRefresh: now,
		AbsoluteExp: now.Add(m.cfg.AbsoluteTTL),
		IdleExp:     now.Add(m.cfg.IdleTimeout),
	}
	if err := m.sessions.Put(sess); err != nil {
		return nil, err
	}

	rawRefresh := newID("rt")
	rec := &model.RefreshTokenRecord{
		Hash:      hashToken(rawRefresh),
		SessionID: sess.ID,
		FamilyID:  familyID,
		UserID:    user.ID,
		IssuedAt:  now,
		ExpiresAt: now.Add(m.cfg.RefreshTTL),
	}
	if err := m.refresh.Put(rec); err != nil {
		return nil, err
	}

	access, err := m.signAccessLocked(user, sess, now)
	if err != nil {
		return nil, err
	}
	csrfTok := ""
	if csrf != nil {
		csrfTok = csrf.Issue(sess.ID)
	}
	return &IssueResult{
		Session:      sess,
		RefreshToken: rawRefresh,
		AccessToken:  access,
		CSRFToken:    csrfTok,
	}, nil
}

// defaultScopesForRoles maps coarse roles to the scopes attached at login.
// Scopes are the least-privilege narrowing layer: roles alone never imply
// write access. The mapping is explicit so the granted set is auditable.
func defaultScopesForRoles(roles []string) []string {
	scopes := []string{}
	have := map[string]bool{}
	add := func(s string) {
		if !have[s] {
			have[s] = true
			scopes = append(scopes, s)
		}
	}
	for _, r := range roles {
		switch r {
		case "member":
			add("docs:read")
		case "editor":
			add("docs:read")
			add("docs:write")
		case "admin":
			add("docs:read")
			add("docs:write")
			add("admin")
		}
	}
	return scopes
}

func (m *Manager) signAccessLocked(user *model.User, sess *model.Session, now time.Time) (string, error) {
	scopes := defaultScopesForRoles(user.Roles)
	claims := model.AccessClaims{
		JTI:       newID("jti"),
		Sub:       user.ID,
		SessionID: sess.ID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(m.cfg.AccessTokenTTL).Unix(),
		Roles:     append([]string(nil), user.Roles...),
		Scopes:    scopes,
		Attrs:     cloneAttrs(user.Attributes),
	}
	return m.tokens.Sign(claims)
}

func cloneAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// RefreshVerdict distinguishes rotation outcomes.
type RefreshVerdict string

const (
	RefreshOK           RefreshVerdict = "ok"
	RefreshNotFound     RefreshVerdict = "not_found"
	RefreshExpired      RefreshVerdict = "expired"
	RefreshRotatedReuse RefreshVerdict = "reuse_detected"
	RefreshRevoked      RefreshVerdict = "revoked"
	RefreshSessionDead  RefreshVerdict = "session_dead"
)

// RefreshResult describes one rotate call. On reuse the whole family and its
// sessions are revoked and RevokedFamily is populated.
type RefreshResult struct {
	Verdict       RefreshVerdict
	NewRefresh    string
	NewAccess     string
	RevokedFamily string
	Reason        string
}

// Rotate atomically consumes rawRefresh and issues replacements. The full
// read-check-rotate-issue sequence runs under m.mu, so two concurrent
// calls with the same token have a deterministic outcome: exactly one wins
// (RefreshOK); the loser observes an already-rotated token, which is treated
// as token reuse and revokes the family. The win/lose decision cannot depend
// on scheduling.
func (m *Manager) Rotate(rawRefresh string, user *model.User) RefreshResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()

	rec, err := m.refresh.Get(hashToken(rawRefresh))
	if err != nil {
		// Do not reveal whether the token existed.
		return RefreshResult{Verdict: RefreshNotFound, Reason: "unknown refresh token"}
	}

	// Revoked family token: refuse regardless of rotated flag.
	if rec.Revoked {
		return RefreshResult{Verdict: RefreshRevoked, Reason: "token family revoked", RevokedFamily: rec.FamilyID}
	}

	// Reuse: the presented token was already rotated once. This is the
	// classic refresh-token theft signal. Revoke family + sessions.
	if rec.Rotated {
		return m.handleReuseLocked(rec, now)
	}

	// Liveness order (after reuse, which always wins):
	// session revoked/missing -> session lifetime -> token own expiry.
	// Session state is a property of the whole family, so a dead session
	// outranks the individual token's expiry and triggers family cleanup.
	sess, err := m.sessions.Get(rec.SessionID)
	if err != nil || sess.Revoked {
		return RefreshResult{Verdict: RefreshSessionDead, Reason: "session revoked or missing"}
	}
	if now.After(sess.AbsoluteExp) || now.After(sess.IdleExp) {
		// Dead session -> revoke family defensively.
		m.revokeFamilyLocked(sess.FamilyID, now, "session lifetime exceeded")
		return RefreshResult{Verdict: RefreshSessionDead, Reason: "session lifetime exceeded"}
	}
	if now.After(rec.ExpiresAt) {
		return RefreshResult{Verdict: RefreshExpired, Reason: "refresh token expired"}
	}

	// CAS on the token: exactly one concurrent caller wins.
	if err := m.refresh.MarkRotated(rec.Hash, now); err != nil {
		if errors.Is(err, model.ErrTokenRotated) {
			fresh, _ := m.refresh.Get(rec.Hash)
			return m.handleReuseLocked(fresh, now)
		}
		return RefreshResult{Verdict: RefreshRevoked, Reason: err.Error()}
	}

	// Issue the successor in the SAME family.
	newRaw := newID("rt")
	newRec := &model.RefreshTokenRecord{
		Hash:       hashToken(newRaw),
		SessionID:  sess.ID,
		FamilyID:   sess.FamilyID,
		UserID:     rec.UserID,
		IssuedAt:   now,
		ExpiresAt:  minTime(rec.ExpiresAt, now.Add(m.cfg.RefreshTTL)),
		ParentHash: rec.Hash,
	}
	if err := m.refresh.Put(newRec); err != nil {
		// Fatal bookkeeping error: the old token is already rotated. Revoke
		// the family rather than leave a half-rotated chain.
		m.revokeFamilyLocked(sess.FamilyID, now, "rotation bookkeeping failure")
		return RefreshResult{Verdict: RefreshRevoked, Reason: "rotation failure; family revoked"}
	}

	// Slide idle window; absolute expiry is a hard ceiling.
	newIdle := minTime(sess.AbsoluteExp, now.Add(m.cfg.IdleTimeout))
	_ = m.sessions.Touch(sess.ID, now, newIdle, sess.AbsoluteExp)

	u := user
	if u == nil || u.ID != rec.UserID {
		u = &model.User{ID: rec.UserID}
	}
	access, err := m.signAccessLocked(u, sess, now)
	if err != nil {
		m.revokeFamilyLocked(sess.FamilyID, now, "access token signing failure")
		return RefreshResult{Verdict: RefreshRevoked, Reason: "signing failure; family revoked"}
	}

	m.aud.Record(model.AuditEvent{
		Type: model.EventTokenRotated, Subject: rec.UserID, SessionID: sess.ID,
		Success: true,
		Details: map[string]string{
			"family_id":   sess.FamilyID,
			"parent_hash": shortHash(rec.Hash),
			"new_hash":    shortHash(newRec.Hash),
		},
	})
	return RefreshResult{
		Verdict:    RefreshOK,
		NewRefresh: newRaw,
		NewAccess:  access,
	}
}

// handleReuseLocked flags the token once (first observer wins) and revokes
// the whole family and all of its sessions. Audit uses a DedupKey per family
// so concurrent reuse reports cannot create duplicate revocation/lock events.
func (m *Manager) handleReuseLocked(rec *model.RefreshTokenRecord, now time.Time) RefreshResult {
	first := m.refresh.MarkReuse(rec.Hash)
	m.revokeFamilyLocked(rec.FamilyID, now, "refresh token reuse")
	m.aud.Record(model.AuditEvent{
		Type:      model.EventRefreshReuse,
		Subject:   rec.UserID,
		SessionID: rec.SessionID,
		Success:   false,
		Reason:    "rotated refresh token presented again",
		Details: map[string]string{
			"family_id":      rec.FamilyID,
			"token_hash":     shortHash(rec.Hash),
			"first_observer": boolStr(first),
		},
		DedupKey: "reuse:" + rec.FamilyID + ":" + rec.Hash,
	})
	return RefreshResult{
		Verdict:       RefreshRotatedReuse,
		Reason:        "refresh token reuse; family revoked",
		RevokedFamily: rec.FamilyID,
	}
}

// revokeFamilyLocked revokes refresh records and sessions together. Audit
// events are deduplicated per (family, reason) so repeated/replayed calls do
// not double-count.
func (m *Manager) revokeFamilyLocked(familyID string, now time.Time, reason string) {
	m.refresh.RevokeFamily(familyID)
	ids := m.sessions.RevokeFamily(familyID, now, reason)
	for _, id := range ids {
		m.aud.Record(model.AuditEvent{
			Type:      model.EventSessionRevoke,
			SessionID: id,
			Success:   true,
			Reason:    reason,
			Details:   map[string]string{"family_id": familyID, "scope": "family"},
			DedupKey:  "revoke:" + id + ":" + reason,
		})
	}
}

// Revoke revokes one session and its whole token family. Idempotent: a second
// revoke changes nothing and emits no new event (store reports no change).
func (m *Manager) Revoke(sessionID, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, err := m.sessions.Get(sessionID)
	if err != nil {
		return err
	}
	changed, err := m.sessions.Revoke(sessionID, m.now(), reason)
	if err != nil {
		return err
	}
	m.refresh.RevokeFamily(sess.FamilyID)
	if changed {
		m.aud.Record(model.AuditEvent{
			Type: model.EventSessionRevoke, Subject: sess.UserID, SessionID: sessionID,
			Success: true, Reason: reason,
			Details:  map[string]string{"family_id": sess.FamilyID, "scope": "session"},
			DedupKey: "revoke:" + sessionID + ":" + reason,
		})
	}
	return nil
}

// ValidateAccess verifies the signed access token and then cross-checks live
// session state: revoked sessions, idle timeout and absolute timeout all fail
// closed even while the bearer token itself is still unexpired.
func (m *Manager) ValidateAccess(raw string) (*model.AccessClaims, *model.Session, model.TokenFailReason) {
	// Validation is read-only on the manager but must observe a state
	// consistent with any concurrent rotate/revoke, so take the same mutex.
	m.mu.Lock()
	defer m.mu.Unlock()
	claims, reason, err := m.tokens.Verify(raw)
	if err != nil {
		return nil, nil, reason
	}
	sess, err := m.sessions.Get(claims.SessionID)
	now := m.now()
	if err != nil || sess.Revoked {
		return nil, nil, model.TokenSessionRevoked
	}
	if now.After(sess.AbsoluteExp) || now.After(sess.IdleExp) {
		return nil, nil, model.TokenSessionRevoked
	}
	return claims, sess, model.TokenOK
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
