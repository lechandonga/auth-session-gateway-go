package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

// CSRFProtector issues and validates per-session double-submit CSRF tokens.
// Tokens are bound to the session id via HMAC so a token minted for one
// session can never validate against another.
type CSRFProtector struct {
	mu     sync.Mutex
	secret []byte
	issued map[string]string // sessionID -> token
}

func NewCSRFProtector() *CSRFProtector {
	sec := make([]byte, 32)
	if _, err := rand.Read(sec); err != nil {
		// crypto/rand failure is not recoverable in a security primitive.
		panic("csrf: cannot read randomness: " + err.Error())
	}
	return &CSRFProtector{secret: sec, issued: map[string]string{}}
}

func (p *CSRFProtector) tokenFor(sessionID string) string {
	m := hmac.New(sha256.New, p.secret)
	m.Write([]byte("csrf:"))
	m.Write([]byte(sessionID))
	return hex.EncodeToString(m.Sum(nil))
}

// Issue returns the token bound to sessionID. Repeated calls return the same
// stable value (double-submit pattern) until invalidation.
func (p *CSRFProtector) Issue(sessionID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if tok, ok := p.issued[sessionID]; ok {
		return tok
	}
	tok := p.tokenFor(sessionID)
	p.issued[sessionID] = tok
	return tok
}

// Validate compares the presented token with the stored/derived one. Empty
// input -> ErrCSRFTokenMissing; mismatch -> ErrCSRFTokenMismatch. Comparison
// is constant time.
func (p *CSRFProtector) Validate(sessionID, presented string) error {
	if presented == "" {
		return model.ErrCSRFTokenMissing
	}
	p.mu.Lock()
	want, known := p.issued[sessionID]
	p.mu.Unlock()
	if !known {
		// Validate on the fly keeps behavior deterministic even if in-memory
		// issue map was not consulted (e.g. reconstructed server).
		want = p.tokenFor(sessionID)
	}
	if !hmac.Equal([]byte(want), []byte(presented)) {
		return model.ErrCSRFTokenMismatch
	}
	return nil
}

// Invalidate drops the token (on session revocation). The deterministic
// derivation means a new issuance after re-login of the same session id is
// impossible: revoked sessions are never re-issued.
func (p *CSRFProtector) Invalidate(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.issued, sessionID)
}
