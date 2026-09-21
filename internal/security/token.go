package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

// Wire format (ASCII, URL-safe):
//
//	v1.<base64url(claimsJSON)>.<base64url(HMAC-SHA256(ring key, "v1."+payload))>
//
// The kid used for signing travels inside the claims (SigningKID), which lets
// verification locate the historical key after rotation. No external JWT
// dependency is required.
const tokenVersion = "v1"

// TokenService signs and verifies compact signed tokens using a KeyRing.
type TokenService struct {
	ring *KeyRing
	now  func() time.Time
}

func NewTokenService(ring *KeyRing) *TokenService {
	return &TokenService{ring: ring, now: time.Now}
}

// WithClock overrides the verification clock (tests/deterministic replay).
func (t *TokenService) WithClock(now func() time.Time) *TokenService {
	t.now = now
	return t
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signMAC(secret []byte, signingInput string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(signingInput))
	return b64(m.Sum(nil))
}

// Sign serializes claims and signs them with the ring's current active key.
// The kid is stamped into the claim set; a missing active key yields
// model.ErrMissingKey and a retired current pointer yields model.ErrRetiredKey.
func (t *TokenService) Sign(c model.AccessClaims) (string, error) {
	k, err := t.ring.Current()
	if err != nil {
		if errors.Is(err, model.ErrMissingKey) {
			return "", model.ErrMissingKey
		}
		return "", err
	}
	if k.Status != KeyActive {
		return "", model.ErrRetiredKey
	}
	if c.IssuedAt == 0 {
		c.IssuedAt = t.now().Unix()
	}
	if c.ExpiresAt == 0 && c.IssuedAt != 0 {
		// No default TTL silently applied here; callers set ExpiresAt.
	}
	c.SigningKID = k.KID
	raw, err := json.Marshal(&c)
	if err != nil {
		return "", err
	}
	signingInput := tokenVersion + "." + b64(raw)
	return signingInput + "." + signMAC(k.Secret, signingInput), nil
}

// Verify parses and verifies a token. The reason code is precise:
//
//	malformed / bad_signature / unknown_kid / expired
//
// Expired tokens whose signature is otherwise valid still report expired
// (rather than a generic failure) so monitoring can distinguish attacks from
// natural expiry.
func (t *TokenService) Verify(raw string) (*model.AccessClaims, model.TokenFailReason, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] != tokenVersion || parts[1] == "" || parts[2] == "" {
		return nil, model.TokenMalformed, model.ErrMalformedToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, model.TokenMalformed, model.ErrMalformedToken
	}
	var c model.AccessClaims
	if err := json.Unmarshal(payload, &c); err != nil || c.SigningKID == "" {
		return nil, model.TokenMalformed, model.ErrMalformedToken
	}
	key, err := t.ring.ForVerify(c.SigningKID)
	if err != nil {
		// Missing KID and revoked KID are indistinguishable to clients to
		// avoid leaking key topology; both are "unknown_kid".
		return nil, model.TokenUnknownKID, model.ErrUnknownKID
	}
	want := signMAC(key.Secret, tokenVersion+"."+parts[1])
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return nil, model.TokenBadSignature, model.ErrBadSignature
	}
	if c.ExpiresAt != 0 && t.now().Unix() >= c.ExpiresAt {
		return &c, model.TokenExpired, model.ErrTokenExpired
	}
	return &c, model.TokenOK, nil
}
