package token

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// HS256Signer implements Signer using HMAC-SHA256 over a compact
// base64url(header).base64url(claims).base64url(signature) token.
// Retired keys may still verify old tokens; only the current active key
// is used to issue.
type HS256Signer struct {
	kr KeyLookup
}

// KeyLookup is the subset of the keyring used by the signer.
type KeyLookup interface {
	CurrentKey() (id string, secret []byte, err error)
	KeyByID(id string) (secret []byte, status string, err error)
}

// NewHS256Signer constructs a signer over the given key lookup.
func NewHS256Signer(kr KeyLookup) *HS256Signer {
	return &HS256Signer{kr: kr}
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

var b64 = base64.RawURLEncoding

func (s *HS256Signer) sign(kid string, secret []byte, c Claims) (string, error) {
	hdr, err := json.Marshal(header{Alg: "HS256", Kid: kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	sig := b64.EncodeToString(mac.Sum(nil))
	return signing + "." + sig, nil
}

func (s *HS256Signer) Issue(ctx context.Context, c Claims, now time.Time) (string, string, error) {
	kid, secret, err := s.kr.CurrentKey()
	if err != nil {
		return "", "", err
	}
	if c.IssuedAt == 0 {
		c.IssuedAt = now.Unix()
	}
	tok, err := s.sign(kid, secret, c)
	if err != nil {
		return "", "", err
	}
	return tok, kid, nil
}

func (s *HS256Signer) Verify(ctx context.Context, compact string, now time.Time) (*Claims, string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, "", ErrMalformed
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, "", ErrMalformed
	}
	var hdr header
	if err := json.Unmarshal(hb, &hdr); err != nil || hdr.Alg != "HS256" || hdr.Kid == "" {
		return nil, "", ErrMalformed
	}
	// Historical verification: retired keys are acceptable here; a missing
	// key yields ErrKeyUnavailable (upstream maps to key-not-found).
	secret, _, err := s.kr.KeyByID(hdr.Kid)
	if err != nil {
		return nil, hdr.Kid, ErrKeyUnavailable
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, hdr.Kid, ErrMalformed
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, hdr.Kid, ErrMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return nil, hdr.Kid, ErrBadSignature
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, hdr.Kid, ErrMalformed
	}
	if c.IsExpired(now) {
		return &c, hdr.Kid, ErrExpired
	}
	return &c, hdr.Kid, nil
}
