// Package token issues and verifies signed compact tokens (HS256-like JWT).
package token

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrMalformed indicates the token string is malformed.
	ErrMalformed = errors.New("token: malformed")
	// ErrBadSignature indicates signature verification failed.
	ErrBadSignature = errors.New("token: bad signature")
	// ErrExpired indicates the token is expired.
	ErrExpired = errors.New("token: expired")
	// ErrKeyUnavailable indicates no usable signing key exists.
	ErrKeyUnavailable = errors.New("token: no signing key available")
)

// Claims is the payload carried by an issued token.
type Claims struct {
	Subject    string            `json:"sub"`
	SessionID  string            `json:"sid"`
	FamilyID   string            `json:"fam"`
	Roles      []string          `json:"roles"`
	Scope      []string          `json:"scope"`
	Attributes map[string]string `json:"attr"`
	IssuedAt   int64             `json:"iat"`
	ExpiresAt  int64             `json:"exp"`
	TokenType  string            `json:"typ"`
}

// IsExpired reports whether claims expire before now.
func (c *Claims) IsExpired(now time.Time) bool {
	return c.ExpiresAt > 0 && now.Unix() >= c.ExpiresAt
}

// Signer signs and verifies tokens against a keyring.
type Signer interface {
	Issue(ctx context.Context, c Claims, now time.Time) (compact string, kid string, err error)
	Verify(ctx context.Context, compact string, now time.Time) (*Claims, string, error)
}
