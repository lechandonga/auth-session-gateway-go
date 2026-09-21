// Package keyring manages signing keys with rotation and historical verification.
package keyring

import (
	"context"
	"errors"
	"time"
)

// ErrKeyNotFound indicates no key matched the requested ID/status.
var ErrKeyNotFound = errors.New("keyring: key not found")

// ErrOverlap indicates two active keys exist in the same overlapping window.
var ErrOverlap = errors.New("keyring: overlapping active keys")

// ErrRetired indicates an attempt to sign with a retired key.
var ErrRetired = errors.New("keyring: key is retired")

// KeyStatus enumerates key lifecycle states.
type KeyStatus string

const (
	StatusActive  KeyStatus = "active"
	StatusRetired KeyStatus = "retired"
)

// Key is an HMAC signing key with lifecycle metadata.
type Key struct {
	ID        string
	Secret    []byte
	Status    KeyStatus
	CreatedAt time.Time
	RetiredAt time.Time
}

// Keyring provides lookup and rotation of signing keys.
type Keyring interface {
	// Current returns the key used for signing now.
	Current(ctx context.Context) (*Key, error)
	// ByID returns a key regardless of status (for historical verify).
	ByID(ctx context.Context, id string) (*Key, error)
	// Rotate installs a new active key and retires the previous active key.
	Rotate(ctx context.Context, newID string, secret []byte, now time.Time) (*Key, error)
	// Retire marks an active key retired.
	Retire(ctx context.Context, id string, now time.Time) error
	// List returns all keys ordered by creation time.
	List(ctx context.Context) ([]*Key, error)
}
