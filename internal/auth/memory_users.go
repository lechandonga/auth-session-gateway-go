package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
)

// ErrUserNotFound indicates the username does not exist.
var ErrUserNotFound = errors.New("auth: user not found")

// hashPassword derives a salted SHA-256 hash. The 16-byte random salt is
// prepended and the whole blob stored in PasswordHash:
//
//	base64(salt || sha256(salt || password))
//
// Local demo component only; production deployments should swap in a
// memory-hard KDF behind the same CredentialStore boundary.
func hashPassword(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append(append([]byte(nil), salt...), []byte(password)...))
	blob := append(salt, sum[:]...)
	return []byte(base64.StdEncoding.EncodeToString(blob)), nil
}

func verifyPassword(hashB64 []byte, password string) bool {
	raw, err := base64.StdEncoding.DecodeString(string(hashB64))
	if err != nil || len(raw) != 16+sha256.Size {
		return false
	}
	salt := raw[:16]
	stored := raw[16:]
	sum := sha256.Sum256(append(append([]byte(nil), salt...), []byte(password)...))
	return subtle.ConstantTimeCompare(sum[:], stored) == 1
}

// NewUser builds a User with a hashed password.
func NewUser(id, username, password string, roles, scopes []string, attrs map[string]string) (*User, error) {
	h, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:           id,
		Username:     username,
		PasswordHash: h,
		Roles:        roles,
		Scopes:       scopes,
		Attributes:   attrs,
	}, nil
}

// MemoryUsers is a concurrency-safe in-memory CredentialStore.
type MemoryUsers struct {
	mu      sync.Mutex
	byLogin map[string]*User
}

// NewMemoryUsers constructs an empty user store.
func NewMemoryUsers() *MemoryUsers {
	return &MemoryUsers{byLogin: map[string]*User{}}
}

// Add inserts or replaces a user.
func (m *MemoryUsers) Add(u *User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byLogin[u.Username] = u
}

// Verify checks a password without returning the stored user on failure.
func (m *MemoryUsers) Verify(username, password string) (*User, bool) {
	m.mu.Lock()
	u := m.byLogin[username]
	m.mu.Unlock()
	if u == nil {
		// Equal-ish work to reduce username enumeration via timing.
		verifyPassword([]byte(base64.StdEncoding.EncodeToString(make([]byte, 16+sha256.Size))), password)
		return nil, false
	}
	if !verifyPassword(u.PasswordHash, password) {
		return nil, false
	}
	return u, true
}

func (m *MemoryUsers) ByLogin(ctx context.Context, username string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byLogin[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

// ByID returns a user by their stable ID.
func (m *MemoryUsers) ByID(id string) (*User, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.byLogin {
		if u.ID == id {
			return u, true
		}
	}
	return nil, false
}
