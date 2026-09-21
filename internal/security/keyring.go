package security

import (
	"sync"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

// KeyStatus is the lifecycle state of a signing key.
type KeyStatus string

const (
	KeyActive  KeyStatus = "active"  // may sign and verify
	KeyRetired KeyStatus = "retired" // verify-only; signing is rejected
	KeyRevoked KeyStatus = "revoked" // neither sign nor verify
)

// SigningKey is an HMAC key with lifecycle metadata.
type SigningKey struct {
	KID       string
	Secret    []byte
	Status    KeyStatus
	CreatedAt time.Time
	RetiredAt time.Time
}

// KeyRing holds signing keys. At most one key may be active at any instant
// ("current"). Rotation promotes a new key and retires the previous one;
// retired keys still verify historical unexpired tokens.
type KeyRing struct {
	mu      sync.RWMutex
	keys    map[string]*SigningKey
	current string
}

func NewKeyRing() *KeyRing { return &KeyRing{keys: map[string]*SigningKey{}} }

// AddKey registers a key. A key explicitly made active is only accepted when
// no other active key exists; otherwise ErrOverlappingKeys is returned so the
// ambiguity never resolves to a random winner. Non-active keys (retired keys
// imported for historical verification) are always accepted.
func (r *KeyRing) AddKey(k *SigningKey, makeActive bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keys[k.KID]; exists {
		return model.ErrOverlappingKeys
	}
	if makeActive && k.Status == KeyActive && r.current != "" {
		return model.ErrOverlappingKeys
	}
	cp := *k
	cp.Secret = append([]byte(nil), k.Secret...)
	r.keys[k.KID] = &cp
	if makeActive {
		if k.Status != KeyActive {
			cp.Status = KeyActive
		}
		r.current = k.KID
	}
	return nil
}

// Rotate installs kid as the new active key and atomically retires the
// previous active key. The whole transition happens under one write lock:
// a concurrent signer either uses the old key or the new key, and verifiers
// can always validate tokens from both. Returns ErrMissingKey if kid absent
// and ErrUnknownKID semantics do not apply to a revoked target (it is simply
// rejected with model.ErrRetiredKey).
func (r *KeyRing) Rotate(kid string, now time.Time) (*SigningKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	nk, ok := r.keys[kid]
	if !ok {
		return nil, model.ErrMissingKey
	}
	if nk.Status == KeyRevoked {
		return nil, model.ErrRetiredKey
	}
	prev := r.current
	r.current = kid
	nk.Status = KeyActive
	if prev != "" && prev != kid {
		if pk, ok := r.keys[prev]; ok && pk.Status == KeyActive {
			pk.Status = KeyRetired
			pk.RetiredAt = now
		}
	}
	out := *nk
	out.Secret = append([]byte(nil), nk.Secret...)
	return &out, nil
}

// Retire moves a key to verify-only state. Retiring the active key without a
// replacement leaves zero active keys; subsequent signing fails deterministically
// with model.ErrMissingKey.
func (r *KeyRing) Retire(kid string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.keys[kid]
	if !ok {
		return model.ErrUnknownKID
	}
	k.Status = KeyRetired
	k.RetiredAt = now
	if r.current == kid {
		r.current = ""
	}
	return nil
}

// RevokeKey prevents a key from signing and verifying (e.g. compromise).
func (r *KeyRing) RevokeKey(kid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.keys[kid]
	if !ok {
		return model.ErrUnknownKID
	}
	k.Status = KeyRevoked
	if r.current == kid {
		r.current = ""
	}
	return nil
}

// Current returns the active key for signing (defensive copy), or
// model.ErrMissingKey when none exists.
func (r *KeyRing) Current() (*SigningKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.current == "" {
		return nil, model.ErrMissingKey
	}
	k := r.keys[r.current]
	if k == nil || k.Status != KeyActive {
		// Invariant defense: dangling pointer means no usable key.
		return nil, model.ErrMissingKey
	}
	out := *k
	out.Secret = append([]byte(nil), k.Secret...)
	return &out, nil
}

// ForVerify returns the key for KID if it may verify (active or retired).
// Revoked keys yield model.ErrBadSignature-class rejection mapped by callers
// to TokenUnknownKID so tokens become unusable.
func (r *KeyRing) ForVerify(kid string) (*SigningKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.keys[kid]
	if !ok || k.Status == KeyRevoked {
		return nil, model.ErrUnknownKID
	}
	out := *k
	out.Secret = append([]byte(nil), k.Secret...)
	return &out, nil
}

// Snapshot returns a defensive copy of all keys for diagnostics.
func (r *KeyRing) Snapshot() []SigningKey {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]SigningKey, 0, len(r.keys))
	for _, k := range r.keys {
		cp := *k
		cp.Secret = append([]byte(nil), k.Secret...)
		out = append(out, cp)
	}
	return out
}
