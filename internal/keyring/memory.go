package keyring

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryKeyring is a concurrency-safe in-memory Keyring implementation.
// Invariant maintained by Rotate: at most one key is in StatusActive at a
// time. If externally seeded state breaks that invariant, Current fails with
// ErrOverlap rather than guessing which key to use.
type MemoryKeyring struct {
	mu   sync.Mutex
	keys map[string]*Key
}

// NewMemoryKeyring creates an empty in-memory keyring.
func NewMemoryKeyring() *MemoryKeyring {
	return &MemoryKeyring{keys: map[string]*Key{}}
}

// AddKey installs an externally constructed key (seeding / tests).
// Installing a second active key while one already exists makes Current
// deterministically return ErrOverlap until one is retired.
func (r *MemoryKeyring) AddKey(k *Key) error {
	if k == nil || k.ID == "" {
		return ErrKeyNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keys[k.ID]; exists {
		return ErrOverlap
	}
	cp := *k
	r.keys[k.ID] = &cp
	return nil
}

func (r *MemoryKeyring) Current(ctx context.Context) (*Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var active []*Key
	for _, k := range r.keys {
		if k.Status == StatusActive {
			active = append(active, k)
		}
	}
	switch len(active) {
	case 0:
		return nil, ErrKeyNotFound
	case 1:
		cp := *active[0]
		return &cp, nil
	default:
		// Overlapping active keys: deterministic, explainable refusal.
		sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
		_ = active
		return nil, ErrOverlap
	}
}

func (r *MemoryKeyring) ByID(ctx context.Context, id string) (*Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.keys[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	cp := *k
	return &cp, nil
}

func (r *MemoryKeyring) Rotate(ctx context.Context, newID string, secret []byte, now time.Time) (*Key, error) {
	if newID == "" || len(secret) == 0 {
		return nil, ErrKeyNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.keys[newID]; exists {
		return nil, ErrOverlap
	}
	// Retire every currently active key under the same lock so that the
	// "exactly one active key" invariant never becomes half-updated.
	for _, k := range r.keys {
		if k.Status == StatusActive {
			k.Status = StatusRetired
			k.RetiredAt = now
		}
	}
	nk := &Key{ID: newID, Secret: append([]byte(nil), secret...), Status: StatusActive, CreatedAt: now}
	r.keys[newID] = nk
	cp := *nk
	return &cp, nil
}

func (r *MemoryKeyring) Retire(ctx context.Context, id string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k, ok := r.keys[id]
	if !ok {
		return ErrKeyNotFound
	}
	if k.Status != StatusRetired {
		k.Status = StatusRetired
		k.RetiredAt = now
	}
	return nil
}

func (r *MemoryKeyring) List(ctx context.Context) ([]*Key, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Key, 0, len(r.keys))
	for _, k := range r.keys {
		cp := *k
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// CurrentKey adapts to token.KeyLookup.
func (r *MemoryKeyring) CurrentKey() (string, []byte, error) {
	k, err := r.Current(context.Background())
	if err != nil {
		return "", nil, err
	}
	return k.ID, append([]byte(nil), k.Secret...), nil
}

// KeyByID adapts to token.KeyLookup for historical verification.
func (r *MemoryKeyring) KeyByID(id string) ([]byte, string, error) {
	k, err := r.ByID(context.Background(), id)
	if err != nil {
		return nil, "", err
	}
	return append([]byte(nil), k.Secret...), string(k.Status), nil
}
