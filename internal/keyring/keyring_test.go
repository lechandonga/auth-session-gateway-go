package keyring

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRotateRetiresOldAndReusesForVerify(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryKeyring()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	if err := r.AddKey(&Key{ID: "k1", Secret: []byte("s1"), Status: StatusActive, CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	k, err := r.Rotate(ctx, "k2", []byte("s2"), t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if k.ID != "k2" || k.Status != StatusActive {
		t.Fatalf("rotate result = %+v", k)
	}
	cur, err := r.Current(ctx)
	if err != nil || cur.ID != "k2" {
		t.Fatalf("current = %v err=%v, want k2 active", cur, err)
	}
	old, err := r.ByID(ctx, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if old.Status != StatusRetired || old.RetiredAt.IsZero() {
		t.Fatalf("old key not retired: %+v", old)
	}
	// Retired key still retrievable for historical verification, and
	// CurrentKey never selects it for signing.
	id, _, err := r.CurrentKey()
	if err != nil || id != "k2" {
		t.Fatalf("CurrentKey = %s, %v", id, err)
	}
	secret, status, err := r.KeyByID("k1")
	if err != nil || status != string(StatusRetired) || string(secret) != "s1" {
		t.Fatalf("KeyByID old = %q,%s,%v", secret, status, err)
	}
	t.Logf("input=rotate(k1->k2) basis=single-active invariant rule=retire-then-insert -> sign=%s verify-key=k1(%s)",
		id, status)
}

func TestMissingAndOverlapDeterministic(t *testing.T) {
	ctx := context.Background()
	r := NewMemoryKeyring()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	if _, err := r.Current(ctx); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("empty keyring Current err = %v, want ErrKeyNotFound", err)
	}
	if _, _, err := r.KeyByID("ghost"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing key err = %v", err)
	}
	// Seed two active keys externally: Current must deterministically refuse
	// with ErrOverlap instead of choosing one arbitrarily.
	if err := r.AddKey(&Key{ID: "a", Secret: []byte("a"), Status: StatusActive, CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddKey(&Key{ID: "b", Secret: []byte("b"), Status: StatusActive, CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := r.Current(ctx); !errors.Is(err, ErrOverlap) {
			t.Fatalf("overlap iteration %d err = %v, want ErrOverlap", i, err)
		}
	}
	// Rotate under overlap retires both and restores exactly one active key.
	k, err := r.Rotate(ctx, "c", []byte("c"), t0)
	if err != nil || k.ID != "c" {
		t.Fatalf("rotate over overlap = %v %v", k, err)
	}
	cur, _ := r.Current(ctx)
	if cur.ID != "c" {
		t.Fatalf("after recovery current = %s", cur.ID)
	}
	t.Log("input=two active keys basis=ambiguous signer rule=ErrOverlap deterministic; rotate recovers one active")
}
