package token

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeLookup struct {
	current string
	secrets map[string][]byte
}

func (f *fakeLookup) CurrentKey() (string, []byte, error) {
	if f.current == "" {
		return "", nil, ErrKeyUnavailable
	}
	return f.current, f.secrets[f.current], nil
}
func (f *fakeLookup) KeyByID(id string) ([]byte, string, error) {
	s, ok := f.secrets[id]
	if !ok {
		return nil, "", ErrKeyUnavailable
	}
	status := "retired"
	if id == f.current {
		status = "active"
	}
	return s, status, nil
}

func TestSignVerifyAndRotationCompatibility(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	lk := &fakeLookup{current: "k1", secrets: map[string][]byte{"k1": []byte("old-secret"), "k2": []byte("new-secret")}}
	s := NewHS256Signer(lk)
	ctx := context.Background()
	c := Claims{Subject: "u1", SessionID: "s1", ExpiresAt: t0.Add(time.Hour).Unix(), TokenType: "access"}
	compact, kid, err := s.Issue(ctx, c, t0)
	if err != nil || kid != "k1" {
		t.Fatalf("issue = %s,%v", kid, err)
	}
	// Rotate: new tokens signed by k2, old k1 token still verifies.
	lk.current = "k2"
	gotClaims, gotKid, err := s.Verify(ctx, compact, t0.Add(time.Minute))
	if err != nil || gotKid != "k1" || gotClaims.Subject != "u1" {
		t.Fatalf("old-token verify = kid %s err %v", gotKid, err)
	}
	t.Logf("input=token signed by retired k1, now=k1+1m basis=historical key lookup rule=retired-verify-ok -> kid=%s sub=%s",
		gotKid, gotClaims.Subject)
	compact2, kid2, err := s.Issue(ctx, c, t0.Add(2*time.Minute))
	if err != nil || kid2 != "k2" {
		t.Fatalf("post-rotate issue kid = %s err %v", kid2, err)
	}
	if _, _, err := s.Verify(ctx, compact2, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("new token verify: %v", err)
	}
	t.Logf("input=new issuance basis=CurrentKey=k2 rule=retired-key-never-signs -> kid=%s", kid2)
}

func TestVerifyFailures(t *testing.T) {
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	lk := &fakeLookup{current: "k1", secrets: map[string][]byte{"k1": []byte("sec")}}
	s := NewHS256Signer(lk)
	ctx := context.Background()
	c := Claims{Subject: "u1", ExpiresAt: t0.Unix(), TokenType: "access"}
	compact, _, _ := s.Issue(ctx, c, t0)
	if _, _, err := s.Verify(ctx, compact, t0); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry: got %v want ErrExpired", err)
	}
	t.Logf("input=expired token basis=now>=exp rule=ErrExpired (distinct)")
	if _, _, err := s.Verify(ctx, "a.b", t0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed: %v", err)
	}
	if _, _, err := s.Verify(ctx, compact+"x", t0.Add(-time.Hour)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: %v", err)
	}
	// Key deleted after issue.
	delete(lk.secrets, "k1")
	if _, _, err := s.Verify(ctx, compact, t0.Add(-time.Hour)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing key: %v", err)
	}
	t.Log("input=token with deleted kid basis=key lookup miss rule=ErrKeyUnavailable (deterministic, explainable)")
}
