package csrf

import (
	"errors"
	"strings"
	"testing"
)

func TestCSRF(t *testing.T) {
	p := NewProtector()
	tok, err := p.GenerateToken()
	if err != nil || len(tok) == 0 {
		t.Fatal(err)
	}
	if err := p.Verify(tok, tok); err != nil {
		t.Fatalf("equal tokens should verify: %v", err)
	}
	if err := p.Verify(tok, ""); !errors.Is(err, ErrMissingToken) {
		t.Fatalf("missing: %v", err)
	}
	if err := p.Verify(tok, tok+"x"); !errors.Is(err, ErrTokenMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	// Safe methods bypass; unsafe methods without tokens are refused.
	if err := p.VerifyRequest("GET", "", ""); err != nil {
		t.Fatalf("GET should be safe: %v", err)
	}
	if err := p.VerifyRequest("POST", "", ""); !errors.Is(err, ErrUnsafeMethod) {
		t.Fatalf("POST no token: %v", err)
	}
	if err := p.VerifyRequest("post", tok, tok); err != nil {
		t.Fatalf("POST with matching tokens: %v", err)
	}
	t.Log("input=GET(bypass)/POST missing->unsafe, mismatch->mismatch, equal->allow basis=double-submit + constant-time")

	h := p.SafeHeaders()
	for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if h[k] == "" {
			t.Fatalf("missing safe header %s", k)
		}
	}
}

func TestSanitizeAndMask(t *testing.T) {
	in := `<script>alert('x')</script> & "q"`
	out := Sanitize(in)
	if strings.Contains(out, "<script>") {
		t.Fatalf("injection not neutralized: %s", out)
	}
	t.Logf("input=%q output=%q basis=html escaping rule=injection never echoed raw", in, out)
	for _, k := range []string{"password", "token", "secret"} {
		if m := Mask(k, "supersecret"); m != "***REDACTED***" {
			t.Fatalf("mask %s = %s", k, m)
		}
	}
	if m := Mask("email", "alice@example.com"); !strings.HasPrefix(m, "a***@") {
		t.Fatalf("email mask = %s", m)
	}
	t.Log("input=password/token/secret -> fully redacted; email -> a***@example.com")
}
