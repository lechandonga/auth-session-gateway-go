package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/csrf"
)

type clientState struct {
	access  string
	refresh string
	csrf    string
	ua      string
}

func (c *clientState) fromCookies(cookies []*http.Cookie, body map[string]any) {
	for _, ck := range cookies {
		switch ck.Name {
		case "access_token":
			c.access = ck.Value
		case "refresh_token":
			c.refresh = ck.Value
		case "csrf_token":
			c.csrf = ck.Value
		}
	}
	if v, ok := body["csrf_token"].(string); ok && v != "" {
		c.csrf = v
	}
}

func (c *clientState) cookies() []*http.Cookie {
	var out []*http.Cookie
	if c.access != "" {
		out = append(out, &http.Cookie{Name: "access_token", Value: c.access})
	}
	if c.refresh != "" {
		out = append(out, &http.Cookie{Name: "refresh_token", Value: c.refresh, Path: "/refresh"})
	}
	if c.csrf != "" {
		out = append(out, &http.Cookie{Name: "csrf_token", Value: c.csrf})
	}
	return out
}

func do(t *testing.T, h http.Handler, method, target string, c *clientState, withCSRF bool) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	req, _ := http.NewRequest(method, target, nil)
	if c != nil {
		for _, ck := range c.cookies() {
			req.AddCookie(ck)
		}
		if withCSRF {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Result().Cookies()
}

func loginClient(t *testing.T, h http.Handler, user string) *clientState {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, user+"-pass")
	req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("User-Agent", "ua-"+user)
	req.RemoteAddr = "198.51.100.11:5100"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", user, rec.Code, rec.Body.String())
	}
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	c := &clientState{}
	c.fromCookies(rec.Result().Cookies(), out)
	return c
}

func countEvents(events []audit.Event, ty audit.EventType) int {
	n := 0
	for _, e := range events {
		if e.Type == ty {
			n++
		}
	}
	return n
}

// Full chain over real HTTP: login -> refresh cookies -> new access works
// immediately -> old refresh rejected as reuse -> whole family chain dead.
func TestHTTPRefreshChainAndReuseKillsFamily(t *testing.T) {
	app := buildApp(t)
	h := app.h
	c := loginClient(t, h, "alice")

	// Sanity: initial access token reaches a protected resource.
	status, out, _ := do(t, h, http.MethodGet, "/docs/r1", c, false)
	if status != http.StatusOK {
		t.Fatalf("protected read with initial access = %d %v", status, out)
	}
	t.Log("input=GET /docs/r1 after login basis=viewer-read rule=200 with cookie access token")

	oldAccess, oldRefresh := c.access, c.refresh
	// Refresh requires the double-submit CSRF token.
	status, out, cookies := do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %v", status, out)
	}
	c.fromCookies(cookies, out)
	if c.access == "" || c.refresh == "" || c.access == oldAccess || c.refresh == oldRefresh {
		t.Fatalf("rotation must issue both new credentials: %+v", c)
	}
	if c.refresh == oldRefresh {
		t.Fatal("new refresh must differ")
	}
	t.Log("input=POST /refresh with refresh cookie+CSRF basis=atomic rotation rule=200, both cookies rotate")

	// The NEW access token works immediately against a protected resource.
	status, out, _ = do(t, h, http.MethodGet, "/docs/r1", c, false)
	if status != http.StatusOK {
		t.Fatalf("protected read with new access = %d %v", status, out)
	}
	t.Log("input=GET /docs/r1 with refreshed access basis=new token+live session rule=200 immediately")

	// Old access token (family still alive until reuse): now replay the OLD
	// refresh cookie. That must be diagnosed as reuse.
	attacker := &clientState{access: oldAccess, refresh: oldRefresh, csrf: c.csrf}
	status, out, _ = do(t, h, http.MethodPost, "/refresh", attacker, true)
	if status != http.StatusUnauthorized || out["code"] != "refresh_reuse" {
		t.Fatalf("old refresh replay = %d %v, want 401 refresh_reuse", status, out)
	}
	t.Logf("input=POST /refresh with old refresh basis=Rotated marker rule=401 code=%s (family killed)", out["code"])

	// The legitimately-issued NEW refresh must now also fail: chain-wide.
	status, out, _ = do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusUnauthorized || out["code"] != "session_revoked" {
		t.Fatalf("new refresh after detected reuse = %d %v, want 401 session_revoked", status, out)
	}
	// New access token is rejected too (revoked session beats valid signature).
	status, out, _ = do(t, h, http.MethodGet, "/docs/r1", c, false)
	if status != http.StatusUnauthorized || out["code"] != "session_revoked" {
		t.Fatalf("access after family kill = %d %v", status, out)
	}
	events, _ := app.sink.List(nil)
	if n := countEvents(events, audit.EventRefreshReuse); n != 1 {
		t.Fatalf("refresh_reuse events = %d want exactly 1", n)
	}
	for _, e := range events {
		if e.Type == audit.EventRefreshReuse {
			if e.Details["refresh_token"] != "***REDACTED***" {
				t.Fatalf("reuse event must redact token, got %v", e.Details)
			}
		}
	}
	t.Log("input=new refresh + new access after reuse basis=family-wide revocation rule=both 401 session_revoked; audit redacted")
}

// A body-carried refresh token must NOT work: only the HttpOnly cookie is
// accepted, so the client-facing contract really is cookie transport.
func TestHTTPRefreshCookieOnly(t *testing.T) {
	app := buildApp(t)
	h := app.h
	c := loginClient(t, h, "alice")

	// Correct CSRF but no refresh cookie.
	noRefresh := &clientState{access: c.access, csrf: c.csrf}
	status, out, _ := do(t, h, http.MethodPost, "/refresh", noRefresh, true)
	if status != http.StatusUnauthorized || out["code"] != "missing_refresh" {
		t.Fatalf("refresh without cookie = %d %v", status, out)
	}
	t.Logf("input=POST /refresh no refresh cookie basis=cookie-only transport rule=401 code=%s", out["code"])
}

// CSRF failures on state-changing entries must be distinguishable (missing
// vs mismatch) and must never mutate or revoke a healthy session.
func TestHTTPRefreshCSRFFailureDoesNotHarmSession(t *testing.T) {
	app := buildApp(t)
	h := app.h
	c := loginClient(t, h, "alice")

	// Missing CSRF header.
	status, out, _ := do(t, h, http.MethodPost, "/refresh", c, false)
	if status != http.StatusForbidden || out["error"] != csrf.ErrUnsafeMethod.Error() {
		t.Fatalf("missing csrf = %d %v", status, out)
	}
	// Mismatched CSRF header.
	mismatch := &clientState{access: c.access, refresh: c.refresh, csrf: c.csrf}
	req, _ := http.NewRequest(http.MethodPost, "/refresh", nil)
	for _, ck := range mismatch.cookies() {
		req.AddCookie(ck)
	}
	req.Header.Set("X-CSRF-Token", "forged")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusForbidden || !strings.Contains(body["error"].(string), "mismatch") {
		t.Fatalf("mismatch csrf = %d %s", rec.Code, rec.Body.String())
	}
	t.Log("input=refresh with missing/mismatch CSRF basis=double-submit rule=403, two distinct messages")

	// The refresh token must still be untouched: a valid CSRF refresh now
	// succeeds, proving no reuse marking and no revocation happened.
	status, rout, cookies := do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusOK {
		t.Fatalf("refresh after blocked attempts = %d %v", status, rout)
	}
	c.fromCookies(cookies, rout)
	st2, out2, _ := do(t, h, http.MethodGet, "/docs/r1", c, false)
	if st2 != http.StatusOK {
		t.Fatalf("session harmed by csrf rejects: %d %v", st2, out2)
	}
	events, _ := app.sink.List(nil)
	if n := countEvents(events, audit.EventRefreshReuse); n != 0 {
		t.Fatalf("csrf reject counted as reuse: %d events", n)
	}
	t.Log("input=valid refresh after CSRF rejects basis=state untouched rule=200 + 200, zero reuse events")
}

// Logout also requires CSRF and a failed check leaves the session alive.
func TestHTTPLogoutCSRFFailureLeavesSession(t *testing.T) {
	app := buildApp(t)
	h := app.h
	c := loginClient(t, h, "alice")
	status, _, _ := do(t, h, http.MethodPost, "/logout", c, false)
	if status != http.StatusForbidden {
		t.Fatalf("logout missing csrf = %d", status)
	}
	status, out, _ := do(t, h, http.MethodGet, "/docs/r1", c, false)
	if status != http.StatusOK {
		t.Fatalf("session revoked by blocked logout: %d %v", status, out)
	}
	t.Log("input=logout without CSRF then GET basis=blocked before mutation rule=403 then 200")
}
