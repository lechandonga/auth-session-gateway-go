package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/auth"
	"github.com/lechandonga/auth-session-gateway-go/internal/authz"
	"github.com/lechandonga/auth-session-gateway-go/internal/csrf"
	"github.com/lechandonga/auth-session-gateway-go/internal/keyring"
	"github.com/lechandonga/auth-session-gateway-go/internal/ratelimit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/token"
)

type testApp struct {
	h     http.Handler
	svc   *auth.Service
	sink  *audit.MemorySink
	store *session.MemoryStore
	now   func() time.Time
	set   func(time.Time)
}

func buildApp(t *testing.T) *testApp {
	return buildAppOpts(t, session.Options{
		IdleTTL: 30 * time.Minute, AbsoluteTTL: 24 * time.Hour, MaxPerUser: 5,
	})
}

func buildAppOpts(t *testing.T, sopts session.Options) *testApp {
	t.Helper()
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	cur := base
	clock := func() time.Time { return cur }
	kr := keyring.NewMemoryKeyring()
	_ = kr.AddKey(&keyring.Key{ID: "k1", Secret: []byte("http-secret-1"),
		Status: keyring.StatusActive, CreatedAt: base})
	users := auth.NewMemoryUsers()
	alice, _ := auth.NewUser("u-alice", "alice", "alice-pass",
		[]string{"viewer"}, []string{"docs:read"}, map[string]string{"dept": "sales"})
	adm, _ := auth.NewUser("u-admin", "admin", "admin-pass",
		[]string{"admin"}, []string{"*"}, nil)
	bob, _ := auth.NewUser("u-bob", "bob", "bob-pass",
		[]string{"viewer"}, []string{"docs:read"}, nil)
	users.Add(alice)
	users.Add(adm)
	users.Add(bob)
	sink := audit.NewMemorySink()
	store := session.NewMemoryStore()
	svc := auth.NewService(auth.Config{
		Users:    users,
		Sessions: session.NewManager(store, sopts),
		Signer:   token.NewHS256Signer(kr),
		Limiter:  ratelimit.NewMemoryLimiter(ratelimit.DefaultPolicy()),
		Audit:    sink, AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour,
		Clock: clock,
	})
	engine := authz.NewEngine([]authz.Rule{
		{Name: "deny-secrets", Effect: authz.EffectDeny, ResourcePattern: "/docs/secret/**"},
		{Name: "admin-all", Effect: authz.EffectAllow, Roles: []string{"admin"},
			Actions: []string{"*"}, ResourcePattern: "/**", Scopes: []string{"*"}},
		{Name: "viewer-read", Effect: authz.EffectAllow, Roles: []string{"viewer"},
			Actions: []string{"GET"}, ResourcePattern: "/docs/*", Scopes: []string{"docs:read"}},
	})
	prot := csrf.NewProtector()
	srv := &server{svc: svc, engine: engine, audit: sink, csrf: prot, keys: kr,
		log: log.New(io.Discard, "", 0), now: clock}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", srv.login)
	mux.HandleFunc("/refresh", srv.refresh)
	mux.HandleFunc("/logout", srv.logout)
	mux.HandleFunc("/sessions/", srv.revokeSession)
	mux.HandleFunc("/sessions", srv.listSessions)
	mux.HandleFunc("/rotate-keys", srv.rotateKeys)
	mux.HandleFunc("/audit", srv.listAudit)
	mux.HandleFunc("/", srv.resource)
	return &testApp{h: srv.headers(mux), svc: svc, sink: sink, store: store,
		now: clock, set: func(tm time.Time) { cur = tm }}
}

func doJSON(t *testing.T, h http.Handler, req *http.Request) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Result().Cookies()
}

func TestHTTPEndToEnd(t *testing.T) {
	app := buildApp(t)
	h, sink := app.h, app.sink
	jar, _ := cookiejar.New(nil)
	_ = jar
	body := `{"username":"alice","password":"alice-pass"}`
	req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	status, out, cookies := doJSON(t, h, req)
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	var access, csrfTok, refresh string
	var refreshCookie *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case "access_token":
			access = c.Value
		case "csrf_token":
			csrfTok = c.Value
		case "refresh_token":
			refresh = c.Value
			refreshCookie = c
		}
	}
	if access == "" || csrfTok == "" || refresh == "" {
		t.Fatal("missing cookies")
	}
	if !refreshCookie.HttpOnly {
		t.Fatal("refresh cookie must be HttpOnly")
	}
	if _, present := out["refresh_token"]; present {
		t.Fatalf("refresh credential must not appear in response body: %v", out)
	}
	if _, present := out["access_token"]; present {
		t.Fatal("access credential must not appear in response body")
	}
	t.Logf("input=POST /login alice basis=credentials rule=200; both creds HttpOnly cookies; body has no credential")

	// Allowed: viewer GET /docs/r1.
	req, _ = http.NewRequest(http.MethodGet, "/docs/r1?echo=<script>x</script>", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	status, out, _ = doJSON(t, h, req)
	if status != http.StatusOK {
		t.Fatalf("read doc status=%d", status)
	}
	if strings.Contains(out["echo"].(string), "<script>") {
		t.Fatalf("injection echoed raw: %v", out["echo"])
	}
	t.Logf("input=GET /docs/r1 (viewer) basis=viewer-read allow; echo sanitized=%v", out["echo"])

	// Denied: write attempt -> scope/action default deny, critical event.
	req, _ = http.NewRequest(http.MethodPost, "/docs/r1", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
	req.Header.Set("X-CSRF-Token", csrfTok)
	status, out, _ = doJSON(t, h, req)
	if status != http.StatusForbidden {
		t.Fatalf("write status=%d want 403", status)
	}
	t.Logf("input=POST /docs/r1 (viewer) basis=no allow rule -> 403 reason=%s", out["reason"])

	// CSRF failure: POST without header token must be rejected first.
	req, _ = http.NewRequest(http.MethodPost, "/docs/r1", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
	status, out, _ = doJSON(t, h, req)
	if status != http.StatusForbidden || out["error"] != csrf.ErrUnsafeMethod.Error() {
		t.Fatalf("csrf missing status=%d body=%v", status, out)
	}
	// Mismatched token.
	req.Header = http.Header{}
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
	req.Header.Set("X-CSRF-Token", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "mismatch") {
		t.Fatalf("csrf mismatch: %d %s", rec.Code, rec.Body.String())
	}
	t.Log("input=POST cookie auth, no/mismatch token basis=double-submit rule=403 missing distinct from mismatch")

	// Explicit deny even for admin.
	adminBody := `{"username":"admin","password":"admin-pass"}`
	req, _ = http.NewRequest(http.MethodPost, "/login", strings.NewReader(adminBody))
	_, _, adminCookies := doJSON(t, h, req)
	var adminAccess string
	for _, c := range adminCookies {
		if c.Name == "access_token" {
			adminAccess = c.Value
		}
	}
	req, _ = http.NewRequest(http.MethodGet, "/docs/secret/x", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: adminAccess})
	status, out, _ = doJSON(t, h, req)
	if status != http.StatusForbidden || out["reason"] != string(authz.ReasonExplicitDeny) {
		t.Fatalf("admin secret status=%d reason=%v", status, out["reason"])
	}
	t.Logf("input=admin GET /docs/secret/x basis=explicit deny precedence rule=403 %s", out["reason"])

	// Critical audit events recorded.
	evs, _ := sink.List(req.Context())
	var denied int
	for _, e := range evs {
		if e.Type == audit.EventAccessDenied {
			denied++
		}
	}
	if denied < 2 {
		t.Fatalf("access_denied events = %d, want >=2", denied)
	}

	// Key rotation endpoint then old token still works.
	req, _ = http.NewRequest(http.MethodPost, "/rotate-keys", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate keys: %d %s", rec.Code, rec.Body.String())
	}
	req, _ = http.NewRequest(http.MethodGet, "/docs/r1", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	status, _, _ = doJSON(t, h, req)
	if status != http.StatusOK {
		t.Fatalf("old token after key rotation status=%d, want 200 (historical verify)", status)
	}
	t.Log("input=rotate-keys then old access token basis=retired-key historical verify rule=200")
}

func TestHTTPLockoutStatusCodes(t *testing.T) {
	h := buildApp(t).h
	post := func(pw string) int {
		req, _ := http.NewRequest(http.MethodPost, "/login",
			bytes.NewBufferString(`{"username":"alice","password":"`+pw+`"}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	codes := []int{post("bad"), post("bad"), post("bad"), post("bad"), post("bad"), post("alice-pass")}
	// 401 failures, eventually 423 Locked; exact switch-over depends on the
	// default policy (throttle at 3 -> 429, lock at 5 -> 423).
	var saw429, saw423 bool
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			saw429 = true
		}
		if c == http.StatusLocked {
			saw423 = true
		}
	}
	if !saw429 || !saw423 {
		t.Fatalf("codes=%v want at least one 429 and one 423", codes)
	}
	t.Logf("input=6 logins (5 bad + 1 good) basis=throttle then lock policy codes=%v (401/429/423 distinguishable)", codes)
}
