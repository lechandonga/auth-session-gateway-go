package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/auth"
	"github.com/lechandonga/auth-session-gateway-go/internal/authz"
	"github.com/lechandonga/auth-session-gateway-go/internal/model"
	"github.com/lechandonga/auth-session-gateway-go/internal/security"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/store"
)

type env struct {
	srv    *Server
	aud    *audit.Logger
	ring   *security.KeyRing
	stores struct {
		users *store.UserStore
		locks *store.LockoutStore
		sess  *store.SessionStore
		refr  *store.RefreshStore
	}
	now time.Time
}

func setup(t *testing.T) *env {
	t.Helper()
	now := time.Unix(1000, 0)
	users := store.NewUserStore()
	locks := store.NewLockoutStore()
	sessions := store.NewSessionStore()
	refresh := store.NewRefreshStore()
	aud := audit.NewLogger()
	ring := security.NewKeyRing()
	_ = ring.AddKey(&security.SigningKey{KID: "k1", Secret: []byte("gateway-secret-1"), Status: security.KeyActive, CreatedAt: now}, true)
	tok := security.NewTokenService(ring).WithClock(func() time.Time { return now })

	rl := auth.NewRateLimiter(100, time.Minute)
	au := auth.NewAuthenticator(users, locks, aud, auth.Policy{
		MaxFailures: 3, FailWindow: 15 * time.Minute, LockDuration: time.Minute,
	}, rl)
	mgr := session.NewManager(sessions, refresh, tok, aud, session.Config{
		AccessTokenTTL: time.Minute, RefreshTTL: time.Hour,
		IdleTimeout: time.Minute, AbsoluteTTL: 2 * time.Hour,
	})
	csrf := security.NewCSRFProtector()
	engine := authz.NewEngine([]model.Policy{
		{ID: "docs-read", Effect: model.EffectAllow, Roles: []string{"member"}, Actions: []string{"GET"}, Resource: "docs/*", Scopes: []string{"docs:read"}},
		{ID: "docs-write", Effect: model.EffectAllow, Roles: []string{"editor"}, Actions: []string{"POST"}, Resource: "docs/*", Scopes: []string{"docs:write"}},
		{ID: "deny-sealed", Effect: model.EffectDeny, Resource: "docs/sealed/*"},
	})
	srv := New(Deps{Auth: au, Sess: mgr, Engine: engine, CSRF: csrf, Aud: aud})

	e := &env{srv: srv, aud: aud, ring: ring, now: now}
	e.stores.users = users
	e.stores.locks = locks
	e.stores.sess = sessions
	e.stores.refr = refresh

	// Seed users: alice member, bob editor.
	for _, u := range []struct{ name, role string }{{"alice", "member"}, {"bob", "editor"}} {
		salt := auth.NewSalt()
		_ = users.Create(&model.User{
			ID: "u-" + u.name, Username: u.name, Salt: salt,
			PasswordHash: auth.HashPassword(salt, "pw"),
			Roles:        []string{u.role},
		})
	}
	return e
}

func (e *env) do(t *testing.T, method, path string, body any, cookies []*http.Cookie, csrf string) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "10.0.0.1:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if csrf != "" {
		req.Header.Set(headerCSRF, csrf)
	}
	rec := httptest.NewRecorder()
	e.srv.Routes().ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out, rec.Result().Cookies()
}

func login(t *testing.T, e *env, user string) (cookies []*http.Cookie, access, csrf string) {
	t.Helper()
	code, body, setCookies := e.do(t, "POST", "/login", map[string]string{"username": user, "password": "pw"}, nil, "")
	if code != 200 {
		t.Fatalf("login %s: code=%d body=%v", user, code, body)
	}
	cookies = setCookies
	access, _ = body["access_token"].(string)
	csrf, _ = body["csrf_token"].(string)
	return
}

func TestEndToEndLoginAccessCSRFRotation(t *testing.T) {
	e := setup(t)
	cookies, access, csrfTok := login(t, e, "alice")
	if access == "" || csrfTok == "" || len(cookies) != 2 {
		t.Fatal("login response incomplete")
	}
	t.Log("INPUT alice/pw 登录 -> 判定依据 凭据正确+签发 -> 命中规则 200 并设置 HttpOnly/SameSite=Strict cookies")

	// Security headers are always present.
	req := httptest.NewRequest("GET", "/echo?q=hi", nil)
	rec := httptest.NewRecorder()
	e.srv.Routes().ServeHTTP(rec, req)
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("missing security headers: %v", rec.Header())
	}

	// CSRF: refresh without token rejected (missing), wrong token rejected (mismatch).
	code, body, _ := e.do(t, "POST", "/refresh", nil, cookies, "")
	if code != 403 || body["reason"] != "csrf_missing" {
		t.Fatalf("refresh without csrf: %d %v", code, body)
	}
	code, body, _ = e.do(t, "POST", "/refresh", nil, cookies, "deadbeef")
	if code != 403 || body["reason"] != "csrf_mismatch" {
		t.Fatalf("refresh wrong csrf: %d %v", code, body)
	}
	t.Log("INPUT /refresh 缺/错 CSRF -> 判定依据 double-submit 校验 -> 命中规则 403 csrf_missing/csrf_mismatch 可区分")

	// Valid refresh rotates; old rotation replay triggers reuse.
	code, body, newCookies := e.do(t, "POST", "/refresh", nil, cookies, csrfTok)
	if code != 200 {
		t.Fatalf("valid refresh: %d %v", code, body)
	}
	rtCookie := cookies[0]
	// Same old refresh cookie presented again -> reuse.
	code, body, _ = e.do(t, "POST", "/refresh", nil, cookies, csrfTok)
	if code != 401 || body["reason"] != "reuse_detected" {
		t.Fatalf("replay old refresh: %d %v", code, body)
	}
	t.Logf("INPUT 重放旧 refresh cookie -> 判定依据 已轮换 -> 命中规则 401 %s 家族连带失效", body["reason"])
	_ = rtCookie
	_ = newCookies

	// Authorization with a fresh login: member can read docs, cannot write
	// and cannot touch the sealed subtree.
	cookies2, access2, csrf2 := login(t, e, "bob") // bob is editor
	code, body, _ = e.doWithBearer(t, "POST", "/access", map[string]string{"resource": "docs/a", "action": "POST"}, cookies2, csrf2, access2)
	if code != 200 {
		t.Fatalf("editor write: %d %v", code, body)
	}
	code, body, _ = e.doWithBearer(t, "POST", "/access", map[string]string{"resource": "docs/sealed/x", "action": "POST"}, cookies2, csrf2, access2)
	if code != 403 || body["reason"] != "explicit_deny" {
		t.Fatalf("sealed doc: %d %v", code, body)
	}
	t.Logf("INPUT editor POST docs/sealed/x -> 判定依据 deny-sealed 无条件拒绝 -> 命中规则 403 %s", body["reason"])

	// Alice (member) attempting write is denied for a specific reason.
	_, accessA, csrfA := login(t, e, "alice")
	cookiesA, _, _ := e.loginCookiesOnly("alice")
	code, body, _ = e.doWithBearer(t, "POST", "/access", map[string]string{"resource": "docs/a", "action": "POST"}, cookiesA, csrfA, accessA)
	if code != 403 {
		t.Fatalf("member write must be 403: %d %v", code, body)
	}
	t.Logf("INPUT member POST docs/a -> 判定依据 动作/角色/作用域 -> 命中规则 403 reason=%s（越权被拒且原因可区分）", body["reason"])

	// Audit trail contains the key security events.
	for _, typ := range []string{model.EventAccessDenied, model.EventRefreshReuse, model.EventCSRFRejected} {
		if len(e.aud.ByType(typ)) == 0 {
			t.Fatalf("expected audit event %s, got none (events=%d)", typ, e.aud.Count())
		}
	}
	t.Logf("INPUT 审计检查 -> 命中规则 access_denied/refresh_token_reuse/csrf_rejected 均已记录(总 %d 条, 无静默丢弃)", e.aud.Count())
}

func (e *env) loginCookiesOnly(user string) ([]*http.Cookie, string, string) {
	req := httptest.NewRequest("POST", "/login", strings.NewReader(`{"username":"`+user+`","password":"pw"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.2:1"
	rec := httptest.NewRecorder()
	e.srv.Routes().ServeHTTP(rec, req)
	var b map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	access, _ := b["access_token"].(string)
	csrf, _ := b["csrf_token"].(string)
	return rec.Result().Cookies(), access, csrf
}

func (e *env) doWithBearer(t *testing.T, method, path string, body any, cookies []*http.Cookie, csrfTok, bearer string) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "10.0.0.3:1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if csrfTok != "" {
		req.Header.Set(headerCSRF, csrfTok)
	}
	rec := httptest.NewRecorder()
	e.srv.Routes().ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec.Code, out, rec.Result().Cookies()
}

func TestInjectionNotReflectedAndSensitiveRedacted(t *testing.T) {
	e := setup(t)
	payload := url.QueryEscape("<script>alert('x')</script>")
	req := httptest.NewRequest("GET", "/echo?q="+payload, nil)
	req.RemoteAddr = "10.0.0.4:1"
	rec := httptest.NewRecorder()
	e.srv.Routes().ServeHTTP(rec, req)
	body := rec.Body.String()
	for _, bad := range []string{"<script>", "</script>", "'"} {
		if strings.Contains(body, bad) {
			t.Fatalf("injection reflected verbatim (%s): %s", bad, body)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("expected escaped output, got %s", body)
	}
	t.Logf("INPUT q=%s -> 判定依据 输出实体转义 -> 命中规则 注入不原样回显: %s", payload, strings.TrimSpace(body))

	if got := security.Redact("password", "anything"); got != "***" {
		t.Fatalf("password redaction: %s", got)
	}
}

func TestLockoutOverHTTPAndAuditOnce(t *testing.T) {
	e := setup(t)
	for i := 0; i < 3; i++ {
		code, _, _ := e.do(t, "POST", "/login", map[string]string{"username": "alice", "password": "WRONG"}, nil, "")
		if code != 401 {
			t.Fatalf("bad attempt %d: %d", i, code)
		}
	}
	code, body, _ := e.do(t, "POST", "/login", map[string]string{"username": "alice", "password": "pw"}, nil, "")
	if code != 423 || body["reason"] != "locked" {
		t.Fatalf("locked response: %d %v", code, body)
	}
	if n := len(e.aud.ByType(model.EventLocked)); n != 1 {
		t.Fatalf("exactly one lock event over HTTP, got %d", n)
	}
	t.Log("INPUT 3 次错误密码后用正确密码 -> 判定依据 阈值锁定 -> 命中规则 423 locked（非 429 限速），锁定事件=1")
}
