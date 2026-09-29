// Command gateway runs a local HTTP server wiring the authentication,
// session, key-rotation, authorization, CSRF and audit components together.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
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

func main() {
	logger := log.New(os.Stdout, "gateway ", log.LstdFlags|log.Lmicroseconds)
	now := time.Now

	// --- Signing keys: seed an initial active key.
	kr := keyring.NewMemoryKeyring()
	if err := kr.AddKey(&keyring.Key{
		ID: "k1", Secret: []byte("demo-secret-key-0001"),
		Status: keyring.StatusActive, CreatedAt: now(),
	}); err != nil {
		log.Fatal(err)
	}
	signer := token.NewHS256Signer(kr)

	// --- Users (local credential store).
	users := auth.NewMemoryUsers()
	admin, err := auth.NewUser("u-admin", "admin", "admin-pass",
		[]string{"admin"}, []string{"*"}, map[string]string{"dept": "ops"})
	must(err)
	alice, err := auth.NewUser("u-alice", "alice", "alice-pass",
		[]string{"viewer"}, []string{"docs:read"}, map[string]string{"dept": "sales"})
	must(err)
	bob, err := auth.NewUser("u-bob", "bob", "bob-pass",
		[]string{"editor"}, []string{"docs:read", "docs:write"}, map[string]string{"dept": "sales"})
	must(err)
	users.Add(admin)
	users.Add(alice)
	users.Add(bob)

	// --- Supporting components.
	sink := audit.NewMemorySink()
	limiter := ratelimit.NewMemoryLimiter(ratelimit.Policy{
		MaxFailures:   5,
		Lockout:       5 * time.Minute,
		ThrottleAfter: 3,
		ThrottleDelay: time.Second,
		Window:        10 * time.Minute,
	})
	store := session.NewMemoryStore()
	mgr := session.NewManager(store, session.Options{
		IdleTTL: 30 * time.Minute, AbsoluteTTL: 24 * time.Hour, MaxPerUser: 5,
	})

	svc := auth.NewService(auth.Config{
		Users: users, Sessions: mgr, Signer: signer, Limiter: limiter,
		Audit: sink, AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour, Clock: now,
	})

	// --- Authorization policy. Explicit deny beats any allow regardless
	// of registration order; hierarchy and scope narrow least privilege.
	engine := authz.NewEngine([]authz.Rule{
		{Name: "deny-secrets", Effect: authz.EffectDeny,
			ResourcePattern: "/docs/secret/**"},
		{Name: "admin-all", Effect: authz.EffectAllow, Roles: []string{"admin"},
			Actions: []string{"*"}, ResourcePattern: "/**", Scopes: []string{"*"}},
		{Name: "viewer-read-docs", Effect: authz.EffectAllow, Roles: []string{"viewer"},
			Actions: []string{"GET"}, ResourcePattern: "/docs/*", Scopes: []string{"docs:read"}},
		{Name: "editor-write-docs", Effect: authz.EffectAllow, Roles: []string{"editor"},
			Actions: []string{"GET", "POST", "PUT"}, ResourcePattern: "/docs/*",
			Scopes: []string{"docs:read", "docs:write"}},
	})

	prot := csrf.NewProtector()
	srv := &server{svc: svc, engine: engine, audit: sink, csrf: prot, keys: kr,
		log: logger, now: now}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/login", srv.login)
	mux.HandleFunc("/refresh", srv.refresh)
	mux.HandleFunc("/logout", srv.logout)
	mux.HandleFunc("/sessions/", srv.revokeSession)
	mux.HandleFunc("/sessions", srv.listSessions)
	mux.HandleFunc("/rotate-keys", srv.rotateKeys)
	mux.HandleFunc("/audit", srv.listAudit)
	mux.HandleFunc("/", srv.resource)

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	logger.Printf("gateway listening on %s (users: admin/alice/bob)", addr)
	if err := http.ListenAndServe(addr, srv.headers(mux)); err != nil {
		log.Fatal(err)
	}
}

type server struct {
	svc    *auth.Service
	engine *authz.DefaultEngine
	audit  audit.Sink
	csrf   *csrf.Protector
	keys   *keyring.MemoryKeyring
	log    *log.Logger
	now    func() time.Time
}

func newAuditID(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(b)
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func (s *server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range s.csrf.SafeHeaders() {
			w.Header().Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	cookieAccess  = "access_token"
	cookieRefresh = "refresh_token"
	cookieCSRF    = "csrf_token"
)

func (s *server) setCredentialCookies(w http.ResponseWriter, tok *auth.LoginTokens, csrfTok string) {
	http.SetCookie(w, &http.Cookie{Name: cookieAccess, Value: tok.AccessToken,
		Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Expires: tok.ExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: cookieRefresh, Value: tok.RefreshToken,
		Path: "/refresh", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Expires: tok.AbsoluteExpiresAt})
	http.SetCookie(w, &http.Cookie{Name: cookieCSRF, Value: csrfTok,
		Path: "/", HttpOnly: false, SameSite: http.SameSiteStrictMode,
		Expires: tok.AbsoluteExpiresAt})
}

func (s *server) clearCredentialCookies(w http.ResponseWriter) {
	for _, n := range []string{cookieAccess, cookieRefresh, cookieCSRF} {
		path := "/"
		if n == cookieRefresh {
			path = "/refresh"
		}
		http.SetCookie(w, &http.Cookie{Name: n, Value: "", MaxAge: -1, Path: path})
	}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed json"})
		return
	}
	tok, err := s.svc.Login(r.Context(), req.Username, req.Password, r.RemoteAddr, r.UserAgent())
	if err != nil {
		s.log.Printf("login input={user:%s peer:%s} decision=deny basis=%q password=%s",
			csrf.Sanitize(req.Username), r.RemoteAddr, err.Error(), csrf.Mask("password", req.Password))
		status := http.StatusUnauthorized
		switch {
		case strings.Contains(err.Error(), "locked"):
			status = http.StatusLocked
		case strings.Contains(err.Error(), "throttled"):
			status = http.StatusTooManyRequests
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	csrfTok, _ := s.csrf.GenerateToken()
	s.setCredentialCookies(w, tok, csrfTok)
	s.log.Printf("login input={user:%s} decision=allow basis=credentials+policy session=%s key=%s",
		csrf.Sanitize(req.Username), tok.SessionID, tok.KeyID)
	// The body carries only non-session-sensitive metadata; both credentials
	// live exclusively in HttpOnly cookies.
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":          tok.SessionID,
		"key_id":              tok.KeyID,
		"expires_at":          tok.ExpiresAt,
		"idle_expires_at":     tok.IdleExpiresAt,
		"absolute_expires_at": tok.AbsoluteExpiresAt,
		"csrf_token":          csrfTok,
	})
}

func (s *server) extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie(cookieAccess); err == nil {
		return c.Value
	}
	return ""
}

// requireCSRF enforces the double-submit check on a state-changing entry.
// Missing and mismatched tokens stay distinguishable. Crucially this runs
// before any session-state mutation: a rejected request is never counted as
// refresh-token reuse and never revokes a healthy session.
func (s *server) requireCSRF(w http.ResponseWriter, r *http.Request, label string) bool {
	csrfCookie, _ := r.Cookie(s.csrf.CookieName())
	cookieVal := ""
	if csrfCookie != nil {
		cookieVal = csrfCookie.Value
	}
	err := s.csrf.VerifyRequest(r.Method, cookieVal, r.Header.Get(s.csrf.HeaderName()))
	if err != nil {
		s.log.Printf("%s csrf input={method:%s} decision=deny basis=%q (no session state touched)",
			label, r.Method, err.Error())
		_, _ = s.audit.Record(r.Context(), audit.Event{
			EventID: newAuditID("csrf"), Type: audit.EventCSRFFailure, OccurredAt: s.now(),
			Details: map[string]string{"entry": label, "basis": err.Error()},
		})
		status := http.StatusForbidden
		if errors.Is(err, csrf.ErrTokenMismatch) {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error(), "code": "csrf_failed"})
		return false
	}
	return true
}

// sessionError maps session-layer causes to distinct, externally visible
// codes: reuse / revoked / idle / absolute / unknown never blur together.
func sessionErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, session.ErrRefreshReused):
		return http.StatusUnauthorized, "refresh_reuse"
	case errors.Is(err, session.ErrSessionRevoked):
		return http.StatusUnauthorized, "session_revoked"
	case errors.Is(err, session.ErrSessionIdle):
		return http.StatusUnauthorized, "session_idle_expired"
	case errors.Is(err, session.ErrSessionAbsolute):
		return http.StatusUnauthorized, "session_absolute_expired"
	case errors.Is(err, auth.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid_token"
	default:
		return http.StatusUnauthorized, "invalid_token"
	}
}

func (s *server) refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.requireCSRF(w, r, "refresh") {
		return
	}
	// The refresh credential is only accepted from its HttpOnly cookie.
	rc, err := r.Cookie(cookieRefresh)
	raw := ""
	if err == nil {
		raw = rc.Value
	}
	if raw == "" {
		s.log.Printf("refresh decision=deny basis=missing refresh cookie (no session state touched)")
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "missing refresh credential", "code": "missing_refresh"})
		return
	}
	tok, rerr := s.svc.Refresh(r.Context(), raw)
	if rerr != nil {
		_, code := sessionErrorStatus(rerr)
		s.log.Printf("refresh input={refresh_token:%s} decision=deny basis=%q code=%s",
			csrf.Mask("refresh_token", raw), rerr.Error(), code)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": rerr.Error(), "code": code})
		return
	}
	// Both credentials rotate together and are re-delivered as cookies.
	s.setCredentialCookies(w, tok, r.Header.Get(s.csrf.HeaderName()))
	s.log.Printf("refresh decision=allow basis=rotation session=%s key=%s (cookies rotated)",
		tok.SessionID, tok.KeyID)
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":          tok.SessionID,
		"key_id":              tok.KeyID,
		"expires_at":          tok.ExpiresAt,
		"idle_expires_at":     tok.IdleExpiresAt,
		"absolute_expires_at": tok.AbsoluteExpiresAt,
	})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.requireCSRF(w, r, "logout") {
		return
	}
	tok := s.extractToken(r)
	if tok == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return
	}
	if err := s.svc.Logout(r.Context(), tok); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	s.clearCredentialCookies(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (s *server) authn(w http.ResponseWriter, r *http.Request) (*auth.User, *auth.SessionView, bool) {
	tok := s.extractToken(r)
	if tok == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return nil, nil, false
	}
	u, sess, err := s.svc.Authenticate(r.Context(), tok)
	if err != nil {
		_, code := sessionErrorStatus(err)
		if errors.Is(err, token.ErrExpired) {
			code = "access_token_expired"
		}
		s.log.Printf("authn input={path:%s} decision=deny basis=%q code=%s", r.URL.Path, err.Error(), code)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error(), "code": code})
		return nil, nil, false
	}
	return u, sess, true
}

func (s *server) listSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	u, sess, ok := s.authn(w, r)
	if !ok {
		return
	}
	list, err := s.svc.ListSessions(r.Context(), u.ID, sess.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

func (s *server) revokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.requireCSRF(w, r, "revoke-session") {
		return
	}
	u, _, ok := s.authn(w, r)
	if !ok {
		return
	}
	targetID := strings.TrimPrefix(r.URL.Path, "/sessions/")
	if targetID == "" || strings.Contains(targetID, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed session id"})
		return
	}
	revoked, err := s.svc.RevokeTarget(r.Context(), u.ID, targetID)
	switch {
	case errors.Is(err, session.ErrSessionNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "session not found", "code": "session_not_found"})
		return
	case errors.Is(err, auth.ErrSessionDenied):
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "not your session", "code": "session_forbidden"})
		return
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	status := http.StatusOK
	body := map[string]any{"revoked": revoked, "session_id": targetID}
	if !revoked {
		// Existed and owned, but already dead: distinct from a fresh revoke.
		status = http.StatusGone
		body["code"] = "already_inactive"
	}
	writeJSON(w, status, body)
}
func (s *server) rotateKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	kidB := make([]byte, 8)
	_, _ = rand.Read(kidB)
	newID := "k" + base64.RawURLEncoding.EncodeToString(kidB)
	k, err := s.keys.Rotate(r.Context(), newID, append([]byte("demo-secret-"), []byte(newID)...), time.Now())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	s.log.Printf("key rotation new=%s (previous keys retained for verify only)", k.ID)
	writeJSON(w, http.StatusOK, map[string]string{"active_key": k.ID})
}

func (s *server) listAudit(w http.ResponseWriter, r *http.Request) {
	events, _ := s.audit.List(r.Context())
	writeJSON(w, http.StatusOK, events)
}

func (s *server) resource(w http.ResponseWriter, r *http.Request) {
	// Cookie-based unsafe requests must carry a valid double-submit token.
	if _, cookieErr := r.Cookie(cookieAccess); cookieErr == nil && !csrf.SafeMethods[r.Method] {
		if !s.requireCSRF(w, r, "resource:"+r.URL.Path) {
			return
		}
	}
	u, sess, ok := s.authn(w, r)
	if !ok {
		return
	}
	sub := authz.Subject{UserID: u.ID, Roles: u.Roles, Scopes: u.Scopes, Attributes: u.Attributes}
	res := authz.Resource{Path: r.URL.Path, Attributes: map[string]string{}}
	result, _ := s.engine.Authorize(r.Context(), sub, res, r.Method, authz.Context{"peer": r.RemoteAddr})
	s.log.Printf("authz input={user:%s path:%s action:%s roles:%v scopes:%v} decision=%s reason=%s rule=%q evaluated=%v",
		u.ID, csrf.Sanitize(r.URL.Path), r.Method, u.Roles, u.Scopes,
		result.Decision, result.DenyReason, result.MatchedRule, result.Evaluated)
	if result.Decision != authz.DecisionAllow {
		_, _ = s.audit.Record(r.Context(), audit.Event{
			EventID: "deny:" + u.ID + ":" + r.URL.Path + ":" + r.Method,
			Type:    audit.EventAccessDenied, OccurredAt: time.Now(), Principal: u.ID,
			SessionID: sess.ID,
			Details: map[string]string{"path": r.URL.Path, "action": r.Method,
				"reason": string(result.DenyReason), "rule": result.MatchedRule},
		})
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":        "access denied",
			"reason":       string(result.DenyReason),
			"matched_rule": result.MatchedRule,
			"echo":         csrf.Sanitize(r.URL.Query().Get("echo")),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"resource": csrf.Sanitize(r.URL.Path),
		"viewer":   u.ID,
		"echo":     csrf.Sanitize(r.URL.Query().Get("echo")),
	})
}
