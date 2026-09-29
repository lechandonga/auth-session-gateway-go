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
	mgr := session.NewManager(store, 30*time.Minute, 24*time.Hour, 5)

	svc := auth.NewService(auth.Config{
		Users: users, Sessions: mgr, Signer: signer, Limiter: limiter,
		Audit: sink, AccessTTL: 15 * time.Minute, RefreshTTL: 24 * time.Hour,
		IdleTTL: 30 * time.Minute, AbsoluteTTL: 24 * time.Hour, MaxSessions: 5, Clock: now,
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
	srv := &server{svc: svc, engine: engine, audit: sink, csrf: prot, keys: kr, log: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/login", srv.login)
	mux.HandleFunc("/refresh", srv.refresh)
	mux.HandleFunc("/logout", srv.logout)
	mux.HandleFunc("/sessions", srv.sessions)
	mux.HandleFunc("/sessions/revoke", srv.revokeSession)
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
	Label    string `json:"label"`
}

const refreshCookieName = "refresh_token"

func (s *server) setSessionCookies(w http.ResponseWriter, tok *auth.LoginTokens, csrfTok string) {
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: tok.AccessToken,
		Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.SetCookie(w, &http.Cookie{Name: refreshCookieName, Value: tok.RefreshToken,
		Path: "/refresh", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	if csrfTok != "" {
		http.SetCookie(w, &http.Cookie{Name: s.csrf.CookieName(), Value: csrfTok,
			Path: "/", HttpOnly: false, SameSite: http.SameSiteStrictMode})
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
	tok, err := s.svc.LoginWithLabel(r.Context(), req.Username, req.Password,
		r.RemoteAddr, req.Label)
	if err != nil {
		s.log.Printf("login input={user:%q peer:%q} decision=deny basis=%q password=%s",
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
	// Issue the double-submit CSRF cookie alongside the session cookie.
	csrfTok, _ := s.csrf.GenerateToken()
	s.setSessionCookies(w, tok, csrfTok)
	s.log.Printf("login input={user:%q label:%q} decision=allow basis=credentials+policy session=%s key=%s refresh=%s",
		csrf.Sanitize(req.Username), csrf.Sanitize(req.Label), tok.SessionID, tok.KeyID,
		csrf.Mask("token", tok.RefreshToken))
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":        tok.SessionID,
		"key_id":            tok.KeyID,
		"expires_at":        tok.ExpiresAt,
		"idle_deadline":     tok.IdleDeadline,
		"absolute_deadline": tok.AbsoluteDeadline,
		"csrf_token":        csrfTok,
	})
}

func (s *server) extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("access_token"); err == nil {
		return c.Value
	}
	return ""
}

func (s *server) refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// State-changing entry: CSRF double-submit is enforced before the
	// refresh credential is inspected, so a CSRF rejection can never be
	// classified as credential reuse and can never touch a live session.
	if status, errResp := s.requireCSRF(r); status != 0 {
		s.log.Printf("refresh input={cookie:%s} decision=deny basis=%q rule=csrf_precheck",
			csrf.Mask("token", r.Header.Get("X-CSRF-Token")), errResp["error"])
		writeJSON(w, status, errResp)
		return
	}
	c, err := r.Cookie(refreshCookieName)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing refresh credential"})
		return
	}
	tok, err := s.svc.Refresh(r.Context(), c.Value)
	if err != nil {
		s.log.Printf("refresh input={refresh:%s} decision=deny basis=%q",
			csrf.Mask("token", c.Value), err.Error())
		writeJSON(w, refreshErrorStatus(err), map[string]string{"error": err.Error()})
		return
	}
	// Rotation delivers a brand-new pair; both cookies are overwritten
	// atomically in this single response. The real credential values go
	// ONLY to the client cookies — never into the body or logs.
	s.setSessionCookies(w, tok, "")
	s.log.Printf("refresh decision=allow basis=rotation session=%s key=%s new_access=%s new_refresh=%s",
		tok.SessionID, tok.KeyID, csrf.Mask("token", tok.AccessToken), csrf.Mask("token", tok.RefreshToken))
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id":        tok.SessionID,
		"key_id":            tok.KeyID,
		"expires_at":        tok.ExpiresAt,
		"idle_deadline":     tok.IdleDeadline,
		"absolute_deadline": tok.AbsoluteDeadline,
	})
}

func refreshErrorStatus(err error) int {
	switch {
	case errors.Is(err, session.ErrRefreshReused):
		return http.StatusConflict
	case errors.Is(err, auth.ErrSessionIdle):
		return http.StatusGone
	case errors.Is(err, auth.ErrSessionAbsolute):
		return http.StatusGone
	case errors.Is(err, auth.ErrSessionRevoked):
		return http.StatusUnauthorized
	default:
		return http.StatusUnauthorized
	}
}

// requireCSRF enforces the double-submit check on state-changing routes.
// Missing token (403 csrf: missing) and mismatched token (403 csrf:
// mismatch) stay distinguishable; it never consults session state.
func (s *server) requireCSRF(r *http.Request) (int, map[string]string) {
	csrfCookie, _ := r.Cookie(s.csrf.CookieName())
	cookieVal := ""
	if csrfCookie != nil {
		cookieVal = csrfCookie.Value
	}
	headerVal := r.Header.Get(s.csrf.HeaderName())
	if cookieVal == "" || headerVal == "" {
		return http.StatusForbidden, map[string]string{"error": csrf.ErrUnsafeMethod.Error()}
	}
	if err := s.csrf.Verify(cookieVal, headerVal); err != nil {
		return http.StatusForbidden, map[string]string{"error": err.Error()}
	}
	return 0, nil
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if status, errResp := s.requireCSRF(r); status != 0 {
		s.log.Printf("logout decision=deny basis=%q rule=csrf_precheck session_untouched", errResp["error"])
		writeJSON(w, status, errResp)
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
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", MaxAge: -1, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: refreshCookieName, Value: "", MaxAge: -1, Path: "/refresh"})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// sessions handles GET (list own active sessions) and POST
// /sessions/revoke (revoke one of the caller's own sessions).
func (s *server) sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	u, view, err := s.authenticateCookie(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	infos, err := s.svc.ListSessions(r.Context(), u.ID, view.ID, s.svc.ClockNow())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": infos})
}

func (s *server) revokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// CSRF gate first: a forged cross-site request must never reach the
	// ownership check nor mutate any session.
	if status, errResp := s.requireCSRF(r); status != 0 {
		s.log.Printf("sessions/revoke decision=deny basis=%q rule=csrf_precheck sessions_untouched", errResp["error"])
		writeJSON(w, status, errResp)
		return
	}
	u, _, err := s.authenticateCookie(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if dErr := json.NewDecoder(r.Body).Decode(&req); dErr != nil || req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}
	if err := s.svc.RevokeSession(r.Context(), u.ID, req.SessionID, s.svc.ClockNow()); err != nil {
		s.log.Printf("sessions/revoke input={actor:%s target:%s} decision=deny basis=%q",
			u.ID, csrf.Sanitize(req.SessionID), err.Error())
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, auth.ErrNotOwner):
			status = http.StatusForbidden
		case errors.Is(err, auth.ErrSessionNotFound):
			status = http.StatusNotFound
		case errors.Is(err, auth.ErrSessionIdle), errors.Is(err, auth.ErrSessionAbsolute):
			status = http.StatusGone
		case errors.Is(err, auth.ErrSessionRevoked):
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	s.log.Printf("sessions/revoke input={actor:%s target:%s} decision=allow basis=owner+active rule=single session revoked",
		u.ID, csrf.Sanitize(req.SessionID))
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "session_id": req.SessionID})
}

func (s *server) authenticateCookie(r *http.Request) (*auth.User, *auth.SessionView, error) {
	tok := s.extractToken(r)
	if tok == "" {
		return nil, nil, errors.New("missing token")
	}
	return s.svc.Authenticate(r.Context(), tok)
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
	if _, cookieErr := r.Cookie("access_token"); cookieErr == nil && !csrf.SafeMethods[r.Method] {
		csrfCookie, _ := r.Cookie(s.csrf.CookieName())
		cookieVal := ""
		if csrfCookie != nil {
			cookieVal = csrfCookie.Value
		}
		if err := s.csrf.VerifyRequest(r.Method, cookieVal, r.Header.Get(s.csrf.HeaderName())); err != nil {
			s.log.Printf("csrf input={path:%s method:%s} decision=deny basis=%q", r.URL.Path, r.Method, err.Error())
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
	}
	tok := s.extractToken(r)
	if tok == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return
	}
	u, sess, err := s.svc.Authenticate(r.Context(), tok)
	if err != nil {
		s.log.Printf("authn input={path:%s} decision=deny basis=%q", r.URL.Path, err.Error())
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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
