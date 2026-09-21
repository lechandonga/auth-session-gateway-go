// Package gateway wires auth/session/authz/security into an HTTP server.
// Cookie-based sessions are protected by double-submit CSRF tokens on
// state-changing requests; all responses carry baseline security headers;
// untrusted input is sanitized on reflection and sensitive fields redacted.
package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/auth"
	"github.com/lechandonga/auth-session-gateway-go/internal/authz"
	"github.com/lechandonga/auth-session-gateway-go/internal/model"
	"github.com/lechandonga/auth-session-gateway-go/internal/security"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
)

const (
	cookieSession = "asg_sid"
	cookieRefresh = "asg_rt"
	headerCSRF    = "X-CSRF-Token"
)

type Deps struct {
	Auth   *auth.Authenticator
	Sess   *session.Manager
	Engine *authz.Engine
	CSRF   *security.CSRFProtector
	Aud    *audit.Logger
}

type Server struct{ deps Deps }

func New(d Deps) *Server { return &Server{deps: d} }

// Routes returns the wired mux:
//
//	POST /login           credential check, sets cookies
//	POST /refresh         rotates refresh token (CSRF-protected)
//	POST /logout          revokes session (CSRF-protected)
//	POST /access          evaluates an authz query for the bearer session
//	GET/POST /echo        reflects only sanitized input (CSRF on POST)
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.withHeaders(s.handleLogin))
	mux.HandleFunc("/refresh", s.withHeaders(s.handleRefresh))
	mux.HandleFunc("/logout", s.withHeaders(s.handleLogout))
	mux.HandleFunc("/access", s.withHeaders(s.handleAccess))
	mux.HandleFunc("/echo", s.withHeaders(s.handleEcho))
	return mux
}

// withHeaders applies baseline security headers to every response.
func (s *Server) withHeaders(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for k, v := range security.SafeHeaders() {
			w.Header().Set(k, v)
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	// Values have already passed through security.Sanitize where untrusted;
	// disable the encoder's automatic HTML escaping so the escaped entities
	// remain visible as intended (content-type is application/json, not HTML).
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		if i := strings.IndexByte(h, ','); i >= 0 {
			return strings.TrimSpace(h[:i])
		}
		return strings.TrimSpace(h)
	}
	return r.RemoteAddr
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginResp never contains the password or its hash; refresh token is
// delivered as HttpOnly cookie while the CSRF token is readable by JS by
// design (double-submit pattern).
type loginResp struct {
	OK          bool              `json:"ok"`
	Reason      string            `json:"reason,omitempty"`
	AccessToken string            `json:"access_token,omitempty"`
	CSRFToken   string            `json:"csrf_token,omitempty"`
	User        map[string]string `json:"user,omitempty"`
}

func (s *Server) setSessionCookies(w http.ResponseWriter, refresh, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieRefresh, Value: refresh, Path: "/refresh",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name: cookieSession, Value: sessionID, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: true,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed json"})
		return
	}
	out := s.deps.Auth.Login(req.Username, req.Password, clientIP(r))
	switch out.Result {
	case model.LoginOK:
		res, err := s.deps.Sess.Issue(out.User, s.deps.CSRF)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "issue failed"})
			return
		}
		s.setSessionCookies(w, res.RefreshToken, res.Session.ID)
		writeJSON(w, http.StatusOK, loginResp{
			OK: true, AccessToken: res.AccessToken, CSRFToken: res.CSRFToken,
			User: map[string]string{
				"id": out.User.ID, "username": security.Sanitize(out.User.Username),
			},
		})
	case model.LoginLocked:
		writeJSON(w, http.StatusLocked, map[string]string{"reason": string(out.Result), "retry_at": out.RetryAt.UTC().Format("2006-01-02T15:04:05Z")})
	case model.LoginRateLimited:
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"reason": string(out.Result), "retry_at": out.RetryAt.UTC().Format("2006-01-02T15:04:05Z")})
	case model.LoginUserDisabled:
		writeJSON(w, http.StatusForbidden, map[string]string{"reason": string(out.Result)})
	case model.LoginMissingInput:
		writeJSON(w, http.StatusBadRequest, map[string]string{"reason": string(out.Result)})
	default:
		// Bad credentials: same 401 shape for unknown user/wrong password.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"reason": string(out.Result), "failures": itoa(out.Failures)})
	}
}

// enforceCSRF validates the double-submit token against the session cookie.
// Returns false after writing the response.
func (s *Server) enforceCSRF(w http.ResponseWriter, r *http.Request) (sessionID string, ok bool) {
	c, err := r.Cookie(cookieSession)
	if err != nil || c.Value == "" {
		s.csrfReject(w, model.ErrCSRFTokenMissing, r)
		return "", false
	}
	tok := r.Header.Get(headerCSRF)
	if err := s.deps.CSRF.Validate(c.Value, tok); err != nil {
		s.csrfReject(w, err, r)
		return "", false
	}
	return c.Value, true
}

func (s *Server) csrfReject(w http.ResponseWriter, err error, r *http.Request) {
	reason := "csrf_invalid"
	if errors.Is(err, model.ErrCSRFTokenMissing) {
		reason = "csrf_missing"
	} else if errors.Is(err, model.ErrCSRFTokenMismatch) {
		reason = "csrf_mismatch"
	}
	s.deps.Aud.Record(model.AuditEvent{
		Type: model.EventCSRFRejected, Success: false, Reason: reason,
		Details: map[string]string{"path": r.URL.Path, "client_ip": clientIP(r)},
	})
	writeJSON(w, http.StatusForbidden, map[string]string{"reason": reason})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if _, ok := s.enforceCSRF(w, r); !ok {
		return
	}
	c, err := r.Cookie(cookieRefresh)
	if err != nil || c.Value == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"reason": "refresh_cookie_missing"})
		return
	}
	res := s.deps.Sess.Rotate(c.Value, nil)
	switch res.Verdict {
	case session.RefreshOK:
		s.setSessionCookies(w, res.NewRefresh, "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true", "access_token": res.NewAccess})
	case session.RefreshRotatedReuse:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"reason": string(res.Verdict), "detail": security.Sanitize(res.Reason)})
	case session.RefreshExpired:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"reason": string(res.Verdict)})
	default:
		writeJSON(w, http.StatusUnauthorized, map[string]string{"reason": string(res.Verdict)})
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	sid, ok := s.enforceCSRF(w, r)
	if !ok {
		return
	}
	if err := s.deps.Sess.Revoke(sid, "user logout"); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"reason": "no_session"})
		return
	}
	s.deps.CSRF.Invalidate(sid)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

type accessReq struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
}

// handleAccess validates the bearer access token, confirms live session state
// and asks the authz engine for a verdict. Denied verdicts are audited with
// the distinguishable reason; access token failure reasons are preserved.
func (s *Server) handleAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	// /access itself is a state-changing authenticated endpoint: require CSRF
	// when the caller rides on the cookie session.
	if _, err := r.Cookie(cookieSession); err == nil {
		if _, ok := s.enforceCSRF(w, r); !ok {
			return
		}
	}
	var req accessReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed json"})
		return
	}
	raw := bearer(r)
	if raw == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"reason": "missing_token"})
		return
	}
	claims, _, reason := s.deps.Sess.ValidateAccess(raw)
	if reason != model.TokenOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"reason": string(reason)})
		return
	}
	dec := s.deps.Engine.Decide(model.AuthzRequest{
		Subject:  claims.Sub,
		Roles:    claims.Roles,
		Scopes:   claims.Scopes,
		Attrs:    claims.Attrs,
		Resource: req.Resource,
		Action:   req.Action,
	})
	if dec.Decision == model.DecisionDeny {
		s.deps.Aud.Record(model.AuditEvent{
			Type: model.EventAccessDenied, Subject: claims.Sub, SessionID: claims.SessionID,
			Success: false, Reason: string(dec.Reason),
			Details: map[string]string{"resource": req.Resource, "action": req.Action, "matched": dec.PolicyID},
		})
		writeJSON(w, http.StatusForbidden, map[string]string{
			"reason":   string(dec.Reason),
			"resource": security.Sanitize(req.Resource),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true", "by": dec.PolicyID})
}

// handleEcho proves output encoding: user-controlled text is sanitized before
// reflection; POST requires CSRF.
func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if _, ok := s.enforceCSRF(w, r); !ok {
			return
		}
	} else if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	raw := r.URL.Query().Get("q")
	writeJSON(w, http.StatusOK, map[string]string{"echo": security.Sanitize(raw)})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
