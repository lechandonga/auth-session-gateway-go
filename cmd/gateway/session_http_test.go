package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
)

// hclient is a tiny cookie-aware HTTP client against the in-process handler.
type hclient struct {
	t       *testing.T
	h       http.Handler
	cookies map[string]string
}

func newClient(t *testing.T, h http.Handler) *hclient {
	return &hclient{t: t, h: h, cookies: map[string]string{}}
}

func (c *hclient) do(method, target, body string, csrf bool) (int, map[string]any, []*http.Cookie) {
	c.t.Helper()
	req, _ := http.NewRequest(method, target, strings.NewReader(body))
	for name, val := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: val})
	}
	if csrf {
		req.Header.Set("X-CSRF-Token", c.cookies["csrf_token"])
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck.Value
		}
	}
	return rec.Code, out, rec.Result().Cookies()
}

func (c *hclient) login(username, password, label string) (int, map[string]any) {
	c.t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"`
	if label != "" {
		body += `,"label":"` + label + `"`
	}
	body += "}"
	status, out, _ := c.do(http.MethodPost, "/login", body, false)
	return status, out
}

// TestHTTPRefreshRotationEndToEnd drives the complete chain over real HTTP:
// login -> cookies (refresh never in body) -> refresh rotates both cookies ->
// new access token reads a protected resource -> old refresh rejected as
// reuse -> the whole login chain is dead.
func TestHTTPRefreshRotationEndToEnd(t *testing.T) {
	h, _, sink := buildApp(t)
	c := newClient(t, h)

	status, out := c.login("alice", "alice-pass", "")
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if _, leaked := out["refresh_token"]; leaked {
		t.Fatalf("refresh credential must not be in response body: %v", out)
	}
	if c.cookies["access_token"] == "" || c.cookies["refresh_token"] == "" || c.cookies["csrf_token"] == "" {
		t.Fatalf("missing cookies: %v", c.cookies)
	}
	oldRefresh := c.cookies["refresh_token"]
	t.Log("input=login basis=credentials rule=200; access/refresh HttpOnly cookies set, body has no refresh_token")

	// Refresh requires CSRF: missing token is rejected before credential use.
	status, out, _ = c.do(http.MethodPost, "/refresh", "", false)
	if status != http.StatusForbidden || !strings.Contains(out["error"].(string), "csrf") {
		t.Fatalf("refresh without csrf status=%d body=%v", status, out)
	}
	t.Logf("input=refresh no CSRF basis=double-submit precheck rule=403 %q (session untouched)", out["error"])

	// Successful rotation: both cookies rotate in one response.
	status, out, _ = c.do(http.MethodPost, "/refresh", "", true)
	if status != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", status, out)
	}
	if _, leaked := out["refresh_token"]; leaked {
		t.Fatal("new refresh must not be in body")
	}
	newAccess, newRefresh := c.cookies["access_token"], c.cookies["refresh_token"]
	if newAccess == "" || newRefresh == "" || newRefresh == oldRefresh {
		t.Fatalf("refresh credential must rotate; access cookie present=%v refreshChanged=%v",
			newAccess != "", newRefresh != oldRefresh)
	}
	t.Logf("input=refresh with cookie+CSRF basis=valid current refresh rule=200, refresh cookie rotated=%v (access cookie replaced)",
		newRefresh != oldRefresh)

	// The NEW access token immediately works on a protected resource.
	status, out, _ = c.do(http.MethodGet, "/docs/r1", "", false)
	if status != http.StatusOK {
		t.Fatalf("new access token read status=%d body=%v", status, out)
	}
	t.Log("input=GET /docs/r1 with rotated access token basis=viewer-read rule=200")

	// Replay the OLD refresh credential: 409 reuse, family-wide invalidation.
	replay := newClient(t, h)
	replay.cookies["refresh_token"] = oldRefresh
	replay.cookies["csrf_token"] = c.cookies["csrf_token"]
	status, out, _ = replay.do(http.MethodPost, "/refresh", "", true)
	if status != http.StatusConflict || out["error"].(string) != session.ErrRefreshReused.Error() {
		t.Fatalf("replay status=%d body=%v want 409 reuse", status, out)
	}
	t.Logf("input=POST /refresh with old credential basis=Rotated marker rule=409 %q + family kill", out["error"])

	// The current refresh credential now also fails (chain collateral), and
	// the new access token is rejected too.
	status, out, _ = c.do(http.MethodPost, "/refresh", "", true)
	if status != http.StatusUnauthorized {
		t.Fatalf("current refresh after reuse status=%d body=%v", status, out)
	}
	status, out, _ = c.do(http.MethodGet, "/docs/r1", "", false)
	if status != http.StatusUnauthorized {
		t.Fatalf("access after family kill status=%d body=%v", status, out)
	}
	t.Log("input=current refresh + access after detected reuse basis=family revoked rule=both refused, no silent pass")

	// Exactly one reuse audit event; it must not contain a raw token.
	reuses := 0
	evs, _ := sink.List(nil)
	for _, e := range evs {
		if e.Type == audit.EventRefreshReuse {
			reuses++
			if v := e.Details["token"]; v != "***REDACTED***" {
				t.Fatalf("raw token leaked into audit: %q", v)
			}
		}
	}
	if reuses != 1 {
		t.Fatalf("reuse events=%d want 1", reuses)
	}
}

// TestHTTPCSRFFailureDoesNotHarmSession proves CSRF rejections never count
// as reuse nor revoke a healthy session.
func TestHTTPCSRFFailureDoesNotHarmSession(t *testing.T) {
	h, _, _ := buildApp(t)
	c := newClient(t, h)
	if status, out := c.login("alice", "alice-pass", ""); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}

	// Mismatched token on refresh: distinct mismatch message, no mutation.
	req, _ := http.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: c.cookies["refresh_token"]})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: c.cookies["csrf_token"]})
	req.Header.Set("X-CSRF-Token", "wrong-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "mismatch") {
		t.Fatalf("mismatch = %d %s", rec.Code, rec.Body.String())
	}

	// Logout with missing CSRF token: session survives.
	status, _, _ := c.do(http.MethodPost, "/logout", "", false)
	if status != http.StatusForbidden {
		t.Fatalf("logout no-csrf status=%d want 403", status)
	}
	status, _, _ = c.do(http.MethodGet, "/docs/r1", "", false)
	if status != http.StatusOK {
		t.Fatalf("session after CSRF-blocked logout status=%d want 200 (not revoked)", status)
	}
	// The refresh credential was never consumed, so rotation still works.
	status, _, _ = c.do(http.MethodPost, "/refresh", "", true)
	if status != http.StatusOK {
		t.Fatalf("refresh after blocked logout status=%d want 200 (not reuse)", status)
	}
	t.Log("input=refresh mismatch + logout missing basis=CSRF precheck before state rule=403 distinct, session & credential intact")
}

// TestHTTPSessionListRevokeIsolation covers multi-device listing, targeted
// revocation isolation and the not-found vs not-owner distinction over HTTP.
func TestHTTPSessionListRevokeIsolation(t *testing.T) {
	h, _, sink := buildApp(t)
	laptop := newClient(t, h)
	if status, out := laptop.login("alice", "alice-pass", "alice-laptop"); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}
	phone := newClient(t, h)
	if status, out := phone.login("alice", "alice-pass", "alice-phone"); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}
	bob := newClient(t, h)
	if status, out := bob.login("bob", "bob-pass", ""); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}

	status, out, _ := laptop.do(http.MethodGet, "/sessions", "", false)
	if status != http.StatusOK {
		t.Fatalf("list status=%d %v", status, out)
	}
	items := out["sessions"].([]any)
	if len(items) != 2 {
		t.Fatalf("sessions = %d want 2", len(items))
	}
	labels := []string{}
	for _, it := range items {
		m := it.(map[string]any)
		labels = append(labels, m["label"].(string))
		if m["created_at"] == nil || m["last_active_at"] == nil || m["label"] == "" {
			t.Fatalf("session view missing markers: %v", m)
		}
	}
	t.Logf("input=GET /sessions basis=owner rule=2 devices with created/last_active/label=%v", labels)

	var laptopSID, phoneSID string
	for _, it := range items {
		m := it.(map[string]any)
		if cur, _ := m["current"].(bool); cur {
			laptopSID = m["session_id"].(string)
		} else {
			phoneSID = m["session_id"].(string)
		}
	}
	payload := func(sid string) string { return `{"session_id":"` + sid + `"}` }

	// Bob cannot revoke alice's session: 403 not-owner; nonexistent -> 404.
	status, out, _ = bob.do(http.MethodPost, "/sessions/revoke", payload(phoneSID), true)
	if status != http.StatusForbidden || !strings.Contains(out["error"].(string), "not the session owner") {
		t.Fatalf("cross-user revoke status=%d body=%v want 403", status, out)
	}
	status, out, _ = bob.do(http.MethodPost, "/sessions/revoke", payload("ghost-id"), true)
	if status != http.StatusNotFound {
		t.Fatalf("missing session status=%d body=%v want 404", status, out)
	}
	t.Log("input=bob revokes alice / ghost basis=ownership+existence rule=403 not-owner vs 404 not-found")

	// Laptop revokes itself; the phone is completely unaffected.
	status, _, _ = laptop.do(http.MethodPost, "/sessions/revoke", payload(laptopSID), true)
	if status != http.StatusOK {
		t.Fatalf("self revoke status=%d", status)
	}
	if status, _, _ := laptop.do(http.MethodGet, "/docs/r1", "", false); status != http.StatusUnauthorized {
		t.Fatalf("revoked laptop status=%d want 401", status)
	}
	if status, out, _ := phone.do(http.MethodGet, "/docs/r1", "", false); status != http.StatusOK {
		t.Fatalf("phone must stay live: status=%d body=%v", status, out)
	}
	status, out, _ = phone.do(http.MethodGet, "/sessions", "", false)
	if status != http.StatusOK || len(out["sessions"].([]any)) != 1 {
		t.Fatalf("phone session list after sibling revoke = %d %v", status, out)
	}

	// Audit: one revoke, two denied attempts; repeat revoke doesn't recount.
	repStatus, _, _ := laptop.do(http.MethodPost, "/sessions/revoke", payload(laptopSID), true)
	if repStatus != http.StatusConflict && repStatus != http.StatusUnauthorized {
		t.Fatalf("repeat revoke status=%d want 409/401", repStatus)
	}
	revokes, denied := 0, 0
	evs, _ := sink.List(nil)
	for _, e := range evs {
		switch e.Type {
		case audit.EventRevoke:
			revokes++
		case audit.EventRevokeDenied:
			denied++
		}
	}
	if revokes != 1 || denied != 2 {
		t.Fatalf("revokes=%d (want1) denied=%d (want2)", revokes, denied)
	}
	t.Logf("input=self revoke + repeat basis=single-session kill + idempotent EventID rule=phone isolated, audit revoke=%d denied=%d", revokes, denied)
}

// TestHTTPSessionCapacityEviction verifies LRU eviction over the login path:
// at the cap the longest-idle session is evicted with an audit event and
// immediately dead credentials.
func TestHTTPSessionCapacityEviction(t *testing.T) {
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	cur := base
	h, _, sink := buildAppAt(t, func() time.Time { return cur }, 2)

	old := newClient(t, h)
	if status, out := old.login("alice", "alice-pass", "old-device"); status != 200 {
		t.Fatalf("login1 %d %v", status, out)
	}
	cur = cur.Add(time.Minute)
	newer := newClient(t, h)
	if status, out := newer.login("alice", "alice-pass", "newer-device"); status != 200 {
		t.Fatalf("login2 %d %v", status, out)
	}
	cur = cur.Add(time.Minute)
	newest := newClient(t, h)
	if status, out := newest.login("alice", "alice-pass", "newest-device"); status != 200 {
		t.Fatalf("login3 %d %v", status, out)
	}

	// Oldest session's refresh credential is immediately dead.
	status, out, _ := old.do(http.MethodPost, "/refresh", "", true)
	if status != http.StatusUnauthorized {
		t.Fatalf("evicted refresh status=%d body=%v want 401", status, out)
	}
	status, _, _ = old.do(http.MethodGet, "/docs/r1", "", false)
	if status != http.StatusUnauthorized {
		t.Fatalf("evicted access status=%d want 401", status)
	}
	// Survivors keep working.
	if status, out, _ := newer.do(http.MethodGet, "/docs/r1", "", false); status != 200 {
		t.Fatalf("newer survivor %d %v", status, out)
	}
	if status, out, _ := newest.do(http.MethodGet, "/docs/r1", "", false); status != 200 {
		t.Fatalf("newest survivor %d %v", status, out)
	}
	evictions := 0
	evs, _ := sink.List(nil)
	for _, e := range evs {
		if e.Type == audit.EventSessionEvicted {
			evictions++
			if e.Details["reason"] != "capacity_eviction" {
				t.Fatalf("eviction reason = %q", e.Details["reason"])
			}
		}
	}
	if evictions != 1 {
		t.Fatalf("eviction events = %d want 1", evictions)
	}
	t.Log("input=3 logins cap=2 basis=LRU LastActiveAt rule=oldest evicted with audit, credentials dead instantly, survivors live")
}

// TestHTTPIdleAndAbsoluteBoundaries drives expiry distinctions through the
// HTTP refresh endpoint with a fully controlled clock.
func TestHTTPIdleAndAbsoluteBoundaries(t *testing.T) {
	base := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	cur := base
	h, _, _ := buildAppAt(t, func() time.Time { return cur }, 5)

	// Idle boundary: idle 10m, absolute 1h.
	c := newClient(t, h)
	if status, out := c.login("alice", "alice-pass", ""); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}
	cur = cur.Add(10 * time.Minute)
	status, out, _ := c.do(http.MethodPost, "/refresh", "", true)
	if status != http.StatusGone || !strings.Contains(out["error"].(string), "idle") {
		t.Fatalf("idle refresh status=%d body=%v want 410 idle", status, out)
	}
	t.Logf("input=refresh at idle deadline basis=IdleDeadline rule=410 %q", out["error"])

	// Refresh before idle slides the window but absolute cap still kills.
	cur = base
	c2 := newClient(t, h)
	if status, out := c2.login("alice", "alice-pass", ""); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}
	cur = cur.Add(9 * time.Minute)
	if status, out, _ := c2.do(http.MethodPost, "/refresh", "", true); status != 200 {
		t.Fatalf("sliding refresh %d %v", status, out)
	}
	cur = cur.Add(50 * time.Minute) // well past the idle slide but under abs
	// Current time is 10:59; the slide set idle to 10:19, so this is idle
	// again — jump straight to the absolute cap instead.
	cur = base.Add(60 * time.Minute)
	status, out, _ = c2.do(http.MethodPost, "/refresh", "", true)
	if status != http.StatusGone || !strings.Contains(out["error"].(string), "absolute") {
		t.Fatalf("absolute refresh status=%d body=%v want 410 absolute", status, out)
	}
	t.Logf("input=refresh at absolute cap basis=AbsoluteDeadline rule=410 %q (idle vs absolute distinct)", out["error"])
}

// TestHTTPConcurrentRefreshExactlyOneWinner submits the same refresh
// credential concurrently over real HTTP: exactly one 200, every loser is a
// 409 reuse, and the winner's old credential is dead afterwards.
func TestHTTPConcurrentRefreshExactlyOneWinner(t *testing.T) {
	h, _, sink := buildApp(t)
	c := newClient(t, h)
	if status, out := c.login("alice", "alice-pass", ""); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}
	sharedRefresh := c.cookies["refresh_token"]
	csrfTok := c.cookies["csrf_token"]

	const n = 16
	var wg sync.WaitGroup
	statuses := make(chan int, n)
	winners := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, "/refresh", nil)
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: sharedRefresh})
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
			req.Header.Set("X-CSRF-Token", csrfTok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			statuses <- rec.Code
			if rec.Code == http.StatusOK {
				for _, ck := range rec.Result().Cookies() {
					if ck.Name == "refresh_token" {
						winners <- ck.Value
					}
				}
			}
		}()
	}
	wg.Wait()
	close(statuses)
	close(winners)
	ok200, conflict409 := 0, 0
	for st := range statuses {
		switch st {
		case http.StatusOK:
			ok200++
		case http.StatusConflict:
			conflict409++
		default:
			t.Fatalf("unexpected concurrent status %d", st)
		}
	}
	if ok200 != 1 || conflict409 != n-1 {
		t.Fatalf("winners=%d reuseLosers=%d want 1 and %d", ok200, conflict409, n-1)
	}
	winRefresh := <-winners
	if winRefresh == "" || winRefresh == sharedRefresh {
		t.Fatal("winner must hold a distinct new refresh credential")
	}
	reuseEvents := 0
	evs, _ := sink.List(nil)
	for _, e := range evs {
		if e.Type == audit.EventRefreshReuse {
			reuseEvents++
		}
	}
	t.Logf("input=%d concurrent POST /refresh same credential basis=single critical section rule=1 winner(new credential), %d reuse-409; reuse audits=%d",
		n, conflict409, reuseEvents)
}

// TestHTTPRevokeVsRefreshAtomic interleaves revocation and rotation of the
// same session. In every ordering the outcome is consistent: a revoked
// session can never mint a new token, and a success leaves no usable old
// credential.
func TestHTTPRevokeVsRefreshAtomic(t *testing.T) {
	h, _, _ := buildApp(t)
	c := newClient(t, h)
	if status, out := c.login("alice", "alice-pass", ""); status != 200 {
		t.Fatalf("login %d %v", status, out)
	}

	const rounds = 20
	var wg sync.WaitGroup
	for i := 0; i < rounds; i++ {
		// Each round: fresh login, then race refresh vs targeted revoke.
		rc := newClient(t, h)
		if status, out := rc.login("alice", "alice-pass", "round"); status != 200 {
			t.Fatalf("round login %d %v", status, out)
		}
		sid := outSessionID(t, h, rc)
		rt := rc.cookies["refresh_token"]
		csrfTok := rc.cookies["csrf_token"]
		wg.Add(2)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, "/sessions/revoke",
				strings.NewReader(`{"session_id":"`+sid+`"}`))
			req.AddCookie(&http.Cookie{Name: "access_token", Value: rc.cookies["access_token"]})
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
			req.Header.Set("X-CSRF-Token", csrfTok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
		}()
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, "/refresh", nil)
			req.AddCookie(&http.Cookie{Name: "refresh_token", Value: rt})
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfTok})
			req.Header.Set("X-CSRF-Token", csrfTok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			// If refresh lost the race it must be 401/409, never 200 against
			// a revoked session.
			if rec.Code == http.StatusOK {
				// Winner: its old credential must now be dead.
				old := newClient(t, h)
				old.cookies["refresh_token"] = rt
				old.cookies["csrf_token"] = csrfTok
				st2, out2, _ := old.do(http.MethodPost, "/refresh", "", true)
				if st2 != http.StatusConflict {
					t.Errorf("old credential after winning rotate: status=%d body=%v want 409 reuse",
						st2, out2)
				}
			}
		}()
	}
	wg.Wait()
	t.Log("input=20 rounds of racing revoke vs refresh basis=store-wide mutex rule=no revoked-session token mint, no old token survives")
}

func outSessionID(t *testing.T, h http.Handler, c *hclient) string {
	t.Helper()
	status, out, _ := c.do(http.MethodGet, "/sessions", "", false)
	if status != http.StatusOK {
		t.Fatalf("list %d %v", status, out)
	}
	for _, it := range out["sessions"].([]any) {
		m := it.(map[string]any)
		if cur, _ := m["current"].(bool); cur {
			return m["session_id"].(string)
		}
	}
	t.Fatal("no current session in list")
	return ""
}

var _ = errors.Is
