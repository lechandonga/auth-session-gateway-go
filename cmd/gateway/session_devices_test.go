package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
)

func loginClientWithUA(t *testing.T, h http.Handler, user, ua string) *clientState {
	t.Helper()
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, user+"-pass")
	req, _ := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("User-Agent", ua)
	req.RemoteAddr = "198.51.100.10:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %s (%s): %d %s", user, ua, rec.Code, rec.Body.String())
	}
	out := map[string]any{}
	_ = recJSON(rec, out)
	c := &clientState{}
	c.fromCookies(rec.Result().Cookies(), out)
	c.ua = ua
	return c
}

func recJSON(rec *httptest.ResponseRecorder, out map[string]any) error {
	return json.Unmarshal(rec.Body.Bytes(), &out)
}

func (c *clientState) sessionIDFromList(t *testing.T, h http.Handler) string {
	t.Helper()
	st, out, _ := do(t, h, http.MethodGet, "/sessions", c, false)
	if st != http.StatusOK {
		t.Fatalf("list: %d %v", st, out)
	}
	list, _ := out["sessions"].([]any)
	for _, it := range list {
		m := it.(map[string]any)
		if m["user_agent"] == c.ua {
			return m["session_id"].(string)
		}
	}
	t.Fatalf("session for ua=%q not found in %v", c.ua, list)
	return ""
}

// Listing, targeted revoke, ownership isolation, not-found and idempotency.
func TestHTTPSessionsListAndTargetedRevoke(t *testing.T) {
	app := buildApp(t)
	h := app.h
	a1 := loginClientWithUA(t, h, "alice", "alice-browser-1")
	a2 := loginClientWithUA(t, h, "alice", "alice-mobile-2")
	b1 := loginClientWithUA(t, h, "bob", "bob-browser")

	status, out, _ := do(t, h, http.MethodGet, "/sessions", a1, false)
	if status != http.StatusOK {
		t.Fatalf("list sessions = %d %v", status, out)
	}
	list, _ := out["sessions"].([]any)
	if len(list) != 2 {
		t.Fatalf("alice sessions = %d want 2", len(list))
	}
	var foundUA bool
	for _, it := range list {
		m := it.(map[string]any)
		if m["user_agent"] == "alice-mobile-2" {
			foundUA = true
		}
		for _, k := range []string{"created_at", "last_active_at", "idle_expires_at", "absolute_expires_at", "peer"} {
			if m[k] == "" || m[k] == nil {
				t.Fatalf("session field %s missing: %v", k, m)
			}
		}
	}
	if !foundUA {
		t.Fatal("device marker not visible")
	}
	t.Log("input=GET /sessions basis=own active sessions rule=2 devices, timestamps+peer+ua present")

	// Bob attacks Alice's session: forbidden, distinct from not-found.
	aliceTarget := a1.sessionIDFromList(t, h)
	status, out, _ = do(t, h, http.MethodPost, "/sessions/"+aliceTarget, b1, true)
	if status != http.StatusForbidden || out["code"] != "session_forbidden" {
		t.Fatalf("cross-user revoke = %d %v want 403 session_forbidden", status, out)
	}
	events, _ := app.sink.List(nil)
	if n := countEventTypes(events, audit.EventSessionRevokeDenied); n != 1 {
		t.Fatalf("revoke_denied events = %d want 1", n)
	}
	if st, _, _ := do(t, h, http.MethodGet, "/docs/r1", a1, false); st != http.StatusOK {
		t.Fatal("forbidden revoke must not touch the victim session")
	}
	t.Log("input=bob revokes alice basis=owner check rule=403 session_forbidden + audit; victim alive")

	status, out, _ = do(t, h, http.MethodPost, "/sessions/does-not-exist", a1, true)
	if status != http.StatusNotFound || out["code"] != "session_not_found" {
		t.Fatalf("missing revoke = %d %v want 404", status, out)
	}

	target2 := a2.sessionIDFromList(t, h)
	status, out, _ = do(t, h, http.MethodPost, "/sessions/"+target2, a1, true)
	if status != http.StatusOK || out["revoked"] != true {
		t.Fatalf("targeted revoke = %d %v", status, out)
	}
	events, _ = app.sink.List(nil)
	if n := countEventTypes(events, audit.EventSessionRevoked); n != 1 {
		t.Fatalf("session_revoked events = %d want 1", n)
	}
	// Repeated report: idempotent, distinct 410, no second audit/count.
	status, out, _ = do(t, h, http.MethodPost, "/sessions/"+target2, a1, true)
	if status != http.StatusGone || out["code"] != "already_inactive" {
		t.Fatalf("repeat revoke = %d %v want 410", status, out)
	}
	events, _ = app.sink.List(nil)
	if n := countEventTypes(events, audit.EventSessionRevoked); n != 1 {
		t.Fatalf("duplicate revoke re-audited: %d want 1", n)
	}
	if st, _, _ := do(t, h, http.MethodGet, "/docs/r1", a2, false); st != http.StatusUnauthorized {
		t.Fatalf("revoked device GET = %d want 401", st)
	}
	if st, _, _ := do(t, h, http.MethodPost, "/refresh", a2, true); st != http.StatusUnauthorized {
		t.Fatalf("revoked device refresh = %d want 401", st)
	}
	if st, _, _ := do(t, h, http.MethodGet, "/docs/r1", a1, false); st != http.StatusOK {
		t.Fatalf("sibling device affected: %d", st)
	}
	if st, _, _ := do(t, h, http.MethodGet, "/docs/r1", b1, false); st != http.StatusOK {
		t.Fatalf("other user affected: %d", st)
	}
	status, out, _ = do(t, h, http.MethodGet, "/sessions", a1, false)
	list, _ = out["sessions"].([]any)
	if status != http.StatusOK || len(list) != 1 {
		t.Fatalf("alice sessions after revoke = %d %v", len(list), out)
	}
	t.Log("input=own revoke then repeat + sibling checks basis=idempotency+isolation rule=200/410, others live")
}

// Per-user cap evicts the least-recently-active session deterministically,
// kills its credentials immediately and audits exactly one eviction.
func TestHTTPCapacityEviction(t *testing.T) {
	app := buildAppOpts(t, session.Options{
		IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour, MaxPerUser: 2,
	})
	h := app.h
	oldest := loginClientWithUA(t, h, "alice", "ua-oldest")
	middle := loginClientWithUA(t, h, "alice", "ua-middle")

	// Drive activity so "middle" is more recently active than "oldest".
	app.set(app.now().Add(2 * time.Minute))
	if st, _, _ := do(t, h, http.MethodGet, "/docs/r1", middle, false); st != http.StatusOK {
		t.Fatal("middle activity failed")
	}
	app.set(app.now().Add(2 * time.Minute))
	// Third login must evict exactly the LRU session (oldest).
	newest := loginClientWithUA(t, h, "alice", "ua-newest")

	events, _ := app.sink.List(nil)
	if n := countEventTypes(events, audit.EventSessionEvicted); n != 1 {
		t.Fatalf("session_evicted events = %d want 1", n)
	}
	var evictedID string
	for _, e := range events {
		if e.Type == audit.EventSessionEvicted {
			evictedID = e.SessionID
			if e.Details["reason"] != string(session.RevokeEvicted) {
				t.Fatalf("eviction detail = %v", e.Details)
			}
		}
	}

	status, out, _ := do(t, h, http.MethodGet, "/sessions", newest, false)
	list, _ := out["sessions"].([]any)
	if status != http.StatusOK || len(list) != 2 {
		t.Fatalf("active sessions after eviction = %d %v", len(list), out)
	}
	for _, it := range list {
		id := it.(map[string]any)["session_id"].(string)
		if id == evictedID {
			t.Fatal("evicted session still listed")
		}
	}
	// Evicted credentials die immediately (access + refresh).
	if st, out2, _ := do(t, h, http.MethodGet, "/docs/r1", oldest, false); st != http.StatusUnauthorized {
		t.Fatalf("evicted access status=%d body=%v", st, out2)
	}
	if st, out2, _ := do(t, h, http.MethodPost, "/refresh", oldest, true); st != http.StatusUnauthorized {
		t.Fatalf("evicted refresh status=%d body=%v", st, out2)
	} else if out2["code"] != "session_revoked" {
		t.Fatalf("evicted refresh code=%v want session_revoked", out2["code"])
	}
	// Survivors stay usable.
	if st, _, _ := do(t, h, http.MethodGet, "/docs/r1", middle, false); st != http.StatusOK {
		t.Fatalf("middle should survive: %d", st)
	}
	if st, _, _ := do(t, h, http.MethodGet, "/docs/r1", newest, false); st != http.StatusOK {
		t.Fatalf("newest should be active: %d", st)
	}
	t.Logf("input=3rd login cap=2 basis=LastActiveAt LRU rule=evicted %s only; its cookies 401, survivors 200", evictedID)
}
