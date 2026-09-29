package main

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
)

func countEventTypes(events []audit.Event, ty audit.EventType) int {
	n := 0
	for _, e := range events {
		if e.Type == ty {
			n++
		}
	}
	return n
}

// Idle window: activity slides it; past it the rejection is the idle code.
func TestHTTPSessionIdleBoundary(t *testing.T) {
	app := buildAppOpts(t, session.Options{
		IdleTTL: 10 * time.Minute, AbsoluteTTL: time.Hour, MaxPerUser: 5,
	})
	h := app.h
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	app.set(t0)
	c := loginClient(t, h, "alice")

	app.set(t0.Add(9*time.Minute + 59*time.Second))
	status, out, cookies := do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusOK {
		t.Fatalf("refresh inside idle = %d %v", status, out)
	}
	c.fromCookies(cookies, out)
	t.Logf("input=refresh at idle-1s basis=within window rule=200 idle slides to %v", out["idle_expires_at"])

	app.set(t0.Add(20 * time.Minute))
	status, out, _ = do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusUnauthorized || out["code"] != "session_idle_expired" {
		t.Fatalf("refresh after idle = %d %v want 401 session_idle_expired", status, out)
	}
	status, out, _ = do(t, h, http.MethodGet, "/docs/r1", c, false)
	if status != http.StatusUnauthorized || out["code"] != "session_idle_expired" {
		t.Fatalf("GET after idle = %d %v", status, out)
	}
	t.Logf("input=refresh+GET past slid idle window basis=now>=IdleExpiresAt rule=401 code=%s", out["code"])
}

// Absolute cap: a continuously rotating session still dies at the cap.
func TestHTTPSessionAbsoluteBoundary(t *testing.T) {
	app := buildAppOpts(t, session.Options{
		IdleTTL: 10 * time.Minute, AbsoluteTTL: 30 * time.Minute, MaxPerUser: 5,
	})
	h := app.h
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	app.set(t0)
	c := loginClient(t, h, "alice")

	app.set(t0.Add(9 * time.Minute))
	status, out, cookies := do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusOK {
		t.Fatalf("rotate 1: %d %v", status, out)
	}
	c.fromCookies(cookies, out)
	app.set(t0.Add(18 * time.Minute))
	status, out, cookies = do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusOK {
		t.Fatalf("rotate 2: %d %v", status, out)
	}
	c.fromCookies(cookies, out)
	t.Log("input=rotations +9m/+18m basis=idle slides, absolute fixed +30m rule=200")

	app.set(t0.Add(30 * time.Minute))
	status, out, _ = do(t, h, http.MethodPost, "/refresh", c, true)
	if status != http.StatusUnauthorized || out["code"] != "session_absolute_expired" {
		t.Fatalf("refresh at absolute cap = %d %v want 401 session_absolute_expired", status, out)
	}
	t.Logf("input=refresh at +30m basis=now>=AbsoluteExpiresAt rule=401 code=%s", out["code"])
}

func TestHTTPConcurrentRefreshAuditAndRace(t *testing.T) {
	app := buildApp(t)
	h := app.h
	c := loginClient(t, h, "alice")
	const n = 16
	var wg sync.WaitGroup
	type res struct {
		status int
		code   string
	}
	results := make(chan res, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, body, _ := do(t, h, http.MethodPost, "/refresh", c, true)
			code, _ := body["code"].(string)
			results <- res{st, code}
		}()
	}
	wg.Wait()
	close(results)
	wins, reuses := 0, 0
	for r := range results {
		switch {
		case r.status == http.StatusOK:
			wins++
		case r.code == "refresh_reuse":
			reuses++
		default:
			t.Fatalf("unexpected concurrent result %+v", r)
		}
	}
	if wins != 1 || reuses != n-1 {
		t.Fatalf("wins=%d reuses=%d want 1/%d", wins, reuses, n-1)
	}
	events, _ := app.sink.List(nil)
	if got := countEventTypes(events, audit.EventRefreshReuse); got != 1 {
		t.Fatalf("refresh_reuse audit = %d want 1 (family kill fires once)", got)
	}
	t.Logf("input=%d concurrent refreshes basis=single critical section rule=1 win %d reuse, one family-kill audit", n, reuses)
}

// Revocation racing rotation over many iterations: never observe a revoked
// session that still mints new usable tokens.
func TestHTTPRevokeRacesRefresh(t *testing.T) {
	app := buildApp(t)
	h := app.h
	for iter := 0; iter < 30; iter++ {
		c := loginClient(t, h, "alice")
		snapshot := &clientState{access: c.access, refresh: c.refresh, csrf: c.csrf}
		var wg sync.WaitGroup
		var mu sync.Mutex
		refreshOK := false
		var refreshStatus int
		winner := &clientState{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			st, _, cookies := do(t, h, http.MethodPost, "/refresh", snapshot, true)
			mu.Lock()
			refreshStatus = st
			if st == http.StatusOK {
				refreshOK = true
				winner.fromCookies(cookies, map[string]any{})
			}
			mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			_, _, _ = do(t, h, http.MethodPost, "/logout", snapshot, true)
		}()
		wg.Wait()

		if refreshOK {
			st, body, _ := do(t, h, http.MethodPost, "/refresh", winner, true)
			if st == http.StatusOK {
				t.Fatalf("iter %d: revoked family but new refresh works: %v", iter, body)
			}
			st, _, _ = do(t, h, http.MethodGet, "/docs/r1", winner, false)
			if st != http.StatusUnauthorized {
				t.Fatalf("iter %d: new access works after race: %d", iter, st)
			}
		} else if refreshStatus != http.StatusUnauthorized {
			t.Fatalf("iter %d: losing refresh status=%d want 401", iter, refreshStatus)
		}
		st, _, _ := do(t, h, http.MethodGet, "/docs/r1", snapshot, false)
		if st != http.StatusUnauthorized {
			t.Fatalf("iter %d: access works after race: %d", iter, st)
		}
	}
	t.Log("input=30x refresh||logout races basis=compound ops under one store lock rule=no revoked-but-usable state")
}
