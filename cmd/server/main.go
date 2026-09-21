// Command server runs the auth/session gateway with in-memory storage and a
// seeded demo tenant. All state is local; restart resets it.
//
// Demo accounts (username / password / roles):
//
//	alice / alice-pw / member
//	bob   / bob-pw   / editor
//
// Listen address defaults to :8080 (override with ASG_ADDR).
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/auth"
	"github.com/lechandonga/auth-session-gateway-go/internal/authz"
	"github.com/lechandonga/auth-session-gateway-go/internal/gateway"
	"github.com/lechandonga/auth-session-gateway-go/internal/model"
	"github.com/lechandonga/auth-session-gateway-go/internal/security"
	"github.com/lechandonga/auth-session-gateway-go/internal/session"
	"github.com/lechandonga/auth-session-gateway-go/internal/store"
)

func seedUser(users *store.UserStore, id, name, pw string, roles []string, attrs map[string]string) {
	salt := auth.NewSalt()
	u := &model.User{
		ID: id, Username: name, Salt: salt,
		PasswordHash: auth.HashPassword(salt, pw),
		Roles:        roles, Attributes: attrs,
	}
	if err := users.Create(u); err != nil {
		log.Fatalf("seed user %s: %v", name, err)
	}
}

func main() {
	now := time.Now()

	// --- storage (all in-memory, concurrency-safe) ---
	users := store.NewUserStore()
	locks := store.NewLockoutStore()
	sessions := store.NewSessionStore()
	refresh := store.NewRefreshStore()
	aud := audit.NewLogger()

	seedUser(users, "u-alice", "alice", "alice-pw", []string{"member"}, map[string]string{"tenant": "acme"})
	seedUser(users, "u-bob", "bob", "bob-pw", []string{"editor"}, map[string]string{"tenant": "acme"})

	// --- signing keys: two seeded, k1 active; k2 is rotated in via API-less
	// startup option later. Here only k1 exists. ---
	ring := security.NewKeyRing()
	if err := ring.AddKey(&security.SigningKey{
		KID: "k1", Secret: []byte("demo-active-key-0001"),
		Status: security.KeyActive, CreatedAt: now,
	}, true); err != nil {
		log.Fatalf("seed key: %v", err)
	}
	tokens := security.NewTokenService(ring)

	// --- services ---
	rl := auth.NewRateLimiter(60, time.Minute)
	authn := auth.NewAuthenticator(users, locks, aud, auth.Policy{
		MaxFailures: 5, FailWindow: 15 * time.Minute, LockDuration: 30 * time.Minute,
	}, rl)
	mgr := session.NewManager(sessions, refresh, tokens, aud, session.DefaultConfig())
	csrf := security.NewCSRFProtector()

	engine := authz.NewEngine([]model.Policy{
		{ID: "docs-read", Effect: model.EffectAllow, Roles: []string{"member", "editor", "admin"},
			Actions: []string{"GET"}, Resource: "docs/*", Scopes: []string{"docs:read"}},
		{ID: "docs-write", Effect: model.EffectAllow, Roles: []string{"editor", "admin"},
			Actions: []string{"POST", "PUT", "DELETE"}, Resource: "docs/*", Scopes: []string{"docs:write"}},
		{ID: "sealed", Effect: model.EffectDeny, Resource: "docs/sealed/*"},
		{ID: "billing-acme", Effect: model.EffectAllow, Roles: []string{"member", "editor"},
			Actions: []string{"GET"}, Resource: "billing/*", AttrMatch: map[string]string{"tenant": "acme"}},
		{ID: "admin-all", Effect: model.EffectAllow, Roles: []string{"admin"},
			Actions: []string{"GET", "POST", "PUT", "DELETE"}, Resource: "*"},
	})

	srv := gateway.New(gateway.Deps{
		Auth: authn, Sess: mgr, Engine: engine, CSRF: csrf, Aud: aud,
	})

	addr := ":8080"
	if v := envOr("ASG_ADDR", ""); v != "" {
		addr = v
	}
	log.Printf("auth-session-gateway listening on %s (demo users: alice/alice-pw, bob/bob-pw)", addr)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	// Avoid importing os solely for this in older layouts; keep it simple.
	return getenv(k, def)
}
