package session

import (
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/model"
	"github.com/lechandonga/auth-session-gateway-go/internal/security"
	"github.com/lechandonga/auth-session-gateway-go/internal/store"
)

type harness struct {
	mgr   *Manager
	users *store.UserStore
	sess  *store.SessionStore
	refr  *store.RefreshStore
	ring  *security.KeyRing
	tok   *security.TokenService
	csrf  *security.CSRFProtector
	aud   *audit.Logger
	clk   *time.Time
}

func newHarness(t *testing.T, now time.Time) *harness {
	users := store.NewUserStore()
	sess := store.NewSessionStore()
	refr := store.NewRefreshStore()
	aud := audit.NewLogger()
	ring := security.NewKeyRing()
	if err := ring.AddKey(&security.SigningKey{KID: "k1", Secret: []byte("sek1"), Status: security.KeyActive, CreatedAt: now}, true); err != nil {
		t.Fatal(err)
	}
	tok := security.NewTokenService(ring).WithClock(func() time.Time { return now })
	mgr := NewManager(sess, refr, tok, aud, Config{
		AccessTokenTTL: time.Minute, RefreshTTL: time.Hour,
		IdleTimeout: 30 * time.Minute, AbsoluteTTL: 2 * time.Hour,
	})
	mgr.now = func() time.Time { return now }
	_ = users.Create(&model.User{ID: "u1", Username: "alice", Roles: []string{"member"}})
	return &harness{mgr: mgr, users: users, sess: sess, refr: refr, ring: ring, tok: tok, csrf: security.NewCSRFProtector(), aud: aud, clk: &now}
}

func (h *harness) user() *model.User {
	u, _ := h.users.Get("alice")
	return u
}

func TestIssueAndAccessValidation(t *testing.T) {
	h := newHarness(t, time.Unix(1000, 0))
	res, err := h.mgr.Issue(h.user(), h.csrf)
	if err != nil {
		t.Fatal(err)
	}
	if res.RefreshToken == "" || res.AccessToken == "" || res.CSRFToken == "" {
		t.Fatal("issue must return all tokens")
	}
	claims, sess, reason := h.mgr.ValidateAccess(res.AccessToken)
	if reason != model.TokenOK || claims.Sub != "u1" || sess.ID != res.Session.ID {
		t.Fatalf("validate: reason=%s claims=%+v sess=%+v", reason, claims, sess)
	}
	t.Log("INPUT 登录签发 -> 判定依据 签名有效+会话存活 -> 命中规则 放行 access/refresh/csrf 三件套")
}

func TestRotationChainAndReuseRevokesFamily(t *testing.T) {
	h := newHarness(t, time.Unix(1000, 0))
	res, _ := h.mgr.Issue(h.user(), h.csrf)
	rt1 := res.RefreshToken
	access1 := res.AccessToken

	// First rotation succeeds.
	r2 := h.mgr.Rotate(rt1, h.user())
	if r2.Verdict != RefreshOK || r2.NewRefresh == "" || r2.NewAccess == "" {
		t.Fatalf("rotate1: %+v", r2)
	}
	t.Log("INPUT rt1 首次轮换 -> 判定依据 MarkRotated CAS 获胜 -> 命中规则 签发同族后继 rt2")

	// The old access token still validates (short-lived, unexpired) but the
	// old refresh token can no longer be used: REUSE detected, family dies.
	if _, _, reason := h.mgr.ValidateAccess(access1); reason != model.TokenOK {
		t.Fatalf("access token should still validate until exp/revoke: %s", reason)
	}
	reuse := h.mgr.Rotate(rt1, h.user())
	if reuse.Verdict != RefreshRotatedReuse || reuse.RevokedFamily == "" {
		t.Fatalf("replay must be detected as reuse: %+v", reuse)
	}
	t.Logf("INPUT 已轮换的 rt1 被再次使用 -> 判定依据 Rotated=true -> 命中规则 reuse_detected 连带撤销家族 %s", reuse.RevokedFamily)

	// Everything in the family is now dead.
	if _, _, reason := h.mgr.ValidateAccess(access1); reason != model.TokenSessionRevoked {
		t.Fatalf("access after family revoke: %s", reason)
	}
	rt3 := h.mgr.Rotate(r2.NewRefresh, h.user())
	if rt3.Verdict != RefreshRevoked && rt3.Verdict != RefreshSessionDead {
		t.Fatalf("successor token must also be refused, got %+v", rt3)
	}
	t.Logf("INPUT 家族内后继 rt2 再用 -> 判定依据 Revoked=true -> 命中规则 %s 拒绝（不静默放行）", rt3.Verdict)

	// Audit: exactly one reuse event and a revoke event.
	if n := len(h.aud.ByType(model.EventRefreshReuse)); n != 1 {
		t.Fatalf("want 1 reuse event, got %d", n)
	}
	if n := len(h.aud.ByType(model.EventSessionRevoke)); n < 1 {
		t.Fatal("want session revoke event(s)")
	}
}

func TestRevokeIdempotentAndConcurrentRotate(t *testing.T) {
	h := newHarness(t, time.Unix(1000, 0))
	res, _ := h.mgr.Issue(h.user(), h.csrf)

	// Revoke then refresh -> refused.
	if err := h.mgr.Revoke(res.Session.ID, "user logout"); err != nil {
		t.Fatal(err)
	}
	r := h.mgr.Rotate(res.RefreshToken, h.user())
	if r.Verdict != RefreshSessionDead && r.Verdict != RefreshRevoked {
		t.Fatalf("refresh after revoke: %+v", r)
	}
	t.Logf("INPUT 撤销后使用 refresh -> 判定依据 session.Revoked -> 命中规则 %s", r.Verdict)

	// Duplicate revoke emits no second event.
	before := h.aud.Count()
	if err := h.mgr.Revoke(res.Session.ID, "user logout"); err != nil {
		t.Fatal(err)
	}
	if h.aud.Count() != before {
		t.Fatalf("idempotent revoke must not add events: %d -> %d", before, h.aud.Count())
	}

	// Fresh session: 50 concurrent rotations of the same token. Exactly one
	// may succeed; all others must see reuse and the family must end revoked.
	res2, _ := h.mgr.Issue(h.user(), h.csrf)
	var wg sync.WaitGroup
	results := make([]RefreshVerdict, 50)
	var wgmu sync.Mutex
	oks := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rr := h.mgr.Rotate(res2.RefreshToken, h.user())
			wgmu.Lock()
			results[i] = rr.Verdict
			if rr.Verdict == RefreshOK {
				oks++
			}
			wgmu.Unlock()
		}(i)
	}
	wg.Wait()
	if oks != 1 {
		t.Fatalf("exactly one rotation must win under concurrency, got %d", oks)
	}
	dist := map[RefreshVerdict]int{}
	for _, v := range results {
		dist[v]++
	}
	// Deterministic mutex-serialized outcome: exactly one winner; the first
	// loser observes reuse and revokes the family; every later loser sees the
	// already-revoked family. None silently succeed.
	if dist[RefreshRotatedReuse] != 1 {
		t.Fatalf("exactly one reuse observation expected, got %d (%v)", dist[RefreshRotatedReuse], dist)
	}
	if dist[RefreshOK]+dist[RefreshRotatedReuse]+dist[RefreshRevoked] != 50 {
		t.Fatalf("unexpected verdict distribution: %v", dist)
	}
	// Session/family ends revoked because the losers triggered reuse.
	sess, _ := h.sess.Get(res2.Session.ID)
	if !sess.Revoked {
		t.Fatal("family must be revoked after concurrent reuse observations")
	}
	if n := len(h.aud.ByType(model.EventRefreshReuse)); n != 1 {
		t.Fatalf("exactly one reuse audit event even with 49 observers, got %d", n)
	}
	t.Logf("INPUT 50 并发轮换同一 refresh -> 判定依据 管理器互斥+CAS+DedupKey -> 命中规则 成功=1 复用=1 已撤销=%d 家族撤销 复用事件=1", dist[RefreshRevoked])
}

func TestExpiredRefreshAndAbsoluteLifetime(t *testing.T) {
	now := time.Unix(1000, 0)
	h := newHarness(t, now)
	res, _ := h.mgr.Issue(h.user(), h.csrf)
	*h.clk = now.Add(2 * time.Hour) // beyond absolute TTL
	r := h.mgr.Rotate(res.RefreshToken, h.user())
	if r.Verdict != RefreshSessionDead {
		t.Fatalf("absolute expiry: %+v", r)
	}
	t.Logf("INPUT 超过绝对生命周期 -> 判定依据 now>AbsoluteExp -> 命中规则 %s", r.Verdict)
}

func TestSigningKeyRetiredDuringSession(t *testing.T) {
	now := time.Unix(1000, 0)
	h := newHarness(t, now)
	res, _ := h.mgr.Issue(h.user(), h.csrf)

	// Rotate signing key: current access token still verifies (retired k1).
	_ = h.ring.AddKey(&security.SigningKey{KID: "k2", Secret: []byte("sek2"), Status: security.KeyRetired, CreatedAt: now}, false)
	if _, err := h.ring.Rotate("k2", now); err != nil {
		t.Fatal(err)
	}
	if _, _, reason := h.mgr.ValidateAccess(res.AccessToken); reason != model.TokenOK {
		t.Fatalf("old access token under retired key: %s", reason)
	}
	// Rotation of refresh issues a new access token signed with k2.
	rr := h.mgr.Rotate(res.RefreshToken, h.user())
	if rr.Verdict != RefreshOK {
		t.Fatalf("rotate after key rotation: %+v", rr)
	}
	cl, reason, err := h.tok.Verify(rr.NewAccess)
	if err != nil {
		t.Fatalf("new access verify: %v %s", err, reason)
	}
	if cl.SigningKID != "k2" {
		t.Fatalf("new token must be signed by k2, got %s", cl.SigningKID)
	}
	t.Log("INPUT 签名密钥轮换期间刷新 -> 判定依据 旧键retired可校验/新键active签发 -> 命中规则 历史兼容且新令牌用 k2")
}

func TestMalformedToken(t *testing.T) {
	h := newHarness(t, time.Unix(1000, 0))
	for _, raw := range []string{"", "garbage", "v1.abc", "v1..", "v2.a.b"} {
		if _, _, reason := h.mgr.ValidateAccess(raw); reason != model.TokenMalformed {
			t.Fatalf("raw=%q reason=%s", raw, reason)
		}
	}
	t.Log("INPUT 畸形令牌 -> 命中规则 malformed 确定性拒绝")
}
