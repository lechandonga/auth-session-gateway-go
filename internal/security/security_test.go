package security

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

func mkKey(kid string, status KeyStatus) *SigningKey {
	return &SigningKey{KID: kid, Secret: []byte("secret-" + kid), Status: status, CreatedAt: time.Unix(1, 0)}
}

func TestKeyRingRotationAndHistory(t *testing.T) {
	ring := NewKeyRing()
	k1 := mkKey("k1", KeyActive)
	if err := ring.AddKey(k1, true); err != nil {
		t.Fatalf("add k1: %v", err)
	}
	ts := NewTokenService(ring).WithClock(func() time.Time { return time.Unix(1000, 0) })
	now := time.Unix(1000, 0)

	c1 := model.AccessClaims{JTI: "t1", Sub: "u1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	raw1, err := ts.Sign(c1)
	if err != nil {
		t.Fatalf("sign with k1: %v", err)
	}

	// Add second key without activating: signing still uses k1.
	if err := ring.AddKey(mkKey("k2", KeyRetired), false); err != nil {
		t.Fatalf("add k2 retired: %v", err)
	}
	if cur, _ := ring.Current(); cur.KID != "k1" {
		t.Fatalf("expected current k1, got %s", cur.KID)
	}

	// Overlap: trying to activate k2 via AddKey while k1 active must fail.
	err = ring.AddKey(mkKey("k2", KeyActive), true)
	if !errors.Is(err, model.ErrOverlappingKeys) {
		t.Fatalf("expected overlap error, got %v", err)
	}
	t.Logf("INPUT add active k2 with k1 already active -> 判定依据: 唯一活跃键不变式 -> 命中规则 ErrOverlappingKeys (%v)", err)

	// Rotate: k2 active, k1 retired. Old token still verifies (history compat);
	// new tokens are signed with k2.
	k2new := mkKey("k2", KeyActive)
	// k2 exists as retired entry; Rotate promotes by kid.
	if _, err := ring.Rotate("k2", now); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	_ = k2new
	if cur, _ := ring.Current(); cur.KID != "k2" {
		t.Fatalf("expected current k2, got %s", cur.KID)
	}

	claims, reason, err := ts.Verify(raw1)
	if err != nil || reason != model.TokenOK || claims.SigningKID != "k1" {
		t.Fatalf("old token must verify after rotation: err=%v reason=%s claims=%+v", err, reason, claims)
	}
	t.Logf("INPUT 旧密钥 k1 签发的未过期令牌 -> 判定依据: ForVerify 接受 retired 键 -> 命中规则 历史兼容放行 (kid=%s)", claims.SigningKID)

	c2 := model.AccessClaims{JTI: "t2", Sub: "u1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	raw2, err := ts.Sign(c2)
	if err != nil {
		t.Fatalf("sign with k2: %v", err)
	}
	if cl, reason, err := ts.Verify(raw2); err != nil || cl.SigningKID != "k2" {
		t.Fatalf("new token verify: %v %s", err, reason)
	}
	t.Log("INPUT 轮换后新签发令牌 -> 命中规则: 仅活跃键可签名, kid=k2")

	// Tamper -> bad signature.
	tampered := raw2[:len(raw2)-2] + "AA"
	if _, reason, err := ts.Verify(tampered); !errors.Is(err, model.ErrBadSignature) || reason != model.TokenBadSignature {
		t.Fatalf("tampered token: err=%v reason=%s", err, reason)
	}
	t.Log("INPUT 篡改签名 -> 判定依据: HMAC 常量时间比较失败 -> 命中规则 bad_signature 拒绝")

	// Expired token signed by retired k1 -> reason expired (signature valid).
	cOld := model.AccessClaims{JTI: "t3", Sub: "u1", IssuedAt: now.Unix(), ExpiresAt: now.Add(-time.Second).Unix()}
	rawExp, err := ts.Sign(cOld)
	if err != nil {
		t.Fatalf("sign expired-shape token: %v", err)
	}
	if _, reason, err := ts.Verify(rawExp); !errors.Is(err, model.ErrTokenExpired) || reason != model.TokenExpired {
		t.Fatalf("expected expired, got %v %s", err, reason)
	}
	t.Log("INPUT 已过期令牌(签名合法) -> 命中规则: expired 与签名失败可区分")

	// Revoke k1: its tokens now reject as unknown_kid.
	if err := ring.RevokeKey("k1"); err != nil {
		t.Fatalf("revoke k1: %v", err)
	}
	if _, reason, err := ts.Verify(raw1); !errors.Is(err, model.ErrUnknownKID) || reason != model.TokenUnknownKID {
		t.Fatalf("revoked key token: %v %s", err, reason)
	}
	t.Log("INPUT 已撤销键 k1 的令牌 -> 命中规则: unknown_kid 拒绝（退役=可校验，撤销=不可校验）")
}

func TestRetiredKeyCannotSignAndMissingKey(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.AddKey(mkKey("k1", KeyActive), true); err != nil {
		t.Fatal(err)
	}
	if err := ring.Retire("k1", time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	_, err := ring.Current()
	if !errors.Is(err, model.ErrMissingKey) {
		t.Fatalf("retired-only ring Current: %v", err)
	}
	ts := NewTokenService(ring)
	if _, err := ts.Sign(model.AccessClaims{}); !errors.Is(err, model.ErrMissingKey) {
		t.Fatalf("sign with no active key: %v", err)
	}
	t.Log("INPUT: 退役唯一活跃键后签发 -> 判定依据 current=='' -> 命中规则 ErrMissingKey 确定性拒绝")
}

func TestRotateConcurrentNoHalfState(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey(mkKey("k1", KeyActive), true)
	_ = ring.AddKey(mkKey("k2", KeyRetired), false)
	now := time.Unix(5, 0)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = ring.Rotate("k2", now)
		}()
	}
	wg.Wait()
	cur, err := ring.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cur.KID != "k2" || cur.Status != KeyActive {
		t.Fatalf("unexpected current after concurrent rotation: %+v", cur)
	}
	snap := ring.Snapshot()
	statuses := map[string]KeyStatus{}
	for _, k := range snap {
		statuses[k.KID] = k.Status
	}
	if statuses["k1"] != KeyRetired || statuses["k2"] != KeyActive {
		t.Fatalf("expected k1 retired/k2 active, got %v", statuses)
	}
	t.Logf("INPUT 50 个并发 Rotate(k2) -> 判定依据 写锁内原子切换 -> 命中规则 无半更新: %v", statuses)
}

func TestCSRFAndSanitizeRedact(t *testing.T) {
	p := NewCSRFProtector()
	tok := p.Issue("sess1")
	if p.Validate("sess1", tok) != nil {
		t.Fatal("valid token rejected")
	}
	if err := p.Validate("sess1", ""); !errors.Is(err, model.ErrCSRFTokenMissing) {
		t.Fatalf("missing: %v", err)
	}
	if err := p.Validate("sess1", "wrong"); !errors.Is(err, model.ErrCSRFTokenMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	if err := p.Validate("sess2", tok); !errors.Is(err, model.ErrCSRFTokenMismatch) {
		t.Fatalf("cross-session token must fail: %v", err)
	}
	p.Invalidate("sess1")
	t.Log("INPUT 缺失/错误/跨会话 CSRF 令牌 -> 命中规则 missing 与 mismatch 分别拒绝")

	injected := `<script>alert('x')</script>"&/`
	got := Sanitize(injected)
	for _, bad := range []string{"<", ">", "'", "\"", "/", "&"} {
		// "&" survives only as entity prefix "&amp;" etc.
		if bad == "&" {
			continue
		}
		if contains(got, bad) {
			t.Fatalf("unsanitized %q remains in %q", bad, got)
		}
	}
	t.Logf("INPUT %q -> 判定依据 元字符实体转义 -> 输出 %q", injected, got)

	cases := map[string]string{
		"password": "supersecret-value",
		"token":    "abcdef123456",
		"username": "alice",
	}
	for f, v := range cases {
		fmt.Printf("REDACT %s=%s -> %s\n", f, v, Redact(f, v))
	}
	if Redact("password", "supersecret-value") != "***" {
		t.Fatal("sensitive field must be fully masked")
	}
	if got := Redact("username", "alice"); got != "a***e" {
		t.Fatalf("5-char non-sensitive value should keep first/last, got %q", got)
	}
	if Redact("username", "ab") != "***" {
		t.Fatal("short non-sensitive value must be fully masked")
	}
	if h := SafeHeaders(); h["X-Content-Type-Options"] != "nosniff" {
		t.Fatalf("safe headers: %v", h)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
