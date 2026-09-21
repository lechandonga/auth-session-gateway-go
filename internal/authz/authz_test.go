package authz

import (
	"fmt"
	"testing"

	"github.com/lechandonga/auth-session-gateway-go/internal/model"
)

func samplePolicies() []model.Policy {
	return []model.Policy{
		{ID: "p-deny-secret", Effect: model.EffectDeny, Roles: []string{"member"}, Resource: "orgs/acme/secret/*"},
		{ID: "p-member-read", Effect: model.EffectAllow, Roles: []string{"member"}, Actions: []string{"GET"}, Resource: "orgs/acme/docs/*", Scopes: []string{"docs:read"}},
		{ID: "p-member-write", Effect: model.EffectAllow, Roles: []string{"editor"}, Actions: []string{"POST", "PUT", "DELETE"}, Resource: "orgs/acme/docs/*", Scopes: []string{"docs:write"}},
		{ID: "p-admin", Effect: model.EffectAllow, Roles: []string{"admin"}, Actions: []string{"GET", "POST", "PUT", "DELETE"}, Resource: "*"},
		{ID: "p-attr-tenanta", Effect: model.EffectAllow, Roles: []string{"member"}, Actions: []string{"GET"}, Resource: "billing/*", AttrMatch: map[string]string{"tenant": "a"}},
	}
}

func TestAllowAndEscalationDenied(t *testing.T) {
	e := NewEngine(samplePolicies())

	ok := e.Decide(model.AuthzRequest{
		Subject: "u1", Roles: []string{"member"}, Scopes: []string{"docs:read"},
		Resource: "orgs/acme/docs/readme", Action: "GET",
	})
	if ok.Decision != model.DecisionAllow || ok.PolicyID != "p-member-read" {
		t.Fatalf("want allow by p-member-read, got %+v", ok)
	}
	t.Log("INPUT member+docs:read GET docs/readme -> 判定依据 角色/资源/作用域全匹配 -> 命中规则 p-member-read 放行")

	// Privilege escalation: read scope must NOT authorize write.
	d := e.Decide(model.AuthzRequest{
		Subject: "u1", Roles: []string{"member"}, Scopes: []string{"docs:read"},
		Resource: "orgs/acme/docs/readme", Action: "POST",
	})
	if d.Decision != model.DecisionDeny || d.Reason == model.DenyNoPolicy || d.Reason == model.DenyExplicitDeny {
		t.Fatalf("write with read scope must be a specific deny, got %+v", d)
	}
	t.Logf("INPUT docs:read 请求写 POST -> 判定依据 动作白名单(GET)/角色(editor)/作用域 逐层比对 -> 命中规则 %s 越权拒绝", d.Reason)

	// Sibling organization: resource hierarchy must not leak across tenants.
	d = e.Decide(model.AuthzRequest{
		Subject: "u1", Roles: []string{"member"}, Scopes: []string{"docs:read"},
		Resource: "orgs/other/docs/x", Action: "GET",
	})
	if d.Decision != model.DecisionDeny || d.Reason != model.DenyNoPolicy {
		t.Fatalf("cross-org access: %+v", d)
	}
	t.Logf("INPUT member 访问 orgs/other/* -> 判定依据 无子树包含 -> 命中规则 %s", d.Reason)

	// Non-admin cannot escape to wildcard resources.
	d = e.Decide(model.AuthzRequest{
		Subject: "u1", Roles: []string{"member"}, Scopes: []string{"docs:read"},
		Resource: "root/keys/k1", Action: "GET",
	})
	if d.Decision != model.DecisionDeny {
		t.Fatalf("member reaching admin-only resource: %+v", d)
	}
	t.Logf("INPUT member 访问 root/keys -> 判定依据 无匹配策略 -> 命中规则 %s", d.Reason)
}

func TestExplicitDenyWinsEvenWithAllowAndOrderIndependent(t *testing.T) {
	pols := samplePolicies()
	// member would match p-member-read on docs, and p-deny-secret is a
	// different tree — build a direct collision instead.
	pols = append(pols, model.Policy{
		ID: "p-deny-one-doc", Effect: model.EffectDeny,
		Roles: []string{"member"}, Resource: "orgs/acme/docs/forbidden",
	})
	for _, order := range [][]model.Policy{pols, reversed(pols), shuffled(pols)} {
		e := NewEngine(order)
		d := e.Decide(model.AuthzRequest{
			Subject: "u1", Roles: []string{"member"}, Scopes: []string{"docs:read"},
			Resource: "orgs/acme/docs/forbidden", Action: "GET",
		})
		if d.Decision != model.DecisionDeny || d.Reason != model.DenyExplicitDeny || d.PolicyID != "p-deny-one-doc" {
			t.Fatalf("deny must win regardless of policy order: %+v", d)
		}
	}
	t.Log("INPUT 同一资源 allow+deny 三种策略顺序 -> 判定依据 两遍扫描 deny 优先 -> 命中规则 explicit_deny 结论恒定")

	// Even admin hits the secret denial? No — secret deny is scoped to member
	// role, admin does not match it. But an explicit deny WITHOUT role bound
	// beats admin wildcard:
	pols = append(pols, model.Policy{ID: "p-deny-nuclear", Effect: model.EffectDeny, Resource: "nuclear/*"})
	e := NewEngine(pols)
	d := e.Decide(model.AuthzRequest{
		Subject: "root", Roles: []string{"admin"}, Scopes: nil,
		Resource: "nuclear/codes", Action: "GET",
	})
	if d.Decision != model.DecisionDeny || d.PolicyID != "p-deny-nuclear" {
		t.Fatalf("unbounded deny must beat admin allow: %+v", d)
	}
	t.Logf("INPUT admin+wildcard 访问 nuclear/* -> 判定依据 无条件 deny 对 admin 同样生效 -> 命中规则 %s/%s", d.PolicyID, d.Reason)
}

func TestScopeNarrowingAndAttrs(t *testing.T) {
	if !ScopeCovers("docs", "docs:read") || ScopeCovers("docs:read", "docs:write") || ScopeCovers("doc", "docs:read") {
		t.Fatal("scope hierarchy rules wrong")
	}
	if !ResourceContains("orgs/a/*", "orgs/a/x/y") || ResourceContains("orgs/a/*", "orgs/b/x") {
		t.Fatal("resource hierarchy rules wrong")
	}
	e := NewEngine(samplePolicies())
	d := e.Decide(model.AuthzRequest{
		Subject: "u", Roles: []string{"member"}, Attrs: map[string]string{"tenant": "b"},
		Resource: "billing/invoices/1", Action: "GET",
	})
	if d.Decision != model.DecisionDeny || d.Reason != model.DenyAttrMismatch {
		t.Fatalf("tenant b vs tenant a policy: %+v", d)
	}
	t.Logf("INPUT tenant=b 访问 tenant=a 计费资源 -> 判定依据 AttrMatch 全等比较失败 -> 命中规则 %s", d.Reason)
	d = e.Decide(model.AuthzRequest{
		Subject: "u", Roles: []string{"member"}, Attrs: map[string]string{"tenant": "a"},
		Resource: "billing/invoices/1", Action: "GET",
	})
	if d.Decision != model.DecisionAllow {
		t.Fatalf("tenant a should be allowed: %+v", d)
	}
	// Narrow scope "docs:read" must not grant parent scope "docs".
	d = e.Decide(model.AuthzRequest{
		Subject: "u1", Roles: []string{"member"}, Scopes: []string{"docs:read"},
		Resource: "orgs/acme/docs/x", Action: "POST",
	})
	if d.Decision != model.DecisionDeny {
		t.Fatalf("child scope + read action cannot cover write: %+v", d)
	}
}

func TestReasonStability(t *testing.T) {
	// With multiple near-miss policies, the reported reason must be the most
	// specific and stable regardless of order.
	pols := []model.Policy{
		{ID: "role-only", Effect: model.EffectAllow, Roles: []string{"ghost"}, Resource: "r/*"},
		{ID: "scope-only", Effect: model.EffectAllow, Roles: []string{"member"}, Resource: "r/*", Scopes: []string{"x:y"}},
	}
	for _, ps := range [][]model.Policy{pols, reversed(pols)} {
		e := NewEngine(ps)
		d := e.Decide(model.AuthzRequest{Subject: "u", Roles: []string{"member"}, Resource: "r/1"})
		if d.Reason != model.DenyScopeInsufficient {
			fmt.Println("evaluated:", d.Evaluated)
			t.Fatalf("most specific reason must be scope_insufficient regardless of order, got %s", d.Reason)
		}
	}
	t.Log("INPUT 多个近似未命中策略+不同顺序 -> 判定依据 reasonRank 取最具体 -> 命中规则 scope_insufficient 恒定")
}

func reversed(p []model.Policy) []model.Policy {
	out := make([]model.Policy, len(p))
	for i := range p {
		out[len(p)-1-i] = p[i]
	}
	return out
}

func shuffled(p []model.Policy) []model.Policy {
	out := make([]model.Policy, len(p))
	copy(out, p)
	// deterministic swap shuffle
	out[0], out[len(out)-1] = out[len(out)-1], out[0]
	out[1], out[2] = out[2], out[1]
	return out
}
