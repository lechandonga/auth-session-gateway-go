package authz

import (
	"context"
	"testing"
)

func sampleRules() []Rule {
	return []Rule{
		{Name: "deny-secrets", Effect: EffectDeny, ResourcePattern: "/docs/secret/**"},
		{Name: "admin-all", Effect: EffectAllow, Roles: []string{"admin"},
			Actions: []string{"*"}, ResourcePattern: "/**", Scopes: []string{"*"}},
		{Name: "viewer-read", Effect: EffectAllow, Roles: []string{"viewer"},
			Actions: []string{"GET"}, ResourcePattern: "/docs/*", Scopes: []string{"docs:read"}},
		{Name: "editor-write", Effect: EffectAllow, Roles: []string{"editor"},
			Actions: []string{"GET", "POST", "PUT"}, ResourcePattern: "/docs/*",
			Scopes: []string{"docs:read", "docs:write"}},
	}
}

func TestAuthzMatrix(t *testing.T) {
	ctx := context.Background()
	e := NewEngine(sampleRules())
	cases := []struct {
		name    string
		sub     Subject
		path    string
		action  string
		want    Decision
		wantWhy DenyReason
	}{
		{"viewer reads doc", Subject{UserID: "a", Roles: []string{"viewer"}, Scopes: []string{"docs:read"}},
			"/docs/r1", "GET", DecisionAllow, ReasonNone},
		{"viewer cannot write (scope+action)", Subject{UserID: "a", Roles: []string{"viewer"}, Scopes: []string{"docs:read"}},
			"/docs/r1", "POST", DecisionDefaultDeny, ReasonNoMatch},
		{"viewer cannot reach /admin (hierarchy)", Subject{UserID: "a", Roles: []string{"viewer"}, Scopes: []string{"docs:read"}},
			"/admin/x", "GET", DecisionDefaultDeny, ReasonHierarchy},
		{"editor writes doc", Subject{UserID: "b", Roles: []string{"editor"}, Scopes: []string{"docs:read", "docs:write"}},
			"/docs/r1", "POST", DecisionAllow, ReasonNone},
		{"editor cannot delete (action missing)", Subject{UserID: "b", Roles: []string{"editor"}, Scopes: []string{"docs:write"}},
			"/docs/r1", "DELETE", DecisionDefaultDeny, ReasonNoMatch},
		{"admin allowed broad", Subject{UserID: "z", Roles: []string{"admin"}, Scopes: []string{"*"}},
			"/any/path", "POST", DecisionAllow, ReasonNone},
		{"editor blocked from secrets even with write scope", Subject{UserID: "b", Roles: []string{"editor"}, Scopes: []string{"*"}},
			"/docs/secret/plan", "GET", DecisionDeny, ReasonExplicitDeny},
		{"admin blocked from secrets (deny beats admin allow)", Subject{UserID: "z", Roles: []string{"admin"}, Scopes: []string{"*"}},
			"/docs/secret/x", "GET", DecisionDeny, ReasonExplicitDeny},
		{"scope narrower than rule denies", Subject{UserID: "c", Roles: []string{"editor"}, Scopes: []string{"docs:read"}},
			"/docs/r1", "POST", DecisionDefaultDeny, ReasonScopeNarrow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := e.Authorize(ctx, tc.sub, Resource{Path: tc.path}, tc.action, Context{})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("input={user:%s path:%s action:%s roles:%v scopes:%v} decision=%s reason=%s rule=%q basis=deny-pass then allow-pass evaluated=%v",
				tc.sub.UserID, tc.path, tc.action, tc.sub.Roles, tc.sub.Scopes,
				res.Decision, res.DenyReason, res.MatchedRule, res.Evaluated)
			if res.Decision != tc.want || (res.Decision != DecisionAllow && res.DenyReason != tc.wantWhy) {
				t.Fatalf("got %s/%s, want %s/%s", res.Decision, res.DenyReason, tc.want, tc.wantWhy)
			}
		})
	}
}

func TestExplicitDenyIndependentOfRuleOrder(t *testing.T) {
	ctx := context.Background()
	rules := sampleRules()
	// Put the admin allow BEFORE the deny rule; deny must still win.
	reordered := []Rule{rules[2], rules[1], rules[0], rules[3]}
	e1 := NewEngine(sampleRules())
	e2 := NewEngine(reordered)
	sub := Subject{UserID: "z", Roles: []string{"admin"}, Scopes: []string{"*"}}
	r1, _ := e1.Authorize(ctx, sub, Resource{Path: "/docs/secret/x"}, "GET", Context{})
	r2, _ := e2.Authorize(ctx, sub, Resource{Path: "/docs/secret/x"}, "GET", Context{})
	if r1.Decision != DecisionDeny || r2.Decision != DecisionDeny ||
		r1.DenyReason != ReasonExplicitDeny || r2.DenyReason != ReasonExplicitDeny ||
		r1.MatchedRule != "deny-secrets" || r2.MatchedRule != "deny-secrets" {
		t.Fatalf("order changed result: %+v vs %+v", r1, r2)
	}
	t.Logf("input=admin GET /docs/secret/x under 2 rule orders basis=deny-evaluated-first rule=explicit_deny both orders -> %s(%s)",
		r1.Decision, r1.MatchedRule)
}

func TestHierarchyPatterns(t *testing.T) {
	ctx := context.Background()
	e := NewEngine([]Rule{{Name: "docs", Effect: EffectAllow,
		ResourcePattern: "/docs/**", Actions: []string{"GET"}}})
	sub := Subject{UserID: "u"}
	for _, p := range []string{"/docs", "/docs/a", "/docs/a/b/c"} {
		r, _ := e.Authorize(ctx, sub, Resource{Path: p}, "GET", Context{})
		if r.Decision != DecisionAllow {
			t.Fatalf("%s should be covered by /docs/**", p)
		}
	}
	for _, p := range []string{"/docsy", "/other", "/"} {
		r, _ := e.Authorize(ctx, sub, Resource{Path: p}, "GET", Context{})
		if r.Decision == DecisionAllow {
			t.Fatalf("%s must NOT be covered by /docs/**", p)
		}
	}
	t.Log("input=/docs/** vs sibling paths basis=segment-boundary prefix rule=children allowed, /docsy denied")
}

func TestABACCondition(t *testing.T) {
	ctx := context.Background()
	e := NewEngine([]Rule{{Name: "own-dept", Effect: EffectAllow,
		ResourcePattern: "/sales/**", Actions: []string{"GET"},
		Condition: func(s Subject, r Resource, c Context) bool {
			return s.Attributes["dept"] == "sales"
		}}})
	ok2, _ := e.Authorize(ctx, Subject{UserID: "a", Attributes: map[string]string{"dept": "sales"}},
		Resource{Path: "/sales/x"}, "GET", Context{})
	bad, _ := e.Authorize(ctx, Subject{UserID: "b", Attributes: map[string]string{"dept": "ops"}},
		Resource{Path: "/sales/x"}, "GET", Context{})
	if ok2.Decision != DecisionAllow || bad.Decision != DecisionDefaultDeny || bad.DenyReason != ReasonAttrFail {
		t.Fatalf("ABAC got %+v / %+v", ok2, bad)
	}
	t.Logf("input=sales vs ops dept on /sales/x basis=condition(sub.attr.dept) rule=attr match allow, mismatch deny(%s)", bad.DenyReason)
}
