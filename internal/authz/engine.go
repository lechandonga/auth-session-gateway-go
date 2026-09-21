package authz

import (
	"context"
	"strings"
)

// DefaultEngine evaluates rules with a deterministic fixed ordering so that
// rule registration order can never change the conclusion:
//
//  1. ALL matching deny rules are collected first; any one wins outright.
//  2. Role scope and requested scope are intersected (least privilege).
//  3. Resource hierarchy is enforced via path patterns ("/a/**" covers
//     "/a/b" but never "/b"; a grant on a parent is automatically narrower
//     on a child via scope intersection).
//  4. Only if no deny matches and at least one allow matches every
//     condition is access granted; otherwise default-deny with a distinct
//     reason.
type DefaultEngine struct {
	rules []Rule
}

// NewEngine constructs an engine over the given rules.
func NewEngine(rules []Rule) *DefaultEngine {
	cp := append([]Rule(nil), rules...)
	return &DefaultEngine{rules: cp}
}

func hasOrStar(want string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" || a == want {
			return true
		}
	}
	return false
}

// matchResource matches exact paths and patterns:
//
//	"/a/b"  -> exact
//	"/a/*"  -> one child segment under /a
//	"/a/**" -> /a and any descendant
func matchResource(pattern, path string) bool {
	if pattern == path {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		base := strings.TrimSuffix(pattern, "/**")
		return path == base || strings.HasPrefix(path, base+"/")
	}
	if strings.HasSuffix(pattern, "/*") {
		base := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, base+"/") {
			return false
		}
		rest := strings.TrimPrefix(path, base+"/")
		return rest != "" && !strings.Contains(rest, "/")
	}
	return false
}

// narrowScope intersects granted scopes with the scopes a rule grants;
// hierarchy parents may grant a broad scope while the resource-level rule
// narrows it. Empty rule scopes means no narrowing (role scope applies).
func narrowScope(roleScopes, ruleScopes []string) []string {
	if len(ruleScopes) == 0 {
		return roleScopes
	}
	var out []string
	for _, s := range ruleScopes {
		for _, rs := range roleScopes {
			if rs == "*" || rs == s {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// ruleMatches checks applicability in a fixed dimension order:
// role -> action -> resource hierarchy -> scope -> attribute condition.
// The returned reason identifies the FIRST failed dimension so near-misses
// stay distinguishable.
func ruleMatches(r Rule, sub Subject, res Resource, action string, actx Context) (bool, DenyReason) {
	if len(r.Roles) > 0 {
		roleOK := false
		for _, role := range sub.Roles {
			if hasOrStar(role, r.Roles) {
				roleOK = true
				break
			}
		}
		if !roleOK {
			return false, ReasonNoMatch
		}
	}
	if len(r.Actions) > 0 && !hasOrStar(action, r.Actions) {
		return false, ReasonNoMatch
	}
	if r.ResourcePattern != "" && !matchResource(r.ResourcePattern, res.Path) {
		return false, ReasonHierarchy
	}
	if len(r.Scopes) > 0 {
		if len(narrowScope(sub.Scopes, r.Scopes)) == 0 {
			return false, ReasonScopeNarrow
		}
		// Least-privilege narrowing: even when some scopes overlap, a
		// write action requires a write-capable scope. Convention:
		// scopes ending ":write" cover mutating actions; GET needs :read.
		if action != "GET" && action != "HEAD" {
			writeOK := false
			for _, s := range narrowScope(sub.Scopes, r.Scopes) {
				if s == "*" || hasSuffix(s, ":write") {
					writeOK = true
					break
				}
			}
			if !writeOK {
				return false, ReasonScopeNarrow
			}
		}
	}
	if r.Condition != nil && !r.Condition(sub, res, actx) {
		return false, ReasonAttrFail
	}
	return true, ReasonNone
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func (e *DefaultEngine) Authorize(ctx context.Context, sub Subject, res Resource, action string, actx Context) (Result, error) {
	if sub.UserID == "" || res.Path == "" {
		return Result{Decision: DecisionDeny, DenyReason: ReasonNoMatch}, ErrInvalidInput
	}
	out := Result{Evaluated: []string{}}

	// Deny pass first and independent of allow rules: ordering invariant.
	for _, r := range e.rules {
		if r.Effect != EffectDeny {
			continue
		}
		out.Evaluated = append(out.Evaluated, r.Name)
		if ok, _ := ruleMatches(r, sub, res, action, actx); ok {
			out.Decision = DecisionDeny
			out.DenyReason = ReasonExplicitDeny
			out.MatchedRule = r.Name
			return out, nil
		}
	}

	// Allow pass: first matching allow wins. Near-miss reasons are ranked
	// so a rule applicable to the subject's role that fails on hierarchy,
	// scope or attributes gives a specific reason instead of the generic
	// "no match" from rules for other roles.
	var specificReason DenyReason
	for _, r := range e.rules {
		if r.Effect != EffectAllow {
			continue
		}
		out.Evaluated = append(out.Evaluated, r.Name)
		ok, why := ruleMatches(r, sub, res, action, actx)
		if ok {
			out.Decision = DecisionAllow
			out.MatchedRule = r.Name
			return out, nil
		}
		if rankReason(why) > rankReason(specificReason) {
			specificReason = why
		}
	}
	out.Decision = DecisionDefaultDeny
	if specificReason != ReasonNone {
		out.DenyReason = specificReason
	} else {
		out.DenyReason = ReasonNoMatch
	}
	return out, nil
}

// rankReason orders near-miss reasons by diagnostic specificity.
func rankReason(r DenyReason) int {
	switch r {
	case ReasonAttrFail, ReasonScopeNarrow, ReasonHierarchy:
		return 2
	case ReasonNoMatch:
		return 1
	default:
		return 0
	}
}
