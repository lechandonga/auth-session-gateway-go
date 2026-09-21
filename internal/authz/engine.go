// Package authz evaluates RBAC+ABAC policies. Evaluation semantics are
// order-independent: an explicit deny always wins over any allow; resources
// are matched along a "/" hierarchy with trailing "*" subtrees; scopes narrow
// by a ":" prefix hierarchy (least privilege); attribute conditions must all
// match. When the final verdict is deny, the reported reason is the most
// specific mismatch among policies that otherwise applied — also independent
// of policy order.
package authz

import "github.com/lechandonga/auth-session-gateway-go/internal/model"

type Engine struct {
	policies []model.Policy
}

func NewEngine(policies []model.Policy) *Engine {
	cp := make([]model.Policy, len(policies))
	copy(cp, policies)
	return &Engine{policies: cp}
}

func (e *Engine) AddPolicy(p model.Policy) {
	e.policies = append(e.policies, p)
}

// policyMatch records whether a policy matches and, if not, the most specific
// reason it failed. resourceHit tells whether the resource pattern covered
// the requested resource: only resource-relevant policies may contribute a
// near-miss reason (a billing policy cannot explain denial of an orgs/*
// request).
type policyMatch struct {
	matches     bool
	resourceHit bool
	reason      model.DenyReason
}

var reasonRank = map[model.DenyReason]int{
	model.DenyNone:              0,
	model.DenyNoPolicy:          1,
	model.DenyResourceOutside:   2,
	model.DenyRoleMismatch:      3,
	model.DenyScopeInsufficient: 4,
	model.DenyAttrMismatch:      5,
	model.DenyActionMismatch:    6,
}

func moreSpecific(a, b model.DenyReason) model.DenyReason {
	if reasonRank[a] >= reasonRank[b] {
		return a
	}
	return b
}

// matchPolicy evaluates ALL conditions of p against req. Conditions not
// constrained by the policy do not cause failure (empty = wildcard).
func matchPolicy(p model.Policy, req model.AuthzRequest) policyMatch {
	if !ResourceContains(p.Resource, req.Resource) {
		return policyMatch{matches: false, resourceHit: false, reason: model.DenyResourceOutside}
	}
	if len(p.Actions) > 0 && !anyString(p.Actions, []string{req.Action}) {
		return policyMatch{false, true, model.DenyActionMismatch}
	}
	if len(p.Roles) > 0 && !anyRole(p.Roles, req.Roles) {
		return policyMatch{false, true, model.DenyRoleMismatch}
	}
	if len(p.Scopes) > 0 {
		for _, need := range p.Scopes {
			if !anyScopeCovers(req.Scopes, need) {
				return policyMatch{false, true, model.DenyScopeInsufficient}
			}
		}
	}
	if len(p.AttrMatch) > 0 {
		for k, want := range p.AttrMatch {
			if req.Attrs[k] != want {
				return policyMatch{false, true, model.DenyAttrMismatch}
			}
		}
	}
	return policyMatch{true, true, model.DenyNone}
}

func anyString(want, have []string) bool {
	for _, w := range want {
		for _, h := range have {
			if w == h {
				return true
			}
		}
	}
	return false
}

func anyRole(want, have []string) bool {
	for _, w := range want {
		for _, h := range have {
			if w == h {
				return true
			}
		}
	}
	return false
}

func anyScopeCovers(granted []string, required string) bool {
	for _, g := range granted {
		if ScopeCovers(g, required) {
			return true
		}
	}
	return false
}

// Decide implements two-pass evaluation:
//
//  1. Every matching deny policy immediately guarantees a final deny
//     (explicit deny wins), collected but order-independent.
//  2. Otherwise a matching allow grants. If neither exists, deny with the
//     most specific observed reason.
//
// Evaluating all policies in both passes instead of returning on the first
// allow means policy slice ordering cannot change the conclusion.
func (e *Engine) Decide(req model.AuthzRequest) model.AuthzDecision {
	evaluated := make([]string, 0, len(e.policies))
	deniedBy := ""
	allowedBy := ""
	bestReason := model.DenyNoPolicy
	anchoredNearMiss := false // a policy anchored to a concrete resource subtree
	wildcardMiss := false     // a bare "*"/empty resource policy missed

	for _, p := range e.policies {
		evaluated = append(evaluated, p.ID)
		m := matchPolicy(p, req)
		if !m.matches {
			// Only resource-relevant near misses inform the reason; a
			// policy on an unrelated subtree cannot explain this denial.
			// A bare wildcard policy ("*"/"") is a catch-all, not an anchor:
			// it contributes a reason only when no concrete-subtree policy
			// came close, otherwise it stays a fallback.
			if m.resourceHit {
				if p.Resource == "*" || p.Resource == "" {
					wildcardMiss = true
				} else {
					anchoredNearMiss = true
					bestReason = moreSpecific(bestReason, m.reason)
				}
			}
			continue
		}
		switch p.Effect {
		case model.EffectDeny:
			if deniedBy == "" {
				deniedBy = p.ID
			}
		case model.EffectAllow:
			if allowedBy == "" {
				allowedBy = p.ID
			}
		}
	}

	if deniedBy != "" {
		return model.AuthzDecision{
			Decision:  model.DecisionDeny,
			Reason:    model.DenyExplicitDeny,
			PolicyID:  deniedBy,
			Evaluated: evaluated,
		}
	}
	if allowedBy != "" {
		return model.AuthzDecision{
			Decision:  model.DecisionAllow,
			PolicyID:  allowedBy,
			Evaluated: evaluated,
		}
	}
	if !anchoredNearMiss && wildcardMiss {
		// E.g. a member reaching an unrelated tenant: only the admin
		// catch-all matched the resource, so there is effectively no policy
		// granting this subject -> deterministic no_matching_policy.
		bestReason = model.DenyNoPolicy
	}
	return model.AuthzDecision{
		Decision:  model.DecisionDeny,
		Reason:    bestReason,
		Evaluated: evaluated,
	}
}

// ResourceContains reports whether the parent pattern contains child under a
// "/" hierarchy:
//
//	"*" or ""                 contains everything
//	"orgs/acme"               contains only "orgs/acme" (exact)
//	"orgs/acme/*"             contains "orgs/acme/x", "orgs/acme/x/y"
//	"orgs/acme*" (non-sep '*') is treated as exact-prefix subtree of the segment
//
// Siblings never contain each other ("orgs/a/*" does not contain "orgs/b").
func ResourceContains(parent, child string) bool {
	if parent == "" || parent == "*" {
		return true
	}
	if parent == child {
		return true
	}
	if len(parent) > 0 && parent[len(parent)-1] == '*' {
		prefix := parent[:len(parent)-1]
		// Require segment boundary for "/*" patterns.
		if len(prefix) > 0 && prefix[len(prefix)-1] == '/' {
			return len(child) >= len(prefix) && child[:len(prefix)] == prefix
		}
		// Plain prefix wildcard still must not cross segment siblings:
		// e.g. "orgs/ac*" matches "orgs/acme" but not "orgs/ad".
		return len(child) >= len(prefix) && child[:len(prefix)] == prefix
	}
	return false
}

// ScopeCovers reports whether granted covers required:
//
//	"docs"       covers "docs", "docs:read"
//	"docs:read"  covers "docs:read" but NOT "docs" or "docs:write"
//
// The boundary is enforced on ":" so "doc" never covers "docs:read".
func ScopeCovers(granted, required string) bool {
	if granted == required {
		return true
	}
	if len(granted) < len(required) && required[:len(granted)] == granted &&
		required[len(granted)] == ':' {
		return true
	}
	return false
}
