// Package authz provides role-based and attribute-based access decisions
// with resource hierarchy, scope narrowing and explicit-deny precedence.
package authz

import (
	"context"
	"errors"
)

// Effect is a policy effect.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Decision is the final access verdict.
type Decision string

const (
	DecisionAllow       Decision = "allow"
	DecisionDeny        Decision = "deny"
	DecisionDefaultDeny Decision = "default_deny"
)

// DenyReason distinguishes why access was refused.
type DenyReason string

const (
	ReasonNone         DenyReason = ""
	ReasonExplicitDeny DenyReason = "explicit_deny"
	ReasonNoMatch      DenyReason = "no_matching_policy"
	ReasonScopeNarrow  DenyReason = "scope_insufficient"
	ReasonHierarchy    DenyReason = "hierarchy_denied"
	ReasonAttrFail     DenyReason = "attribute_condition_failed"
)

// Subject describes the authenticated principal.
type Subject struct {
	UserID     string
	Roles      []string
	Scopes     []string
	Attributes map[string]string
}

// Resource describes the target; Path is hierarchical with "/" separators.
type Resource struct {
	Path       string
	Attributes map[string]string
}

// Context carries runtime attributes for ABAC conditions.
type Context map[string]string

// Rule is one authorization policy rule.
type Rule struct {
	Name   string
	Effect Effect
	Roles  []string
	Scopes []string
	// ResourcePattern supports exact and prefix (".../*" and ".../**") matches.
	ResourcePattern string
	// Actions matched ("*" = any).
	Actions []string
	// Condition is evaluated against subject/resource/context attributes.
	Condition func(sub Subject, res Resource, ctx Context) bool
	Priority  int
}

// Result explains a decision.
type Result struct {
	Decision   Decision
	DenyReason DenyReason
	// MatchedRule names the rule that drove the decision.
	MatchedRule string
	// Evaluated lists rules considered in deterministic order.
	Evaluated []string
}

// ErrInvalidInput is returned for malformed subjects/resources.
var ErrInvalidInput = errors.New("authz: invalid input")

// Engine evaluates requests against an ordered rule set.
type Engine interface {
	Authorize(ctx context.Context, sub Subject, res Resource, action string, actx Context) (Result, error)
}
