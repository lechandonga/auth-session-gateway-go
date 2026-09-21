// Package model holds shared domain types, reason codes and sentinel errors
// for the auth/session gateway. It is a leaf package with no dependencies.
package model

import "time"

// ----- Core identifiers -----

// User is a locally stored account.
type User struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	Salt         string            `json:"salt"`
	PasswordHash string            `json:"password_hash"`
	Roles        []string          `json:"roles"`
	Attributes   map[string]string `json:"attributes"`
	Disabled     bool              `json:"disabled"`
}

// Session is a login session. Refresh tokens belonging to the same login
// share a FamilyID; observed reuse of a rotated token revokes the family.
type Session struct {
	ID           string
	UserID       string
	FamilyID     string
	CreatedAt    time.Time
	LastRefresh  time.Time
	AbsoluteExp  time.Time
	IdleExp      time.Time
	Revoked      bool
	RevokedAt    time.Time
	RevokeReason string
}

// RefreshTokenRecord stores only a hash of an opaque refresh token.
type RefreshTokenRecord struct {
	Hash       string
	SessionID  string
	FamilyID   string
	UserID     string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Rotated    bool
	RotatedAt  time.Time
	Revoked    bool
	ReuseSeen  bool
	ParentHash string
}

// ----- Tokens -----

// AccessClaims is the claim set carried by signed access tokens.
type AccessClaims struct {
	JTI        string            `json:"jti"`
	Sub        string            `json:"sub"`
	SessionID  string            `json:"sid"`
	IssuedAt   int64             `json:"iat"`
	ExpiresAt  int64             `json:"exp"`
	Roles      []string          `json:"roles"`
	Scopes     []string          `json:"scopes"`
	Attrs      map[string]string `json:"attrs,omitempty"`
	SigningKID string            `json:"kid"`
}

// TokenFailReason distinguishes why a token was rejected.
type TokenFailReason string

const (
	TokenOK             TokenFailReason = "ok"
	TokenMalformed      TokenFailReason = "malformed"
	TokenBadSignature   TokenFailReason = "bad_signature"
	TokenUnknownKID     TokenFailReason = "unknown_kid"
	TokenRetiredSigning TokenFailReason = "retired_key_used_for_signing"
	TokenExpired        TokenFailReason = "expired"
	TokenSessionRevoked TokenFailReason = "session_revoked"
)

// ----- Login / lockout / rate limit -----

// LoginResult is the verdict of a credential check.
type LoginResult string

const (
	LoginOK             LoginResult = "ok"
	LoginBadCredentials LoginResult = "bad_credentials"
	LoginUserDisabled   LoginResult = "user_disabled"
	LoginLocked         LoginResult = "locked"
	LoginRateLimited    LoginResult = "rate_limited"
	LoginMissingInput   LoginResult = "missing_input"
)

// ----- Authorization -----

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Policy is one RBAC+ABAC rule. Resource uses a "/" hierarchy
// (e.g. "orgs/acme/docs/*"). Scopes are space-narrowed by prefix
// (e.g. "docs:read" is narrower than "docs").
type Policy struct {
	ID        string
	Effect    Effect
	Roles     []string          // ANY match
	Actions   []string          // ANY match; empty = every action
	Resource  string            // exact, trailing "*" denotes a subtree
	Scopes    []string          // ALL required; each must be satisfied by a granted scope
	AttrMatch map[string]string // ALL must equal subject attributes
}

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

// DenyReason makes every rejection distinguishable.
type DenyReason string

const (
	DenyNone              DenyReason = ""
	DenyNoPolicy          DenyReason = "no_matching_policy"
	DenyExplicitDeny      DenyReason = "explicit_deny"
	DenyRoleMismatch      DenyReason = "role_mismatch"
	DenyScopeInsufficient DenyReason = "scope_insufficient"
	DenyAttrMismatch      DenyReason = "attribute_mismatch"
	DenyActionMismatch    DenyReason = "action_mismatch"
	DenyResourceOutside   DenyReason = "resource_outside_hierarchy"
)

// AuthzRequest is one authorization query.
type AuthzRequest struct {
	Subject  string
	Roles    []string
	Scopes   []string
	Attrs    map[string]string
	Resource string
	Action   string
}

// AuthzDecision is the verdict plus the policy that decided it.
type AuthzDecision struct {
	Decision  Decision
	Reason    DenyReason
	PolicyID  string
	Evaluated []string // IDs of policies considered, in evaluation order
}

// ----- Audit -----

type AuditEvent struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	OccurredAt time.Time         `json:"occurred_at"`
	Subject    string            `json:"subject"`
	SessionID  string            `json:"session_id"`
	Resource   string            `json:"resource"`
	Success    bool              `json:"success"`
	Reason     string            `json:"reason"`
	Details    map[string]string `json:"details"`
	DedupKey   string            `json:"dedup_key"`
}

// Event type constants.
const (
	EventLoginSuccess  = "login_success"
	EventLoginFailure  = "login_failure"
	EventLocked        = "account_locked"
	EventRateLimited   = "rate_limited"
	EventRefreshReuse  = "refresh_token_reuse"
	EventSessionRevoke = "session_revoked"
	EventTokenRotated  = "refresh_token_rotated"
	EventAccessDenied  = "access_denied"
	EventKeyRotated    = "signing_key_rotated"
	EventKeyRetired    = "signing_key_retired"
	EventCSRFRejected  = "csrf_rejected"
)
