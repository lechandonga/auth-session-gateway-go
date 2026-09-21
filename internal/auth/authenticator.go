// Package auth performs credential verification with failure counting,
// lockout and rate limiting. Lockout and rate-limit verdicts are distinct
// reasons; all accounting is atomic under concurrency (no lost or double
// counts, no double locking).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"time"

	"github.com/lechandonga/auth-session-gateway-go/internal/audit"
	"github.com/lechandonga/auth-session-gateway-go/internal/model"
	"github.com/lechandonga/auth-session-gateway-go/internal/store"
)

// Policy configures lockout behavior.
type Policy struct {
	MaxFailures  int
	FailWindow   time.Duration // failures older than this are not counted
	LockDuration time.Duration
}

func DefaultPolicy() Policy {
	return Policy{MaxFailures: 5, FailWindow: 15 * time.Minute, LockDuration: 30 * time.Minute}
}

type Authenticator struct {
	users  *store.UserStore
	locks  *store.LockoutStore
	aud    *audit.Logger
	policy Policy
	rl     *RateLimiter
	now    func() time.Time
}

func NewAuthenticator(users *store.UserStore, locks *store.LockoutStore, aud *audit.Logger, p Policy, rl *RateLimiter) *Authenticator {
	return &Authenticator{users: users, locks: locks, aud: aud, policy: p, rl: rl, now: time.Now}
}

// LoginOutcome carries the verdict and, on success, the authenticated user.
type LoginOutcome struct {
	Result   model.LoginResult
	User     *model.User
	Failures int       // failures counted within the window for the subject
	RetryAt  time.Time // lock expiry or rate-limit reset, whichever applied
}

// Login verifies credentials from clientIP. The decision order is FIXED so
// concurrent or reordered requests cannot produce inconsistent verdicts:
//
//  1. missing input
//  2. rate limit (per IP; independent of account state)
//  3. account lock (per username; evaluated before credential check so a
//     locked account never leaks whether the presented password was right)
//  4. user existence / disabled / password
//  5. success -> failure counter reset
//
// Every failed credential verification performs exactly one atomic
// RegisterFailure; the "just locked" transition is reported at most once and
// emits exactly one lock audit event.
func (a *Authenticator) Login(username, password, clientIP string) LoginOutcome {
	now := a.now()

	if username == "" || password == "" {
		a.aud.Record(model.AuditEvent{
			Type: model.EventLoginFailure, Subject: username, Success: false,
			Reason:  string(model.LoginMissingInput),
			Details: map[string]string{"client_ip": clientIP},
		})
		return LoginOutcome{Result: model.LoginMissingInput}
	}

	// 2. Rate limit first: protects even unknown usernames from enumeration
	// and is independent of the lockout state, so the two causes never blur.
	if a.rl != nil {
		if ok, retry := a.rl.Allow(clientIP); !ok {
			a.aud.Record(model.AuditEvent{
				Type: model.EventRateLimited, Subject: username, Success: false,
				Reason: string(model.LoginRateLimited),
				Details: map[string]string{
					"client_ip":   clientIP,
					"retry_after": retry.String(),
				},
				// DedupKey intentionally scoped to the window so the same IP
				// being rejected repeatedly yields one event per window, not
				// one per request.
				DedupKey: "rl:" + clientIP + ":" + now.Truncate(a.rl.Window).Format(time.RFC3339),
			})
			return LoginOutcome{Result: model.LoginRateLimited, RetryAt: now.Add(retry)}
		}
	}

	// 3. Lock check.
	if locked, until := a.locks.IsLocked(username, now); locked {
		a.aud.Record(model.AuditEvent{
			Type: model.EventLoginFailure, Subject: username, Success: false,
			Reason:  string(model.LoginLocked),
			Details: map[string]string{"client_ip": clientIP, "locked_until": until.Format(time.RFC3339)},
		})
		return LoginOutcome{Result: model.LoginLocked, RetryAt: until}
	}

	// 4. Credential verification.
	user, err := a.users.Get(username)
	if err != nil {
		// Unknown user: still register a failure under the presented name so
		// username-enumeration-by-lockout cannot be used as an oracle, and to
		// throttle sustained guessing.
		fails, lockedNow, until := a.locks.RegisterFailure(username, now, a.policy.MaxFailures, a.policy.FailWindow, a.policy.LockDuration)
		a.recordFailure(username, clientIP, model.LoginBadCredentials, fails)
		if lockedNow {
			a.recordLock(username, clientIP, until)
		}
		return LoginOutcome{Result: model.LoginBadCredentials, Failures: fails, RetryAt: until}
	}
	if user.Disabled {
		a.aud.Record(model.AuditEvent{
			Type: model.EventLoginFailure, Subject: username, Success: false,
			Reason:  string(model.LoginUserDisabled),
			Details: map[string]string{"client_ip": clientIP, "user_id": user.ID},
		})
		return LoginOutcome{Result: model.LoginUserDisabled}
	}

	want := HashPassword(user.Salt, password)
	// len pre-check keeps the comparison length-agnostic without leaking via
	// timing differences.
	if len(want) != len(user.PasswordHash) ||
		subtle.ConstantTimeCompare([]byte(want), []byte(user.PasswordHash)) != 1 {
		fails, lockedNow, until := a.locks.RegisterFailure(username, now, a.policy.MaxFailures, a.policy.FailWindow, a.policy.LockDuration)
		a.recordFailure(username, clientIP, model.LoginBadCredentials, fails)
		if lockedNow {
			a.recordLock(username, clientIP, until)
		}
		return LoginOutcome{Result: model.LoginBadCredentials, Failures: fails, RetryAt: until}
	}

	// 5. Success: clear counters and audit exactly once.
	a.locks.Reset(username)
	a.aud.Record(model.AuditEvent{
		Type: model.EventLoginSuccess, Subject: username, Success: true,
		Details: map[string]string{"client_ip": clientIP, "user_id": user.ID},
	})
	return LoginOutcome{Result: model.LoginOK, User: user}
}

func (a *Authenticator) recordFailure(username, ip string, reason model.LoginResult, fails int) {
	a.aud.Record(model.AuditEvent{
		Type: model.EventLoginFailure, Subject: username, Success: false,
		Reason: string(reason),
		Details: map[string]string{
			"client_ip":    ip,
			"fail_count":   itoa(fails),
			"max_failures": itoa(a.policy.MaxFailures),
		},
	})
}

func (a *Authenticator) recordLock(username, ip string, until time.Time) {
	// DedupKey binds to the concrete lock expiry: the same lock window is
	// logged exactly once even if many concurrent failures crossed the
	// threshold together (only one observes lockedNow anyway).
	a.aud.Record(model.AuditEvent{
		Type: model.EventLocked, Subject: username, Success: false,
		Reason:   string(model.LoginLocked),
		Details:  map[string]string{"client_ip": ip, "locked_until": until.Format(time.RFC3339)},
		DedupKey: "lock:" + username + ":" + until.Format(time.RFC3339Nano),
	})
}

// HashPassword derives salted SHA-256 hex. The KDF is deliberately simple and
// dependency-free while still applying a per-user random salt; it models a
// local credential store rather than claiming production-grade KDF strength.
func HashPassword(salt, password string) string {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte(":"))
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// NewSalt returns 16 random bytes as hex.
func NewSalt() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("auth: cannot read randomness: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
