// Package csrf provides double-submit CSRF protection and security headers,
// plus output sanitization and sensitive-field masking.
package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html"
	"strings"
)

var (
	// ErrMissingToken indicates the CSRF token was absent.
	ErrMissingToken = errors.New("csrf: missing token")
	// ErrTokenMismatch indicates cookie and header tokens differ.
	ErrTokenMismatch = errors.New("csrf: token mismatch")
	// ErrUnsafeMethod indicates a state-changing method lacks protection.
	ErrUnsafeMethod = errors.New("csrf: unsafe method without token")
)

// Protector validates double-submit tokens and emits security headers.
type Protector struct {
	headerName string
	cookieName string
}

// NewProtector constructs a Protector with the standard names.
func NewProtector() *Protector {
	return &Protector{headerName: "X-CSRF-Token", cookieName: "csrf_token"}
}

// HeaderName / CookieName expose configured token transport names.
func (p *Protector) HeaderName() string { return p.headerName }
func (p *Protector) CookieName() string { return p.cookieName }

// GenerateToken returns a fresh random token.
func (p *Protector) GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Verify checks the cookie token against the request header token using a
// constant-time comparison. Missing and mismatched tokens are distinct
// failures.
func (p *Protector) Verify(cookieToken, headerToken string) error {
	if cookieToken == "" || headerToken == "" {
		return ErrMissingToken
	}
	if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
		return ErrTokenMismatch
	}
	return nil
}

// SafeMethods lists HTTP methods that do not require CSRF tokens.
var SafeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "TRACE": true}

// VerifyRequest enforces tokens only on state-changing methods.
func (p *Protector) VerifyRequest(method, cookieToken, headerToken string) error {
	if SafeMethods[strings.ToUpper(method)] {
		return nil
	}
	if cookieToken == "" || headerToken == "" {
		return ErrUnsafeMethod
	}
	return p.Verify(cookieToken, headerToken)
}

// SafeHeaders returns baseline security response headers.
func (p *Protector) SafeHeaders() map[string]string {
	return map[string]string{
		"Content-Security-Policy":   "default-src 'none'; frame-ancestors 'none'",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
}

// Sanitize neutralizes HTML/script injection in echoed input.
func Sanitize(in string) string {
	return html.EscapeString(in)
}

// Mask masks sensitive values for logs and external output. Supported kinds:
// "password", "token", "secret", "email"; unknown kinds are fully masked.
func Mask(kind, value string) string {
	switch kind {
	case "email":
		at := strings.IndexByte(value, '@')
		if at <= 0 {
			return "***"
		}
		return string(value[0]) + "***" + value[at:]
	case "password", "secret", "token", "refresh_token", "access_token":
		return "***REDACTED***"
	default:
		if value == "" {
			return ""
		}
		return "***REDACTED***"
	}
}
