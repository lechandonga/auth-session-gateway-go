package model

import "errors"

// Sentinel errors shared across packages.
var (
	ErrNotFound          = errors.New("not found")
	ErrUserExists        = errors.New("user already exists")
	ErrSessionRevoked    = errors.New("session revoked")
	ErrTokenRotated      = errors.New("refresh token already rotated")
	ErrTokenExpired      = errors.New("token expired")
	ErrTokenReuse        = errors.New("refresh token reuse detected")
	ErrFamilyRevoked     = errors.New("token family revoked due to reuse")
	ErrRetiredKey        = errors.New("retired key cannot sign")
	ErrUnknownKID        = errors.New("unknown key id")
	ErrOverlappingKeys   = errors.New("overlapping active keys")
	ErrMissingKey        = errors.New("no active signing key")
	ErrMalformedToken    = errors.New("malformed token")
	ErrBadSignature      = errors.New("signature verification failed")
	ErrLocked            = errors.New("account locked")
	ErrRateLimited       = errors.New("rate limited")
	ErrBadCredentials    = errors.New("invalid credentials")
	ErrUserDisabled      = errors.New("user disabled")
	ErrCSRFTokenMissing  = errors.New("csrf token missing")
	ErrCSRFTokenMismatch = errors.New("csrf token mismatch")
	ErrInvalidInput      = errors.New("invalid input")
)
