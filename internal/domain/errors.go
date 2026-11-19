package domain

import (
	"errors"
	"fmt"
)

// Code classifies an error for callers. The HTTP layer maps codes to status
// codes; anything without a code is treated as an internal error and its
// details are never sent to the client.
type Code string

const (
	CodeInvalid      Code = "invalid"          // 400
	CodeUnauthorized Code = "unauthorized"     // 401
	CodeForbidden    Code = "forbidden"        // 403
	CodeReauth       Code = "reauth_required"  // 403: sign in again first
	CodeNotFound     Code = "not_found"        // 404
	CodeConflict     Code = "conflict"         // 409
	CodeConfirm      Code = "confirm_required" // 409: repeat with confirmation
	CodeGone         Code = "gone"             // 410
	CodePrecondition Code = "precondition"     // 412
	CodeTooLarge     Code = "too_large"        // 413
	CodeRateLimited  Code = "rate_limited"     // 429
	CodeQuota        Code = "quota_exceeded"   // 507
)

// Error is a client-safe error: Message may be shown to the caller.
type Error struct {
	Code    Code
	Message string
	// Detail is an optional, client-safe structured hint (e.g. the ID of
	// a conflicting node the caller is already allowed to see).
	Detail map[string]string
}

func (e *Error) Error() string { return string(e.Code) + ": " + e.Message }

// Is lets errors.Is match on code, so ErrNotFound matches any not-found error.
func (e *Error) Is(target error) bool {
	var t *Error
	if errors.As(target, &t) {
		return t.Code == e.Code && t.Message == ""
	}
	return false
}

// Sentinels for errors.Is checks. They carry no message, so they match any
// error with the same code.
var (
	ErrInvalid      = &Error{Code: CodeInvalid}
	ErrUnauthorized = &Error{Code: CodeUnauthorized}
	ErrForbidden    = &Error{Code: CodeForbidden}
	ErrNotFound     = &Error{Code: CodeNotFound}
	ErrConflict     = &Error{Code: CodeConflict}
	ErrGone         = &Error{Code: CodeGone}
	ErrPrecondition = &Error{Code: CodePrecondition}
	ErrTooLarge     = &Error{Code: CodeTooLarge}
	ErrRateLimited  = &Error{Code: CodeRateLimited}
	ErrQuota        = &Error{Code: CodeQuota}
)

// E builds a client-safe error.
func E(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CodeOf returns the error's code, or "" for internal errors.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
