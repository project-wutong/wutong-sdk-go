// SPDX-License-Identifier: AGPL-3.0-only

package wtp

import "fmt"

// Code is a WTP error code (WTP-STD-001 §14).
type Code string

// Error codes used by this package.
const (
	ErrSchema    Code = "ERR_SCHEMA"
	ErrSignature Code = "ERR_SIGNATURE"
	ErrTraversal Code = "ERR_PATH_TRAVERSAL"
	ErrState     Code = "ERR_STATE"
)

// Error is a protocol error carrying a WTP error code.
type Error struct {
	Code   Code
	Detail string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Detail) }

func errf(c Code, format string, a ...any) error {
	return &Error{Code: c, Detail: fmt.Sprintf(format, a...)}
}
