// SPDX-License-Identifier: AGPL-3.0-only

package wtp

import (
	"strings"
	"unicode"
)

var windowsReserved = map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}

func init() {
	for _, p := range []string{"COM", "LPT"} {
		for i := '1'; i <= '9'; i++ {
			windowsReserved[p+string(i)] = true
		}
	}
}

// ValidateRelativePath enforces the Document-profile portable relative path rules.
func ValidateRelativePath(p string) error {
	if p == "" || strings.ContainsAny(p, "\x00\\") || strings.HasPrefix(p, "/") {
		return errf(ErrTraversal, "unsafe relative_path")
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return errf(ErrTraversal, "path traversal or noncanonical path")
		}
		if strings.HasSuffix(part, " ") || strings.HasSuffix(part, ".") || strings.Contains(part, ":") ||
			strings.IndexFunc(part, unicode.IsControl) >= 0 {
			return errf(ErrTraversal, "non-portable path")
		}
		stem := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if windowsReserved[stem] {
			return errf(ErrTraversal, "Windows reserved device name")
		}
	}
	return nil
}
