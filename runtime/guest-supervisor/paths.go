package supervisor

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// CheckWorkspacePath rejects absolute paths, escaping relative paths, and
// any name containing control characters, whitespace, or backslash. The
// character rule is not aesthetic: workspace paths are interpolated into
// debugfs command scripts (whitespace-tokenized, newline-delimited, no
// quoting), so a newline is command injection and a space is argument
// injection (verified against debugfs 1.47). Both the in-guest agent and
// the host-side image builder enforce this independently (defense in
// depth): a name minted by root inside a guest must be rejected at the
// next materialization boundary.
func CheckWorkspacePath(path string) error {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("unsafe workspace path: %q", path)
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '\\' {
			return fmt.Errorf("workspace path %q contains illegal character %q", path, r)
		}
	}
	return nil
}
