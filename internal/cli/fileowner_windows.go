//go:build windows

package cli

import "os"

// fileOwner is not available on Windows.
func fileOwner(os.FileInfo) (int, int, bool) { return 0, 0, false }

// openDirNoFollow opens path; Windows has no O_NOFOLLOW.
func openDirNoFollow(path string) (*os.File, error) { return os.Open(path) } // #nosec G304 -- operator-supplied path
