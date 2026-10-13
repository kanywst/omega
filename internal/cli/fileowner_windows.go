//go:build windows

package cli

import "os"

// fileOwner is not available on Windows.
func fileOwner(os.FileInfo) (int, bool) { return 0, false }
