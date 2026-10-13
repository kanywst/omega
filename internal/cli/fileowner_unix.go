//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// fileOwner returns the uid and gid that own fi.
func fileOwner(fi os.FileInfo) (int, int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
