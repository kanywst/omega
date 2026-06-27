//go:build !windows

package cli

import (
	"os"
	"syscall"
)

// sighupSignals is the set of signals that trigger an in-place audit
// keyring reload. SIGHUP is unix-only, so it lives behind a build tag;
// the server command installs the reload handler only when this is
// non-empty.
var sighupSignals = []os.Signal{syscall.SIGHUP}
