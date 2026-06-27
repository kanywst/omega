//go:build windows

package cli

import "os"

// sighupSignals is empty on Windows, which has no SIGHUP. The audit
// keyring reload handler is therefore not installed; operators rotate
// keys by restarting the process instead.
var sighupSignals []os.Signal
