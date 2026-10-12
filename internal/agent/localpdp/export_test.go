package localpdp

// FailSpoolWritesForTest makes the next n spool writes write half the
// line and then fail, as a full disk would.
func FailSpoolWritesForTest(n int) func() {
	orig := writeSync
	left := n
	writeSync = func(f spoolFile, b []byte) error {
		if left > 0 {
			left--
			_, _ = f.Write(b[:len(b)/2])
			return errSpoolInjected
		}
		return orig(f, b)
	}
	return func() { writeSync = orig }
}

type injected struct{}

func (injected) Error() string { return "injected spool failure" }

var errSpoolInjected error = injected{}
