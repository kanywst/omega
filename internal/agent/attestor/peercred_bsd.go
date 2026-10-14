//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package attestor

import "golang.org/x/sys/unix"

// getPeerCreds returns the credentials of the peer connected to the unix socket fd.
//
// Darwin/BSD don't expose SO_PEERCRED. Instead we read the kernel-attested
// peer credentials via getsockopt(SOL_LOCAL, LOCAL_PEERCRED) which returns
// an xucred struct. xucred carries the effective UID and a list of GIDs;
// we surface the first GID as the peer GID for symmetry with Linux ucred.
// The PID is left zero: only the Linux Kubernetes attestor uses it.
func getPeerCreds(fd int) (Creds, error) {
	xu, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return Creds{}, err
	}
	c := Creds{UID: xu.Uid}
	if xu.Ngroups > 0 {
		c.GID = xu.Groups[0]
	}
	return c, nil
}
