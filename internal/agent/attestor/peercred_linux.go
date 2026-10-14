//go:build linux

package attestor

import "golang.org/x/sys/unix"

// getPeerCreds returns the credentials of the peer connected to the unix socket fd.
func getPeerCreds(fd int) (Creds, error) {
	cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return Creds{}, err
	}
	return Creds{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, nil
}
