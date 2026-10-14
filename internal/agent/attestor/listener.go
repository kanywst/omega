// Package attestor identifies workloads connecting to the local agent.
//
// The listener records the peer's UID via SO_PEERCRED on Linux and
// LOCAL_PEERCRED (Getpeereid) on Darwin/BSD, and on Linux its PID,
// which the Kubernetes workload attestor in the k8s subpackage resolves
// to a pod container.
package attestor

import (
	"fmt"
	"net"
	"os"
)

// Creds carries the attested identity of a workload connected to the
// agent's unix socket.
type Creds struct {
	UID uint32
	GID uint32
	// PID is the peer's process ID in the agent's PID namespace, as of
	// connect(). Zero when the platform does not report it or the peer
	// is in a PID namespace the agent cannot see.
	PID int32
}

// CredAddr is the net.Addr surfaced for connections wrapped by Listener.
// gRPC stores this on peer.Peer.Addr; downstream RPC handlers fetch the
// creds via CredsFromAddr.
type CredAddr struct {
	Base  net.Addr
	Creds Creds
}

func (a *CredAddr) Network() string { return a.Base.Network() }
func (a *CredAddr) String() string {
	return fmt.Sprintf("%s(uid=%d,gid=%d)", a.Base.String(), a.Creds.UID, a.Creds.GID)
}

type credConn struct {
	net.Conn
	creds Creds
}

func (c *credConn) RemoteAddr() net.Addr {
	return &CredAddr{Base: c.Conn.RemoteAddr(), Creds: c.creds}
}

// Listener accepts unix-domain connections and tags each one with peer
// credentials extracted via the kernel.
type Listener struct {
	net.Listener
	socketPath string
}

// Listen creates a unix socket at socketPath, removing any stale file
// first, and applies mode 0666 so unprivileged workloads can connect.
func Listen(socketPath string) (*Listener, error) {
	_ = os.Remove(socketPath)
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", socketPath, err)
	}
	// #nosec G302 -- workload socket must be world-accessible; UID is verified at SO_PEERCRED.
	if err := os.Chmod(socketPath, 0o666); err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("chmod %s: %w", socketPath, err)
	}
	return &Listener{Listener: l, socketPath: socketPath}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("attestor: expected *net.UnixConn, got %T", c)
	}
	creds, err := peerCredsOf(uc)
	if err != nil {
		_ = uc.Close()
		return nil, fmt.Errorf("attestor: peer creds: %w", err)
	}
	return &credConn{Conn: uc, creds: creds}, nil
}

func (l *Listener) Close() error {
	err := l.Listener.Close()
	_ = os.Remove(l.socketPath)
	return err
}

func peerCredsOf(uc *net.UnixConn) (Creds, error) {
	raw, err := uc.SyscallConn()
	if err != nil {
		return Creds{}, err
	}
	var (
		creds    Creds
		innerErr error
	)
	if cerr := raw.Control(func(fd uintptr) {
		creds, innerErr = getPeerCreds(int(fd))
	}); cerr != nil {
		return Creds{}, cerr
	}
	if innerErr != nil {
		return Creds{}, innerErr
	}
	return creds, nil
}

// CredsFromAddr extracts peer credentials from a net.Addr, returning
// false if the addr is not a CredAddr (e.g., not from this listener).
func CredsFromAddr(a net.Addr) (Creds, bool) {
	if ca, ok := a.(*CredAddr); ok {
		return ca.Creds, true
	}
	return Creds{}, false
}
