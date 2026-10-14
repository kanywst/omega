package attestor

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestListenerReportsPeerCreds(t *testing.T) {
	// macOS caps unix socket paths near 104 bytes, which t.TempDir can exceed.
	dir, err := os.MkdirTemp("", "omega-attestor")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "a.sock")

	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	creds, ok := CredsFromAddr(c.RemoteAddr())
	if !ok {
		t.Fatalf("remote addr %T carries no creds", c.RemoteAddr())
	}
	if creds.UID != uint32(os.Getuid()) {
		t.Fatalf("uid = %d, want %d", creds.UID, os.Getuid())
	}
	// Only Linux reports the peer PID; the Kubernetes attestor needs it.
	wantPID := int32(0)
	if runtime.GOOS == "linux" {
		wantPID = int32(os.Getpid())
	}
	if creds.PID != wantPID {
		t.Fatalf("pid = %d, want %d", creds.PID, wantPID)
	}
	if c.RemoteAddr().String() == "" || c.RemoteAddr().Network() != "unix" {
		t.Fatalf("addr = %q/%q", c.RemoteAddr().Network(), c.RemoteAddr().String())
	}
	if _, ok := CredsFromAddr(&net.UnixAddr{}); ok {
		t.Fatal("a plain addr must not carry creds")
	}
}
