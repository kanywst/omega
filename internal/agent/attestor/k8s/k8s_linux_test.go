//go:build linux

package k8s

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Against the real procfs: the test process's own stat and cgroup
// parse, and outside a pod it falls through to the UID mapping
// without calling the apiserver.
func TestAttestOwnProcessOnRealProcfs(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no procfs: %v", err)
	}
	if _, err := ParseCgroup(bytes.NewReader(raw)); !errors.Is(err, errNotAPod) {
		t.Skipf("the test runs inside a pod: %v", err)
	}
	client, err := kubernetes.NewForConfig(&rest.Config{Host: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Client: client, NodeName: testNode, Template: tmpl})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.ParseInt(strconv.Itoa(os.Getpid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.startTime(int32(pid)); err != nil {
		t.Fatalf("start time: %v", err)
	}
	id, ok, err := a.Attest(context.Background(), int32(pid))
	if err != nil || ok || id != "" {
		t.Fatalf("host process: id=%q ok=%v err=%v", id, ok, err)
	}
}
