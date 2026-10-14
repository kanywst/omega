package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const testNode = "node-a"

// fakeAPIServer serves GET /api/v1/pods from a mutable pod list and
// records the field selectors it was asked for, standing in for
// kube-apiserver behind a real client-go clientset.
type fakeAPIServer struct {
	mu        sync.Mutex
	pods      []corev1.Pod
	selectors []string
	lists     atomic.Int32
	fail      bool
	onList    func()
}

func (f *fakeAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/pods" {
		http.NotFound(w, r)
		return
	}
	f.lists.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.selectors = append(f.selectors, r.URL.Query().Get("fieldSelector"))
	if f.onList != nil {
		f.onList()
	}
	if f.fail {
		http.Error(w, "etcd is on fire", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(corev1.PodList{
		TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"},
		Items:    f.pods,
	})
}

func (f *fakeAPIServer) setPods(p ...corev1.Pod) {
	f.mu.Lock()
	f.pods = p
	f.mu.Unlock()
}

func pod(uid, ns, name, sa, node, containerID string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID(uid), Namespace: ns, Name: name, Labels: map[string]string{"app": name}},
		Spec:       corev1.PodSpec{NodeName: node, ServiceAccountName: sa},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "main", ContainerID: "containerd://" + containerID},
		}},
	}
}

// writeProc lays out <root>/<pid>/{cgroup,stat} like procfs.
func writeProc(t *testing.T, root string, pid int, cgroup, startTime string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cgroup), 0o600); err != nil {
		t.Fatal(err)
	}
	// comm with a space and a ')' to exercise the last-paren split.
	stat := strconv.Itoa(pid) + " (my) proc) S 1 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 " + startTime + " 1000 10\n"
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
}

func podCgroup(uid, containerID string) string {
	return "0::/kubepods.slice/kubepods-pod" + uid + ".slice/cri-containerd-" + containerID + ".scope\n"
}

type harness struct {
	api   *fakeAPIServer
	att   *Attestor
	proc  string
	clock time.Time
}

func newHarness(t *testing.T, template string) *harness {
	t.Helper()
	api := &fakeAPIServer{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{api: api, proc: t.TempDir(), clock: time.Unix(1_700_000_000, 0)}
	att, err := New(Config{Client: client, NodeName: testNode, Template: template, ProcRoot: h.proc})
	if err != nil {
		t.Fatal(err)
	}
	att.now = func() time.Time { return h.clock }
	att.log = io.Discard
	h.att = att
	return h
}

const tmpl = "spiffe://omega.local/k8s/{namespace}/{serviceaccount}"

func TestAttestRendersTheTemplateFromThePod(t *testing.T) {
	h := newHarness(t, tmpl)
	h.api.setPods(pod(fixturePodUID, "apps", "web-1", "web", testNode, fixtureContainerID))
	writeProc(t, h.proc, 4242, podCgroup(fixturePodUID, fixtureContainerID), "777")

	id, ok, err := h.att.Attest(context.Background(), 4242)
	if err != nil || !ok {
		t.Fatalf("attest: ok=%v err=%v", ok, err)
	}
	if id != "spiffe://omega.local/k8s/apps/web" {
		t.Fatalf("id = %q", id)
	}
	if got := h.api.selectors; len(got) != 1 || got[0] != "spec.nodeName="+testNode {
		t.Fatalf("field selectors = %q, want one spec.nodeName=%s", got, testNode)
	}

	// The pod is cached: a second attestation does not re-list.
	if _, _, err := h.att.Attest(context.Background(), 4242); err != nil {
		t.Fatal(err)
	}
	if n := h.api.lists.Load(); n != 1 {
		t.Fatalf("lists = %d, want 1", n)
	}
}

func TestWorkloadDetailsAndSelectors(t *testing.T) {
	h := newHarness(t, tmpl)
	p := pod(fixturePodUID, "apps", "web-1", "", testNode, fixtureContainerID)
	p.Status.ContainerStatuses = nil
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ContainerID: "cri-o://" + fixtureContainerID}}
	h.api.setPods(p)
	writeProc(t, h.proc, 7, podCgroup(fixturePodUID, fixtureContainerID), "1")

	w, ok, err := h.att.Workload(context.Background(), 7)
	if err != nil || !ok {
		t.Fatalf("workload: ok=%v err=%v", ok, err)
	}
	if w.ServiceAccount != "default" || w.ContainerName != "init" || w.PodUID != fixturePodUID {
		t.Fatalf("workload = %+v", w)
	}
	want := []string{
		"k8s:ns:apps", "k8s:sa:default", "k8s:pod-name:web-1", "k8s:pod-uid:" + fixturePodUID,
		"k8s:container-name:init", "k8s:pod-label:app:web-1",
	}
	if got := w.Selectors(); !slices.Equal(got, want) {
		t.Fatalf("selectors = %q, want %q", got, want)
	}
}

func TestAttestPodNameTemplate(t *testing.T) {
	h := newHarness(t, "spiffe://omega.local/ns/{namespace}/pod/{podname}")
	h.api.setPods(pod(fixturePodUID, "apps", "web-1", "web", testNode, fixtureContainerID))
	writeProc(t, h.proc, 9, podCgroup(fixturePodUID, fixtureContainerID), "1")
	id, _, err := h.att.Attest(context.Background(), 9)
	if err != nil || id != "spiffe://omega.local/ns/apps/pod/web-1" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestAttestHostProcessFallsThrough(t *testing.T) {
	h := newHarness(t, tmpl)
	writeProc(t, h.proc, 1, "0::/system.slice/sshd.service\n", "1")
	id, ok, err := h.att.Attest(context.Background(), 1)
	if err != nil || ok || id != "" {
		t.Fatalf("host process: id=%q ok=%v err=%v", id, ok, err)
	}
	if n := h.api.lists.Load(); n != 0 {
		t.Fatalf("a host process must not reach the apiserver, lists = %d", n)
	}
}

func TestAttestStaticPodByMirrorAnnotation(t *testing.T) {
	h := newHarness(t, tmpl)
	const configHash = "0f0f0f0f-0000-1111-2222-333333333333"
	mirror := pod("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "kube-system", "etcd-node-a", "", testNode, fixtureContainerID)
	mirror.Annotations = map[string]string{mirrorAnnotation: configHash}
	mirror.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: testNode, Controller: ptr(true)}}
	h.api.setPods(mirror)
	writeProc(t, h.proc, 11, podCgroup(configHash, fixtureContainerID), "1")
	id, ok, err := h.att.Attest(context.Background(), 11)
	if err != nil || !ok || id != "spiffe://omega.local/k8s/kube-system/default" {
		t.Fatalf("id=%q ok=%v err=%v", id, ok, err)
	}
}

func TestAttestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		pods  []corev1.Pod
		pid   int32
		write bool
	}{
		{name: "pod not on the node", pods: nil, pid: 20, write: true},
		{name: "pod on another node ignored", pods: []corev1.Pod{pod(fixturePodUID, "apps", "web-1", "web", "node-b", fixtureContainerID)}, pid: 21, write: true},
		{name: "container not in the pod", pods: []corev1.Pod{pod(fixturePodUID, "apps", "web-1", "web", testNode, "ffff")}, pid: 22, write: true},
		{name: "no peer pid", pid: 0},
		{name: "process gone", pid: 23},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tmpl)
			h.api.setPods(tc.pods...)
			if tc.write {
				writeProc(t, h.proc, int(tc.pid), podCgroup(fixturePodUID, fixtureContainerID), "1")
			}
			_, _, err := h.att.Attest(context.Background(), tc.pid)
			if !errors.Is(err, ErrNotAttested) {
				t.Fatalf("got %v, want ErrNotAttested", err)
			}
		})
	}
}

func TestAttestPodInCgroupButNotInContainerIsRefused(t *testing.T) {
	h := newHarness(t, tmpl)
	writeProc(t, h.proc, 30, "0::/kubepods.slice/kubepods-pod"+fixturePodUID+".slice\n", "1")
	_, ok, err := h.att.Attest(context.Background(), 30)
	if !ok || !errors.Is(err, ErrNotAttested) {
		t.Fatalf("ok=%v err=%v, want a refusal that does not fall through", ok, err)
	}
}

func TestAttestAPIServerFailureIsNotARefusal(t *testing.T) {
	h := newHarness(t, tmpl)
	h.api.fail = true
	writeProc(t, h.proc, 40, podCgroup(fixturePodUID, fixtureContainerID), "1")
	_, _, err := h.att.Attest(context.Background(), 40)
	if err == nil || errors.Is(err, ErrNotAttested) {
		t.Fatalf("got %v, want a transient error", err)
	}
}

// A new pod is found by re-listing on a miss, but at most once per
// minRelist, so a stream of unknown processes cannot flood the
// apiserver. A miss inside the interval is transient (the client
// retries), not a refusal.
func TestLookupRelistsOnMissAtMostOncePerInterval(t *testing.T) {
	h := newHarness(t, tmpl)
	writeProc(t, h.proc, 50, podCgroup(fixturePodUID, fixtureContainerID), "1")

	if _, _, err := h.att.Attest(context.Background(), 50); !errors.Is(err, ErrNotAttested) {
		t.Fatalf("before the pod exists: %v", err)
	}
	h.api.setPods(pod(fixturePodUID, "apps", "web-1", "web", testNode, fixtureContainerID))
	if _, _, err := h.att.Attest(context.Background(), 50); err == nil || errors.Is(err, ErrNotAttested) {
		t.Fatalf("within the relist interval: got %v, want a transient error", err)
	}
	if n := h.api.lists.Load(); n != 1 {
		t.Fatalf("lists = %d, want 1", n)
	}
	h.clock = h.clock.Add(minRelist)
	if _, ok, err := h.att.Attest(context.Background(), 50); err != nil || !ok {
		t.Fatalf("after the interval: ok=%v err=%v", ok, err)
	}
	if n := h.api.lists.Load(); n != 2 {
		t.Fatalf("lists = %d, want 2", n)
	}
}

// If the peer exits and its PID is reused while the pod is looked up,
// the start time changes and the newcomer is not attested.
func TestAttestRefusesAProcessReplacedDuringLookup(t *testing.T) {
	h := newHarness(t, tmpl)
	h.api.setPods(pod(fixturePodUID, "apps", "web-1", "web", testNode, fixtureContainerID))
	writeProc(t, h.proc, 60, podCgroup(fixturePodUID, fixtureContainerID), "100")
	h.api.onList = func() { writeProc(t, h.proc, 60, podCgroup(fixturePodUID, fixtureContainerID), "200") }
	if _, _, err := h.att.Attest(context.Background(), 60); !errors.Is(err, ErrNotAttested) {
		t.Fatalf("got %v, want ErrNotAttested", err)
	}
}

func TestStartTimeRejectsMalformedStat(t *testing.T) {
	h := newHarness(t, tmpl)
	for i, stat := range []string{"no paren here", "1 (x) S 1 2"} {
		pid := 70 + i
		dir := filepath.Join(h.proc, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := h.att.startTime(int32(pid)); !errors.Is(err, ErrNotAttested) {
			t.Fatalf("%q: got %v", stat, err)
		}
	}
}

func TestNewValidatesConfig(t *testing.T) {
	client, err := kubernetes.NewForConfig(&rest.Config{Host: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cfg  Config
	}{
		{"no client", Config{NodeName: testNode, Template: tmpl}},
		{"no node", Config{Client: client, Template: tmpl}},
		{"not a spiffe id", Config{Client: client, NodeName: testNode, Template: "https://example.com/{namespace}"}},
		{"empty template", Config{Client: client, NodeName: testNode}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
	a, err := New(Config{Client: client, NodeName: testNode, Template: tmpl})
	if err != nil || a.procRoot != "/proc" {
		t.Fatalf("defaults: %v %+v", err, a)
	}
}

// The mirror annotation counts only on a pod the node's kubelet owns,
// and never shadows a real UID: a user pod that copies another pod's
// UID into the annotation must not make that pod unattestable.
func TestMirrorAnnotationIsTrustedOnlyOnNodeOwnedPods(t *testing.T) {
	const configHash = "0f0f0f0f-0000-1111-2222-333333333333"
	h := newHarness(t, tmpl)
	fake := pod("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "evil", "fake", "", testNode, fixtureContainerID)
	fake.Annotations = map[string]string{mirrorAnnotation: configHash}
	h.api.setPods(fake)
	writeProc(t, h.proc, 12, podCgroup(configHash, fixtureContainerID), "1")
	if _, _, err := h.att.Attest(context.Background(), 12); !errors.Is(err, ErrNotAttested) {
		t.Fatalf("a mirror annotation on a user pod was honoured: %v", err)
	}

	h = newHarness(t, tmpl)
	victim := pod(fixturePodUID, "apps", "web-1", "web", testNode, fixtureContainerID)
	squatter := pod("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "evil", "squat", "", testNode, "ffff")
	squatter.Annotations = map[string]string{mirrorAnnotation: fixturePodUID}
	squatter.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Node", Name: testNode, Controller: ptr(true)}}
	h.api.setPods(squatter, victim)
	writeProc(t, h.proc, 13, podCgroup(fixturePodUID, fixtureContainerID), "1")
	if id, _, err := h.att.Attest(context.Background(), 13); err != nil || id != "spiffe://omega.local/k8s/apps/web" {
		t.Fatalf("victim: id=%q err=%v", id, err)
	}
}

func ptr[T any](v T) *T { return &v }

// A failed list still counts against minRelist, so a failing apiserver
// is not retried on every connection.
func TestFailedListIsThrottledToo(t *testing.T) {
	h := newHarness(t, tmpl)
	h.api.fail = true
	writeProc(t, h.proc, 80, podCgroup(fixturePodUID, fixtureContainerID), "1")
	for range 3 {
		if _, _, err := h.att.Attest(context.Background(), 80); err == nil || errors.Is(err, ErrNotAttested) {
			t.Fatalf("got %v, want a transient error", err)
		}
	}
	if n := h.api.lists.Load(); n != 1 {
		t.Fatalf("lists = %d, want 1", n)
	}
}

// Concurrent misses share one list, and every one of them finds the
// pod that list fetched.
func TestConcurrentMissesShareOneList(t *testing.T) {
	h := newHarness(t, tmpl)
	h.api.setPods(pod(fixturePodUID, "apps", "web-1", "web", testNode, fixtureContainerID))
	writeProc(t, h.proc, 90, podCgroup(fixturePodUID, fixtureContainerID), "1")
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() {
			if _, _, err := h.att.Attest(context.Background(), 90); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("attest: %v", err)
	}
	if n := h.api.lists.Load(); n != 1 {
		t.Fatalf("lists = %d, want 1", n)
	}
}
