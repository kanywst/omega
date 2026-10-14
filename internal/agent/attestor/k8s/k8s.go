// Package k8s is the node agent's Kubernetes workload attestor.
//
// It identifies the process on the other end of a Workload API
// connection as a container of a pod on this node: the peer PID's
// /proc/<pid>/cgroup names the pod UID and container ID, and the pod
// is looked up in kube-apiserver among the pods scheduled to this node.
// The pod's namespace, service account and name fill the SPIFFE ID
// template, with the same placeholders as the server's --k8s-svid-template.
//
// It serves the self-issued development and evaluation path. It is not
// a substitute for a production workload attestor such as SPIRE's; see
// ADR 0020 for what it does not do.
package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"

	"github.com/kanywst/omega/internal/server/attest"
)

// ErrNotAttested wraps every failure that means "this process is not a
// workload we can vouch for", as opposed to a kube-apiserver or
// procfs failure that a retry may cure. The Workload API answers the
// former with PermissionDenied and the latter with Unavailable.
var ErrNotAttested = errors.New("k8s workload attestation failed")

// mirrorAnnotation holds a static pod's config hash, which is the UID
// its cgroup path carries, on the mirror pod kube-apiserver serves.
const mirrorAnnotation = "kubernetes.io/config.mirror"

// minRelist bounds how often a cache miss may re-list the node's pods,
// so a process probing the socket cannot turn into apiserver load.
const minRelist = time.Second

// Config wires an Attestor.
type Config struct {
	// Client reaches kube-apiserver. The agent's service account needs
	// list on pods; the list is filtered to NodeName server-side.
	Client kubernetes.Interface
	// NodeName is the node the agent runs on (spec.nodeName).
	NodeName string
	// Template renders the SPIFFE ID; placeholders {namespace},
	// {serviceaccount} and {podname}.
	Template string
	// ProcRoot is the procfs mount; empty means /proc.
	ProcRoot string
}

// Workload is an attested pod container.
type Workload struct {
	Namespace      string
	ServiceAccount string
	PodName        string
	PodUID         string
	ContainerName  string
	ContainerID    string
	Labels         map[string]string
}

// Selectors lists the workload's attributes in the SPIFFE ecosystem's
// "type:key:value" selector form, for the agent's log. Omega does
// not match registration entries against them; the SPIFFE ID comes
// from the template.
func (w *Workload) Selectors() []string {
	out := []string{
		"k8s:ns:" + w.Namespace,
		"k8s:sa:" + w.ServiceAccount,
		"k8s:pod-name:" + w.PodName,
		"k8s:pod-uid:" + w.PodUID,
		"k8s:container-name:" + w.ContainerName,
	}
	labels := make([]string, 0, len(w.Labels))
	for k, v := range w.Labels {
		labels = append(labels, "k8s:pod-label:"+k+":"+v)
	}
	sort.Strings(labels)
	return append(out, labels...)
}

// Attestor resolves peer PIDs to pod containers on one node.
type Attestor struct {
	client   kubernetes.Interface
	node     string
	template string
	procRoot string
	now      func() time.Time
	log      io.Writer

	mu       sync.Mutex
	pods     map[string]*corev1.Pod // keyed by UID
	mirrors  map[string]*corev1.Pod // static pods' mirror pods, keyed by config hash
	listedAt time.Time
}

// New checks cfg and returns an Attestor. The template must render a
// valid SPIFFE ID; the trust domain is checked by the control plane
// when it issues.
func New(cfg Config) (*Attestor, error) {
	if cfg.Client == nil {
		return nil, errors.New("k8s workload attestor: no kube-apiserver client")
	}
	if cfg.NodeName == "" {
		return nil, errors.New("k8s workload attestor: node name is required (set --k8s-node-name or NODE_NAME from the downward API)")
	}
	probe, err := attest.RenderSPIFFEID(cfg.Template, &attest.K8sClaims{Namespace: "ns", ServiceAccount: "sa", PodName: "pod"})
	if err != nil {
		return nil, fmt.Errorf("k8s workload attestor: template: %w", err)
	}
	if _, err := spiffeid.FromString(probe); err != nil {
		return nil, fmt.Errorf("k8s workload attestor: template %q does not render a SPIFFE ID: %w", cfg.Template, err)
	}
	root := cfg.ProcRoot
	if root == "" {
		root = "/proc"
	}
	return &Attestor{
		client:   cfg.Client,
		node:     cfg.NodeName,
		template: cfg.Template,
		procRoot: root,
		now:      time.Now,
		log:      os.Stderr,
	}, nil
}

// Attest returns the SPIFFE ID for the process pid. ok is false when
// the process is not in a pod at all (a host process), so the caller
// can fall back to UID attestation; a process that is in a pod is
// either attested here or refused, never handed to the UID mapping.
func (a *Attestor) Attest(ctx context.Context, pid int32) (id string, ok bool, err error) {
	w, ok, err := a.Workload(ctx, pid)
	if err != nil || !ok {
		return "", ok, err
	}
	id, err = attest.RenderSPIFFEID(a.template, &attest.K8sClaims{
		Namespace:      w.Namespace,
		ServiceAccount: w.ServiceAccount,
		PodName:        w.PodName,
	})
	if err != nil {
		return "", true, fmt.Errorf("%w: %w", ErrNotAttested, err)
	}
	fmt.Fprintf(a.log, "omega agent: k8s attested pid=%d as %s %v\n", pid, id, w.Selectors())
	return id, true, nil
}

// Workload attests pid and returns the pod container it runs in. See
// Attest for the meaning of ok.
func (a *Attestor) Workload(ctx context.Context, pid int32) (*Workload, bool, error) {
	if pid <= 0 {
		return nil, false, fmt.Errorf("%w: the kernel reported no peer PID; the agent must share the host PID namespace (hostPID)", ErrNotAttested)
	}
	start, err := a.startTime(pid)
	if err != nil {
		return nil, false, err
	}
	ref, err := a.containerRef(pid)
	if errors.Is(err, errNotAPod) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	pod, err := a.lookup(ctx, ref)
	if err != nil {
		return nil, true, err
	}
	name, err := containerName(pod, ref.ContainerID)
	if err != nil {
		return nil, true, err
	}
	// A PID is only a name for a process while it lives. If the peer
	// exited and the PID was reused while we looked, the start time
	// changed; refuse rather than attest the newcomer. This narrows the
	// reuse window to the gap between connect and the first read, which
	// a pidfd would close (ADR 0020).
	if again, err := a.startTime(pid); err != nil || again != start {
		return nil, true, fmt.Errorf("%w: process %d exited or was replaced during attestation", ErrNotAttested, pid)
	}
	return &Workload{
		Namespace:      pod.Namespace,
		ServiceAccount: serviceAccountOf(pod),
		PodName:        pod.Name,
		PodUID:         string(pod.UID),
		ContainerName:  name,
		ContainerID:    ref.ContainerID,
		Labels:         pod.Labels,
	}, true, nil
}

func (a *Attestor) containerRef(pid int32) (ContainerRef, error) {
	f, err := os.Open(filepath.Join(a.procRoot, strconv.Itoa(int(pid)), "cgroup"))
	if err != nil {
		return ContainerRef{}, fmt.Errorf("%w: read cgroup of process %d: %w", ErrNotAttested, pid, err)
	}
	defer f.Close()
	ref, err := ParseCgroup(f)
	if err != nil && !errors.Is(err, errNotAPod) {
		return ContainerRef{}, fmt.Errorf("%w: process %d: %w", ErrNotAttested, pid, err)
	}
	return ref, err
}

// startTime is field 22 of /proc/<pid>/stat: the process start time in
// clock ticks after boot. The comm field (2) may hold spaces and
// parentheses, so fields are counted from the last ')'.
func (a *Attestor) startTime(pid int32) (string, error) {
	raw, err := os.ReadFile(filepath.Join(a.procRoot, strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return "", fmt.Errorf("%w: read stat of process %d: %w", ErrNotAttested, pid, err)
	}
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 {
		return "", fmt.Errorf("%w: malformed stat for process %d", ErrNotAttested, pid)
	}
	f := strings.Fields(string(raw[i+1:]))
	const startTimeIdx = 22 - 3 // fields after ')' start at field 3
	if len(f) <= startTimeIdx {
		return "", fmt.Errorf("%w: malformed stat for process %d", ErrNotAttested, pid)
	}
	return f[startTimeIdx], nil
}

// lookup finds the pod for ref among the pods on this node, re-listing
// on a miss (a pod scheduled since the last list) or when the pod is
// known but the container is not yet in its status (just started).
func (a *Attestor) lookup(ctx context.Context, ref ContainerRef) (*corev1.Pod, error) {
	a.mu.Lock()
	pod := a.podLocked(ref.PodUID)
	fresh := a.now().Sub(a.listedAt) < minRelist
	a.mu.Unlock()
	if pod != nil && hasContainer(pod, ref.ContainerID) {
		return pod, nil
	}
	if !fresh {
		if err := a.relist(ctx); err != nil {
			return nil, err
		}
		a.mu.Lock()
		pod = a.podLocked(ref.PodUID)
		a.mu.Unlock()
	}
	if pod == nil {
		return nil, fmt.Errorf("%w: no pod with UID %s on node %s", ErrNotAttested, ref.PodUID, a.node)
	}
	return pod, nil
}

func (a *Attestor) relist(ctx context.Context) error {
	list, err := a.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("spec.nodeName", a.node).String(),
	})
	if err != nil {
		return fmt.Errorf("list pods on node %s: %w", a.node, err)
	}
	pods := make(map[string]*corev1.Pod, len(list.Items))
	mirrors := map[string]*corev1.Pod{}
	for i := range list.Items {
		p := &list.Items[i]
		// The field selector already filters; checking again keeps a
		// misbehaving or impersonated apiserver response from naming a
		// pod on another node.
		if p.Spec.NodeName != a.node {
			continue
		}
		pods[string(p.UID)] = p
		if hash := p.Annotations[mirrorAnnotation]; hash != "" && ownedByNode(p, a.node) {
			mirrors[hash] = p
		}
	}
	a.mu.Lock()
	a.pods, a.mirrors, a.listedAt = pods, mirrors, a.now()
	a.mu.Unlock()
	return nil
}

// podLocked returns the pod with uid, or the mirror pod of the static
// pod whose config hash is uid. Real UIDs come first and mirror hashes
// live apart, so a pod that copies another's UID into its annotation
// cannot shadow it.
func (a *Attestor) podLocked(uid string) *corev1.Pod {
	if p := a.pods[uid]; p != nil {
		return p
	}
	return a.mirrors[uid]
}

// ownedByNode reports whether the kubelet of node created p as a mirror
// pod: the kubelet sets the Node as its controller owner, which a user
// creating an ordinary pod with the annotation does not get.
func ownedByNode(p *corev1.Pod, node string) bool {
	for _, o := range p.OwnerReferences {
		if o.Kind == "Node" && o.APIVersion == "v1" && o.Name == node && o.Controller != nil && *o.Controller {
			return true
		}
	}
	return false
}

func hasContainer(pod *corev1.Pod, id string) bool {
	_, err := containerName(pod, id)
	return err == nil
}

// containerName finds the container whose runtime ID is id among the
// pod's regular, init and ephemeral container statuses. The status
// holds "<runtime>://<id>".
func containerName(pod *corev1.Pod, id string) (string, error) {
	for _, set := range [][]corev1.ContainerStatus{pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses, pod.Status.EphemeralContainerStatuses} {
		for _, cs := range set {
			if _, cid, ok := strings.Cut(cs.ContainerID, "://"); ok && cid == id {
				return cs.Name, nil
			}
		}
	}
	return "", fmt.Errorf("%w: pod %s/%s has no container %s", ErrNotAttested, pod.Namespace, pod.Name, id)
}

func serviceAccountOf(pod *corev1.Pod) string {
	if pod.Spec.ServiceAccountName != "" {
		return pod.Spec.ServiceAccountName
	}
	return "default"
}
