package k8s

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// ContainerRef is what the cgroup path of a process says about the pod
// container it runs in.
type ContainerRef struct {
	// PodUID is the pod's UID in its canonical dashed form. For a static
	// pod it is the kubelet's config hash, which the mirror pod carries
	// in its kubernetes.io/config.mirror annotation.
	PodUID string
	// ContainerID is the 64-hex runtime ID, without the runtime prefix.
	ContainerID string
}

var (
	// podSegment matches the pod-level cgroup directory under both cgroup
	// drivers: "pod<uid>" (cgroupfs) and "kubepods-<qos>-pod<uid_with_underscores>.slice"
	// (systemd, including kind's "kubelet-kubepods-..." prefix).
	podSegment = regexp.MustCompile(`(?:^|[-_])pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})(?:\.slice)?$`)
	// containerSegment matches the container's directory directly under
	// the pod's: a bare ID (cgroupfs) or "<runtime>-<id>.scope" (systemd)
	// for containerd, CRI-O and Docker. CRI-O's "crio-conmon-<id>.scope"
	// holds the monitor process, not the container, and does not match.
	containerSegment = regexp.MustCompile(`^(?:cri-containerd-|crio-|docker-)?([0-9a-f]{64})(?:\.scope)?$`)
)

// errNotAPod is returned when no line of a cgroup file names a pod.
var errNotAPod = errors.New("process is not in a Kubernetes pod cgroup")

// ParseCgroup reads a /proc/<pid>/cgroup file (cgroup v1 or v2) and
// returns the pod container the process belongs to. It returns
// errNotAPod when the process is not in a pod (a host process), and an
// error when the lines disagree or the process sits in a pod cgroup
// but outside any container (the pod sandbox or a stray process).
//
// The path is matched anywhere in the line rather than from the root:
// when the agent runs in its own cgroup namespace the kernel shows
// other processes' paths relative to it ("/../../kubepods.slice/...").
func ParseCgroup(r io.Reader) (ContainerRef, error) {
	var (
		found ContainerRef
		inPod bool
	)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// hierarchy-ID:controller-list:cgroup-path; the path may itself
		// contain colons, so split into exactly three fields.
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		ref, ok, err := parseCgroupPath(parts[2])
		if err != nil {
			return ContainerRef{}, err
		}
		if !ok {
			continue
		}
		if inPod && ref != found {
			return ContainerRef{}, fmt.Errorf("cgroup hierarchies disagree on the container: %s/%s and %s/%s", found.PodUID, found.ContainerID, ref.PodUID, ref.ContainerID)
		}
		found, inPod = ref, true
	}
	if err := sc.Err(); err != nil {
		return ContainerRef{}, fmt.Errorf("read cgroup: %w", err)
	}
	if !inPod {
		return ContainerRef{}, errNotAPod
	}
	return found, nil
}

func parseCgroupPath(path string) (ContainerRef, bool, error) {
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		m := podSegment.FindStringSubmatch(seg)
		if m == nil {
			continue
		}
		podUID := strings.ReplaceAll(m[1], "_", "-")
		if i+1 >= len(segs) {
			return ContainerRef{}, false, fmt.Errorf("process is in pod %s but in no container", podUID)
		}
		c := containerSegment.FindStringSubmatch(segs[i+1])
		if c == nil {
			return ContainerRef{}, false, fmt.Errorf("process is in pod %s but cgroup %q names no container", podUID, segs[i+1])
		}
		return ContainerRef{PodUID: podUID, ContainerID: c[1]}, true, nil
	}
	return ContainerRef{}, false, nil
}
