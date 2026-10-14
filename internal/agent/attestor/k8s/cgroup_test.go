package k8s

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixturePodUID      = "2c48913c-b29f-11e7-9350-020968147796"
	fixtureContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestParseCgroupFindsTheContainer(t *testing.T) {
	for _, name := range []string{
		"v1-cgroupfs-docker",
		"v1-systemd-containerd",
		"v2-systemd-containerd",
		"v2-systemd-crio",
		"v2-kind-cgroupns",
		"v2-nested-in-container",
	} {
		t.Run(name, func(t *testing.T) {
			ref, err := parseFixture(t, name)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			want := ContainerRef{PodUID: fixturePodUID, ContainerID: fixtureContainerID}
			if ref != want {
				t.Fatalf("got %+v, want %+v", ref, want)
			}
		})
	}
}

func TestParseCgroupHostProcessIsNotAPod(t *testing.T) {
	for _, name := range []string{"v1-host", "v2-host"} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFixture(t, name); !errors.Is(err, errNotAPod) {
				t.Fatalf("got %v, want errNotAPod", err)
			}
		})
	}
	if _, err := ParseCgroup(strings.NewReader("")); !errors.Is(err, errNotAPod) {
		t.Fatalf("empty file: got %v, want errNotAPod", err)
	}
}

// A process inside a pod's cgroup but not in a container's must be
// refused, not treated as a host process: falling back to the UID
// mapping would hand a pod process a host identity.
func TestParseCgroupRefusesPodProcessOutsideAContainer(t *testing.T) {
	for _, name := range []string{"v2-pod-no-container", "v2-crio-conmon", "v1-disagree", "v2-kubepods-unknown-layout"} {
		t.Run(name, func(t *testing.T) {
			_, err := parseFixture(t, name)
			if err == nil || errors.Is(err, errNotAPod) {
				t.Fatalf("got %v, want a refusal", err)
			}
		})
	}
}

func TestParseCgroupSkipsMalformedLines(t *testing.T) {
	in := "garbage\n0::/kubepods/pod" + fixturePodUID + "/" + fixtureContainerID + "\n"
	ref, err := ParseCgroup(strings.NewReader(in))
	if err != nil || ref.ContainerID != fixtureContainerID {
		t.Fatalf("got %+v, %v", ref, err)
	}
}

func parseFixture(t *testing.T, name string) (ContainerRef, error) {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name+".cgroup"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return ParseCgroup(f)
}
