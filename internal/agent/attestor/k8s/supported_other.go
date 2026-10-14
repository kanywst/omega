//go:build !linux

package k8s

// Supported reports whether this platform can run the attestor: it
// reads the peer's cgroup from Linux procfs.
const Supported = false
