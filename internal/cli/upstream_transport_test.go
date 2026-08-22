package cli

import (
	"strings"
	"testing"
)

// Every case here is rejected during flag validation, before anything listens.
func runServerExpectingError(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newServerCommand()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs(append([]string{"--data-dir", t.TempDir()}, args...))
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected startup to fail for args %v", args)
	}
	return err
}

// Neither transport leaves omega without anchors; both lets one shadow the
// other, so a rotation on the wrong one looks like it did nothing.
func TestServerCommandUpstreamNeedsExactlyOneTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "neither",
			args: []string{"--identity-source", "spire-upstream", "--trust-domain", "upstream.example"},
			want: "--identity-source-workload-api is required",
		},
		{
			name: "both",
			args: []string{
				"--identity-source", "spire-upstream",
				"--trust-domain", "upstream.example",
				"--identity-source-bundle", "/nonexistent/bundle.pem",
				"--identity-source-workload-api", "unix:///nonexistent/agent.sock",
			},
			want: "set exactly one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runServerExpectingError(t, tc.args...)
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// Ignoring it would leave the operator believing the upstream is followed
// while omega issues its own SVIDs.
func TestServerCommandRejectsWorkloadAPIOutsideUpstreamMode(t *testing.T) {
	err := runServerExpectingError(t, "--identity-source-workload-api", "unix:///nonexistent/agent.sock")
	if !strings.Contains(err.Error(), "only valid when --identity-source=spire-upstream") {
		t.Fatalf("error should scope the flag to spire-upstream, got: %v", err)
	}
}

func TestServerCommandWorkloadAPIJWTRequiresTheSocket(t *testing.T) {
	err := runServerExpectingError(t,
		"--identity-source", "spire-upstream",
		"--trust-domain", "upstream.example",
		"--identity-source-bundle", "/nonexistent/bundle.pem",
		"--identity-source-workload-api-jwt",
	)
	if !strings.Contains(err.Error(), "requires --identity-source-workload-api") {
		t.Fatalf("error should point at the missing socket flag, got: %v", err)
	}
}

// Pairing the file transport's JWT half with the socket would pin the JWKS
// to a file while the anchors followed the upstream live.
func TestServerCommandRejectsFileJWTBundleWithWorkloadAPI(t *testing.T) {
	err := runServerExpectingError(t,
		"--identity-source", "spire-upstream",
		"--trust-domain", "upstream.example",
		"--identity-source-workload-api", "unix:///nonexistent/agent.sock",
		"--identity-source-jwt-bundle", "/nonexistent/jwks.json",
	)
	if !strings.Contains(err.Error(), "--identity-source-workload-api-jwt") {
		t.Fatalf("error should redirect to the socket's JWT flag, got: %v", err)
	}
}

// The endpoint serves a set of bundles, so the default omega.local would
// publish the wrong domain's anchors or none.
func TestServerCommandWorkloadAPIStillRequiresTrustDomain(t *testing.T) {
	err := runServerExpectingError(t,
		"--identity-source", "spire-upstream",
		"--identity-source-workload-api", "unix:///nonexistent/agent.sock",
	)
	if !strings.Contains(err.Error(), "--trust-domain") {
		t.Fatalf("error should demand an explicit trust domain, got: %v", err)
	}
}
