package cli

import (
	"strings"
	"testing"
)

func TestHasNonEmpty(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{"nil", nil, false},
		{"empty slice", []string{}, false},
		{"single blank", []string{"  "}, false},
		{"empty string", []string{""}, false},
		{"one real value", []string{"https://omega.example.com"}, true},
		{"blank then real", []string{"", "omega"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasNonEmpty(tc.in); got != tc.want {
				t.Errorf("hasNonEmpty(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// Enabling --k8s-attest without an audience leaves TokenReview's
// audience check disabled, which lets any pod's default ServiceAccount
// token be replayed. The server must refuse to start in that state.
func TestServerCommandRequiresK8sTokenAudience(t *testing.T) {
	cmd := newServerCommand()
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{
		"--k8s-attest",
		"--data-dir", t.TempDir(),
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected startup to fail when --k8s-attest is on but no --k8s-token-audience is set")
	}
	if !strings.Contains(err.Error(), "k8s-token-audience") {
		t.Fatalf("error should mention the missing audience flag, got: %v", err)
	}
}
