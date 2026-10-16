package policy_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/policy"
)

func TestValidRequestID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"bfe9eb29-ab87-4ca3-be83-a1d5d8305716", true},
		{"01J9ZQ3K8X5V7W2M4N6P8R0T2Y", true},
		{"Root=1-67891233-abcdef012345678912345678;Parent=53995c3f42cd8ad8", true},
		{"a+b/c=@d.e_f~g:h", true},
		{strings.Repeat("a", policy.MaxRequestIDBytes), true},
		{"", false},
		{strings.Repeat("a", policy.MaxRequestIDBytes+1), false},
		{"has space", false},
		{`quote"d`, false},
		{`back\slash`, false},
		{"tab\there", false},
		{"new\nline", false},
		{"café", false},
		{"<script>", false},
	}
	for _, tc := range cases {
		if got := policy.ValidRequestID(tc.id); got != tc.want {
			t.Errorf("ValidRequestID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

func TestRequestIDFrom(t *testing.T) {
	h := http.Header{}
	if id := policy.RequestIDFrom(h); id != "" {
		t.Fatalf("no header: got %q", id)
	}
	h.Set(policy.RequestIDHeader, "abc-123")
	if id := policy.RequestIDFrom(h); id != "abc-123" {
		t.Fatalf("one header: got %q", id)
	}
	h.Add(policy.RequestIDHeader, "def-456")
	if id := policy.RequestIDFrom(h); id != "abc-123, def-456" {
		t.Fatalf("two header lines are one field: got %q", id)
	}
}

func TestRequestIDForAudit(t *testing.T) {
	if p, d := policy.RequestIDForAudit(""); p != "" || d != "" {
		t.Errorf("empty: (%q, %q)", p, d)
	}
	if p, d := policy.RequestIDForAudit("abc-123"); p != "abc-123" || d != "" {
		t.Errorf("valid: (%q, %q)", p, d)
	}
	unsafe := `id with "quotes" and spaces`
	sum := sha256.Sum256([]byte(unsafe))
	if p, d := policy.RequestIDForAudit(unsafe); p != "" || d != hex.EncodeToString(sum[:]) {
		t.Errorf("unsafe: (%q, %q), want only its digest", p, d)
	}
}
