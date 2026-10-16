package policy_test

import (
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
	if id, ok := policy.RequestIDFrom(h); id != "" || !ok {
		t.Fatalf("no header: got (%q, %v), want (\"\", true)", id, ok)
	}
	h.Set(policy.RequestIDHeader, "abc-123")
	if id, ok := policy.RequestIDFrom(h); id != "abc-123" || !ok {
		t.Fatalf("one valid header: got (%q, %v)", id, ok)
	}
	h.Add(policy.RequestIDHeader, "def-456")
	if _, ok := policy.RequestIDFrom(h); ok {
		t.Fatal("two headers must be refused: there is no single id to echo")
	}
	h = http.Header{}
	h.Set(policy.RequestIDHeader, "not ok")
	if _, ok := policy.RequestIDFrom(h); ok {
		t.Fatal("an id outside the charset must be refused")
	}
}
