package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestTypMatches(t *testing.T) {
	cases := []struct {
		got, want string
		ok        bool
	}{
		{"oauth-id-jag+jwt", "oauth-id-jag+jwt", true},
		{"OAuth-ID-JAG+JWT", "oauth-id-jag+jwt", true},
		{"application/oauth-id-jag+jwt", "oauth-id-jag+jwt", true},
		{"JWT", "oauth-id-jag+jwt", false},
		{"", "oauth-id-jag+jwt", false},
	}
	for _, tc := range cases {
		if got := TypMatches(tc.got, tc.want); got != tc.ok {
			t.Errorf("TypMatches(%q, %q) = %v, want %v", tc.got, tc.want, got, tc.ok)
		}
	}
}

func TestCheckTypRejectsAnyMismatchedHeader(t *testing.T) {
	good := jose.Header{ExtraHeaders: map[jose.HeaderKey]any{jose.HeaderType: "oauth-id-jag+jwt"}}
	bad := jose.Header{ExtraHeaders: map[jose.HeaderKey]any{jose.HeaderType: "JWT"}}
	if err := checkTyp([]jose.Header{good}, "oauth-id-jag+jwt"); err != nil {
		t.Errorf("single matching header: %v", err)
	}
	if err := checkTyp([]jose.Header{good, bad}, "oauth-id-jag+jwt"); err == nil {
		t.Error("a mismatched second header must fail")
	}
	if err := checkTyp(nil, "oauth-id-jag+jwt"); err == nil {
		t.Error("no header must fail")
	}
}

func TestValidateByIssuerRouting(t *testing.T) {
	cfg := func(name string) IDPConfig {
		return IDPConfig{Name: name, Issuer: "https://idp.example.com", Audiences: []string{"a"}, SPIFFEIDTemplate: "spiffe://td/{sub}"}
	}
	// header.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9.sig with iss=https://idp.example.com
	tok := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlLmNvbSJ9.c2ln"

	dup, err := NewRegistry([]IDPConfig{cfg("one"), cfg("two")})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := dup.ValidateByIssuer(context.Background(), tok); err == nil || errors.Is(err, ErrUnknownIDP) {
		t.Errorf("duplicate issuer: got %v, want an ambiguity error", err)
	}

	other := cfg("one")
	other.Issuer = "https://other.example.com"
	none, err := NewRegistry([]IDPConfig{other})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := none.ValidateByIssuer(context.Background(), tok); !errors.Is(err, ErrUnknownIDP) {
		t.Errorf("unknown issuer: got %v, want ErrUnknownIDP", err)
	}
}
