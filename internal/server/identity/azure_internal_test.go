package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAzureKeyVaultScope(t *testing.T) {
	cases := map[string]string{
		"https://myvault.vault.azure.net":             "https://vault.azure.net/.default",
		"https://myhsm.managedhsm.azure.net":          "https://managedhsm.azure.net/.default",
		"https://gov.vault.usgovcloudapi.net":         "https://vault.usgovcloudapi.net/.default",
		"https://cn.vault.azure.cn":                   "https://vault.azure.cn/.default",
		"http://127.0.0.1:8443":                       "https://vault.azure.net/.default",
		"https://myvault.vault.azure.net:443/":        "https://vault.azure.net/.default",
		"https://vault":                               "https://vault.azure.net/.default",
		"https://single-label-host":                   "https://vault.azure.net/.default",
		"https://myvault.privatelink.vault.azure.net": "https://vault.azure.net/.default",
	}
	for in, want := range cases {
		u, _ := url.Parse(in)
		if got := azureKeyVaultScope(u); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestAzureIMDSCredential(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			http.Error(w, "no metadata header", http.StatusBadRequest)
			return
		}
		gotQuery = r.URL.Query()
		// IMDS reports expires_in as a string.
		_, _ = w.Write([]byte(`{"access_token":"imds-token","expires_in":"86399","token_type":"Bearer"}`))
	}))
	defer srv.Close()
	old := azureIMDSEndpoint
	azureIMDSEndpoint = srv.URL
	defer func() { azureIMDSEndpoint = old }()

	env := map[string]string{"AZURE_CLIENT_ID": "uami-1"}
	cred, err := newAzureCredential(func(k string) string { return env[k] }, srv.Client(), "https://vault.azure.net/.default")
	if err != nil {
		t.Fatal(err)
	}
	if cred.name() != "managed identity" {
		t.Fatalf("picked %s", cred.name())
	}
	cache := &azureTokenCache{cred: cred}
	tok, err := cache.token(context.Background())
	if err != nil || tok != "imds-token" {
		t.Fatalf("token %q (%v)", tok, err)
	}
	if gotQuery.Get("resource") != "https://vault.azure.net" || gotQuery.Get("client_id") != "uami-1" || gotQuery.Get("api-version") == "" {
		t.Fatalf("query %v", gotQuery)
	}
	if cache.exp.Before(time.Now().Add(23 * time.Hour)) {
		t.Fatalf("expiry %v not parsed from a string expires_in", cache.exp)
	}
}

func TestAzureTokenResponses(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		want       string
	}{
		{"not json", `<html>`, 200, "not JSON"},
		{"no token", `{"expires_in":10}`, 200, "no access_token"},
		{"no expiry", `{"access_token":"t"}`, 200, "expires_in"},
		{"bad expiry", `{"access_token":"t","expires_in":"soon"}`, 200, "expires_in"},
		{"plain error", `oops`, 500, "returned 500"},
		{"oauth error", `{"error":"invalid_scope","error_description":"AADSTS70011: bad scope\nmore"}`, 400, "invalid_scope: AADSTS70011: bad scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			_, _, err := doAzureTokenRequest(srv.Client(), req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "more") {
				t.Fatal("error quotes more than the first line of the description")
			}
		})
	}
	// An unreachable endpoint is a request error, not a panic.
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1", nil)
	if _, _, err := doAzureTokenRequest(http.DefaultClient, req); err == nil {
		t.Fatal("unreachable endpoint accepted")
	}
}

func TestAzureKeyVaultSignerRejects(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &azureKeyVaultSigner{pub: &k.PublicKey, keyID: "k/v", timeout: time.Second}
	if _, err := s.Sign(rand.Reader, make([]byte, 48), crypto.SHA384); err == nil {
		t.Fatal("SHA-384 accepted")
	}
	if _, err := s.Sign(rand.Reader, make([]byte, 32), nil); err == nil {
		t.Fatal("nil opts accepted")
	}
	if _, _, err := s.signDigest(make([]byte, 20)); err == nil {
		t.Fatal("short digest accepted")
	}
	if _, err := s.joseSigner().SignPayload([]byte("x"), "RS256"); err == nil {
		t.Fatal("RS256 accepted")
	}
	if pub := s.joseSigner().Public(); !pub.IsPublic() || pub.Algorithm != "ES256" {
		t.Fatalf("jose public key %+v", pub)
	}
}

func TestAzureECPublicKey(t *testing.T) {
	if _, err := azureECPublicKey("!!", "AA"); err == nil {
		t.Fatal("bad x accepted")
	}
	if _, err := azureECPublicKey("AA", "!!"); err == nil {
		t.Fatal("bad y accepted")
	}
	long := strings.Repeat("A", 48) // 36 bytes
	if _, err := azureECPublicKey(long, "AA"); err == nil {
		t.Fatal("over-long coordinate accepted")
	}
	if _, err := azureECPublicKey("AQ", "Ag"); err == nil {
		t.Fatal("point off the curve accepted")
	}
}

func TestRequireHTTPSOrLoopback(t *testing.T) {
	for in, ok := range map[string]bool{
		"https://x.vault.azure.net": true,
		"http://127.0.0.1:1":        true,
		"http://[::1]:1":            true,
		"http://localhost:1":        true,
		"http://10.0.0.1":           false,
		"ftp://x":                   false,
	} {
		u, _ := url.Parse(in)
		if err := requireHTTPSOrLoopback(u); (err == nil) != ok {
			t.Errorf("%s: err %v, want ok=%v", in, err, ok)
		}
	}
}
