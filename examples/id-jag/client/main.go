// client plays the AI agent in the ID-JAG demo: it takes the user's
// ID token from the IdP, exchanges it there for an ID-JAG addressed to
// omega, presents the ID-JAG at omega's token endpoint authenticated by
// its own JWT-SVID, and calls the MCP tool with the delegated token.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func main() {
	var (
		idpURL       = flag.String("idp-url", "http://127.0.0.1:19100", "IdP base URL")
		omegaURL     = flag.String("omega-url", "http://127.0.0.1:18098", "omega base URL")
		omegaIssuer  = flag.String("omega-issuer", "https://omega.demo.local", "omega's --issuer-url")
		toolURL      = flag.String("tool-url", "http://127.0.0.1:19001/tool/issues", "MCP tool endpoint")
		toolAudience = flag.String("tool-audience", "mcp://github-issue", "resource the agent asks for")
		user         = flag.String("user", "alice", "user who signed in at the IdP")
		agent        = flag.String("agent", "spiffe://omega.local/agents/claude-code", "the agent's SPIFFE ID")
		otherAgent   = flag.String("other-agent", "spiffe://omega.local/agents/other", "an agent the ID-JAG was not issued to")
		clientID     = flag.String("client-id", "claude-code", "the agent's client_id at the IdP")
		clientSecret = flag.String("client-secret", "demo-secret", "the agent's client secret at the IdP")
	)
	flag.Parse()

	step("1. user signs in at the IdP (SSO stand-in)")
	idToken := mustField(postForm(*idpURL+"/login", url.Values{"user": {*user}}, http.StatusOK), "id_token")

	step("2. agent exchanges the ID token for an ID-JAG addressed to omega")
	jagResp := postForm(*idpURL+"/token", url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:id-jag"},
		"subject_token":        {idToken},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:id_token"},
		"audience":             {*omegaIssuer},
		"resource":             {*toolAudience},
		"scope":                {"issues:read"},
		"client_id":            {*clientID},
		"client_secret":        {*clientSecret},
	}, http.StatusOK)
	jag := mustField(jagResp, "access_token")
	fmt.Printf("   issued_token_type=%v\n", jagResp["issued_token_type"])

	step("3. agent presents the ID-JAG to omega, authenticated by its JWT-SVID")
	tokResp := postForm(*omegaURL+"/oauth2/token", grantForm(jag, clientAssertion(*omegaURL, *agent, *omegaIssuer)), http.StatusOK)
	accessToken := mustField(tokResp, "access_token")
	fmt.Printf("   spiffe_id=%v delegation_chain=%v scope=%v\n", tokResp["spiffe_id"], tokResp["delegation_chain"], tokResp["scope"])

	step("4. agent calls the MCP tool with the delegated token")
	req, _ := http.NewRequest(http.MethodGet, *toolURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatalf("tool call: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("tool returned %d: %s", resp.StatusCode, body)
	}
	fmt.Printf("   tool response: %s", body)

	step("5. negative: the raw ID token is not accepted as a grant")
	expectError(postForm(*omegaURL+"/oauth2/token", grantForm(idToken, clientAssertion(*omegaURL, *agent, *omegaIssuer)), http.StatusBadRequest), "invalid_grant")

	step("6. negative: another agent cannot redeem this agent's ID-JAG")
	expectError(postForm(*omegaURL+"/oauth2/token", grantForm(jag, clientAssertion(*omegaURL, *otherAgent, *omegaIssuer)), http.StatusBadRequest), "invalid_grant")

	fmt.Println("\nOK")
}

func grantForm(assertion, clientAssertion string) url.Values {
	return url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":             {assertion},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"},
		"client_assertion":      {clientAssertion},
	}
}

// clientAssertion fetches a short JWT-SVID for id with omega's issuer as
// its audience. A real agent would get it from the SPIFFE Workload API.
func clientAssertion(omegaURL, id, issuer string) string {
	body, _ := json.Marshal(map[string]any{"spiffe_id": id, "audience": []string{issuer}, "ttl_seconds": 60})
	resp, err := httpClient.Post(omegaURL+"/v1/svid/jwt", "application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Fatalf("jwt-svid: %v", err)
	}
	return mustField(decode(resp, http.StatusOK), "token")
}

func postForm(u string, form url.Values, want int) map[string]any {
	resp, err := httpClient.PostForm(u, form)
	if err != nil {
		log.Fatalf("POST %s: %v", u, err)
	}
	return decode(resp, want)
}

func decode(resp *http.Response, want int) map[string]any {
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		log.Fatalf("%s: status %d, want %d: %s", resp.Request.URL, resp.StatusCode, want, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		log.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func mustField(m map[string]any, k string) string {
	s, _ := m[k].(string)
	if s == "" {
		log.Fatalf("response has no %s: %v", k, m)
	}
	return s
}

func expectError(m map[string]any, code string) {
	if m["error"] != code {
		fmt.Fprintf(os.Stderr, "want error %s, got %v\n", code, m)
		os.Exit(1)
	}
	fmt.Printf("   rejected: %s (%v)\n", code, m["error_description"])
}

func step(s string) { fmt.Println("\n[client] " + s) }
