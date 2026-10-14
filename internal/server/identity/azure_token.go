// azure_token.go is the minimal Microsoft Entra ID token source the
// Azure Key Vault backend authenticates with. It covers the three
// credentials a server process normally has on Azure, tried in the
// same order as the Azure SDK's DefaultAzureCredential:
//
//  1. a client secret (AZURE_TENANT_ID, AZURE_CLIENT_ID,
//     AZURE_CLIENT_SECRET),
//  2. workload identity federation (AZURE_TENANT_ID, AZURE_CLIENT_ID,
//     AZURE_FEDERATED_TOKEN_FILE, as injected by the AKS workload
//     identity webhook),
//  3. a managed identity through the instance metadata service
//     (AZURE_CLIENT_ID optionally selects a user-assigned identity).
//
// It is hand-written rather than taken from azidentity on purpose: the
// SDK pulls azcore, MSAL and their transitive modules into a control
// plane whose other upstream backends (Vault PKI, step-ca) call REST
// directly, for three HTTP requests. ADR 0021 records the trade-off.
// Tokens are never logged and never appear in errors.

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAzureAuthorityHost = "https://login.microsoftonline.com/"
	// azureTokenRefreshMargin renews a token this long before it
	// expires, so a sign never starts with a token about to lapse.
	azureTokenRefreshMargin = 5 * time.Minute
	maxAzureTokenResponse   = 1 << 20
)

// azureIMDSEndpoint is the managed identity token endpoint. A variable
// so tests can point it at a fake.
var azureIMDSEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

// azureCredential fetches an access token for one scope.
type azureCredential interface {
	fetch(ctx context.Context) (token string, expiresAt time.Time, err error)
	name() string
}

// azureTokenCache serves a cached token until shortly before it
// expires and serialises refreshes.
type azureTokenCache struct {
	cred azureCredential

	mu  sync.Mutex
	tok string
	exp time.Time
}

func (c *azureTokenCache) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != "" && time.Now().Add(azureTokenRefreshMargin).Before(c.exp) {
		return c.tok, nil
	}
	tok, exp, err := c.cred.fetch(ctx)
	if err != nil {
		return "", fmt.Errorf("azure %s credential: %w", c.cred.name(), err)
	}
	c.tok, c.exp = tok, exp
	return tok, nil
}

// invalidate drops the cached token, so the next call fetches a new
// one. Used when Key Vault rejects a token the cache thought valid.
func (c *azureTokenCache) invalidate() {
	c.mu.Lock()
	c.tok, c.exp = "", time.Time{}
	c.mu.Unlock()
}

// newAzureCredential picks the first credential the environment
// configures. scope is the OAuth 2.0 scope ("<resource>/.default").
func newAzureCredential(getenv func(string) string, client *http.Client, scope string) (azureCredential, error) {
	tenant := strings.TrimSpace(getenv("AZURE_TENANT_ID"))
	clientID := strings.TrimSpace(getenv("AZURE_CLIENT_ID"))
	secret := getenv("AZURE_CLIENT_SECRET")
	tokenFile := strings.TrimSpace(getenv("AZURE_FEDERATED_TOKEN_FILE"))

	if secret != "" || tokenFile != "" {
		if tenant == "" || clientID == "" {
			return nil, errors.New("AZURE_CLIENT_SECRET or AZURE_FEDERATED_TOKEN_FILE needs AZURE_TENANT_ID and AZURE_CLIENT_ID")
		}
		endpoint, err := azureTokenEndpoint(getenv("AZURE_AUTHORITY_HOST"), tenant)
		if err != nil {
			return nil, err
		}
		c := &entraCredential{client: client, endpoint: endpoint, clientID: clientID, scope: scope}
		if secret != "" {
			c.kind, c.secret = "client secret", secret
		} else {
			c.kind, c.assertionFile = "workload identity", tokenFile
		}
		return c, nil
	}
	resource := strings.TrimSuffix(scope, "/.default")
	return &imdsCredential{client: client, resource: resource, clientID: clientID}, nil
}

// azureTokenEndpoint builds the Entra ID v2 token endpoint for tenant.
// The authority host must be https; plain http is accepted only for a
// loopback address, which is what tests use.
func azureTokenEndpoint(authorityHost, tenant string) (string, error) {
	if strings.TrimSpace(authorityHost) == "" {
		authorityHost = defaultAzureAuthorityHost
	}
	u, err := url.Parse(strings.TrimSpace(authorityHost))
	if err != nil {
		return "", fmt.Errorf("AZURE_AUTHORITY_HOST: %w", err)
	}
	if err := requireHTTPSOrLoopback(u); err != nil {
		return "", fmt.Errorf("AZURE_AUTHORITY_HOST: %w", err)
	}
	if strings.ContainsAny(tenant, "/?#") {
		return "", fmt.Errorf("AZURE_TENANT_ID %q is not a tenant id or domain", tenant)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
	return u.String(), nil
}

// entraCredential runs the OAuth 2.0 client credentials grant against
// Entra ID, authenticating with a client secret or with a federated
// assertion read from a file.
type entraCredential struct {
	client        *http.Client
	kind          string
	endpoint      string
	clientID      string
	scope         string
	secret        string
	assertionFile string
}

func (c *entraCredential) name() string { return c.kind }

func (c *entraCredential) fetch(ctx context.Context) (string, time.Time, error) {
	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {c.clientID},
		"scope":      {c.scope},
	}
	if c.secret != "" {
		form.Set("client_secret", c.secret)
	} else {
		// Re-read on every fetch: the projected service account token
		// is rotated by the kubelet.
		// #nosec G304 -- AZURE_FEDERATED_TOKEN_FILE is set by the operator or the AKS webhook.
		raw, err := os.ReadFile(c.assertionFile)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("read federated token file: %w", err)
		}
		assertion := strings.TrimSpace(string(raw))
		if assertion == "" {
			return "", time.Time{}, errors.New("federated token file is empty")
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doAzureTokenRequest(c.client, req)
}

// imdsCredential asks the instance metadata service for a managed
// identity token.
type imdsCredential struct {
	client   *http.Client
	resource string
	clientID string
}

func (c *imdsCredential) name() string { return "managed identity" }

func (c *imdsCredential) fetch(ctx context.Context) (string, time.Time, error) {
	q := url.Values{"api-version": {"2018-02-01"}, "resource": {c.resource}}
	if c.clientID != "" {
		q.Set("client_id", c.clientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, azureIMDSEndpoint+"?"+q.Encode(), nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Metadata", "true")
	return doAzureTokenRequest(c.client, req)
}

// doAzureTokenRequest sends a token request and decodes the response
// both Entra ID and IMDS return. expires_in is a number from Entra ID
// and a string from IMDS.
func doAzureTokenRequest(client *http.Client, req *http.Request) (string, time.Time, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAzureTokenResponse))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read token response: %w", err)
	}
	var out struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Error       string          `json:"error"`
		Description string          `json:"error_description"`
	}
	// The body of an error carries an error code and a description,
	// never a token, so it is safe to quote; a success body is not
	// quoted anywhere.
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(body, &out)
		if out.Error != "" {
			return "", time.Time{}, fmt.Errorf("token endpoint returned %d: %s: %s", resp.StatusCode, out.Error, firstLine(out.Description))
		}
		return "", time.Time{}, fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, errors.New("token response is not JSON")
	}
	if out.AccessToken == "" {
		return "", time.Time{}, errors.New("token response has no access_token")
	}
	secs, err := strconv.ParseInt(strings.Trim(string(out.ExpiresIn), `"`), 10, 64)
	if err != nil || secs <= 0 {
		return "", time.Time{}, errors.New("token response has no usable expires_in")
	}
	return out.AccessToken, time.Now().Add(time.Duration(secs) * time.Second), nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(s)
}
