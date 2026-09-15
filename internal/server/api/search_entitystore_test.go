package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// entityStoreFixture loads a policy set plus an entities.json that
// declares three Spiffe principals, two HttpPath resources and two
// Action entities. Only alice may GET /api/foo, and only via GET, so
// each of the three search dimensions has a filter that actually
// discriminates.
func entityStoreFixture(t *testing.T, enableEntityStoreSearch bool) *httptest.Server {
	t.Helper()
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "p.cedar"), []byte(`permit (
  principal == Spiffe::"spiffe://omega.local/alice",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "entities.json"), []byte(`[
  {"uid": {"type": "Spiffe", "id": "spiffe://omega.local/alice"}, "attrs": {}, "parents": []},
  {"uid": {"type": "Spiffe", "id": "spiffe://omega.local/bob"},   "attrs": {}, "parents": []},
  {"uid": {"type": "Spiffe", "id": "spiffe://omega.local/carol"}, "attrs": {}, "parents": []},
  {"uid": {"type": "HttpPath", "id": "/api/foo"}, "attrs": {}, "parents": []},
  {"uid": {"type": "HttpPath", "id": "/api/bar"}, "attrs": {}, "parents": []},
  {"uid": {"type": "Action", "id": "GET"},  "attrs": {}, "parents": []},
  {"uid": {"type": "Action", "id": "POST"}, "attrs": {}, "parents": []}
]`), 0o600); err != nil {
		t.Fatalf("write entities: %v", err)
	}
	pdp := policy.New()
	if err := pdp.LoadDir(policyDir); err != nil {
		t.Fatalf("load policy dir: %v", err)
	}

	dataDir := t.TempDir()
	store, err := storage.Open(filepath.Join(dataDir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dataDir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srv := httptest.NewServer(
		api.NewServer(store, ca, pdp).WithEntityStoreSearch(enableEntityStoreSearch).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func postSearch(t *testing.T, srv *httptest.Server, path, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, raw
}

func TestSearchPatternShapeRejectedWithoutEntityStoreMode(t *testing.T) {
	srv := entityStoreFixture(t, false)
	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"}
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", code, raw)
	}
	// The error has to name the flag, or an operator reading it has no
	// way to discover that the shape they sent is supported at all.
	if !bytes.Contains(raw, []byte("--authzen-search-entity-store")) {
		t.Errorf("error should point at the flag, got %s", raw)
	}
}

func TestSearchSubjectEnumeratesEntityStore(t *testing.T) {
	srv := entityStoreFixture(t, true)
	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].ID != "spiffe://omega.local/alice" {
		t.Fatalf("results: got %+v, want only alice", out.Results)
	}
	if out.Page == nil {
		t.Fatal("page: missing; next_token is REQUIRED on a search response")
	}
	if out.Page.NextToken != "" {
		t.Errorf("next_token: got %q, want empty on the last page", out.Page.NextToken)
	}
	if out.Page.Count != 1 {
		t.Errorf("count: got %d want 1", out.Page.Count)
	}
}

// A subject id in the pattern must not narrow the search: section 8.4.1
// says it SHOULD be omitted and MUST be ignored when present, so a
// caller that sends bob's id still gets alice back.
func TestSearchSubjectIgnoresPatternID(t *testing.T) {
	srv := entityStoreFixture(t, true)
	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe", "id": "spiffe://omega.local/bob"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].ID != "spiffe://omega.local/alice" {
		t.Fatalf("results: got %+v, want only alice", out.Results)
	}
}

func TestSearchResourceEnumeratesEntityStore(t *testing.T) {
	srv := entityStoreFixture(t, true)
	code, raw := postSearch(t, srv, "/access/v1/search/resource", `{
	  "subject":  {"type": "Spiffe", "id": "spiffe://omega.local/alice"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.ResourceSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].ID != "/api/foo" {
		t.Fatalf("results: got %+v, want only /api/foo", out.Results)
	}
}

// Section 8.6.1: an Action Search payload carries no action key, so the
// absence of a candidate list is itself the pattern.
func TestSearchActionEnumeratesEntityStore(t *testing.T) {
	srv := entityStoreFixture(t, true)
	code, raw := postSearch(t, srv, "/access/v1/search/action", `{
	  "subject":  {"type": "Spiffe", "id": "spiffe://omega.local/alice"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.ActionSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].Name != "GET" {
		t.Fatalf("results: got %+v, want only GET", out.Results)
	}
}

// An unknown type is an error rather than an empty result set: "the
// store has no such type" and "you may touch none of them" are
// different answers and a PEP cannot distinguish them from `[]`.
func TestSearchUnknownTypeIsAnErrorNotAnEmptyList(t *testing.T) {
	srv := entityStoreFixture(t, true)
	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "NoSuchType"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"}
	}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (body=%s)", code, raw)
	}
	if !bytes.Contains(raw, []byte("NoSuchType")) {
		t.Errorf("error should name the type it could not find, got %s", raw)
	}
}

// Paging walks the search space, so a page may hold no matches while a
// later page does. Driving the whole loop is the only way to see that
// an empty page is not the end of the sequence.
func TestSearchPaginationWalksTheSearchSpace(t *testing.T) {
	srv := entityStoreFixture(t, true)

	var (
		seen  []string
		token string
		pages int
	)
	for {
		body := fmt.Sprintf(`{
		  "subject":  {"type": "Spiffe"},
		  "action":   {"name": "GET"},
		  "resource": {"type": "HttpPath", "id": "/api/foo"},
		  "page":     {"limit": 1, "token": %q}
		}`, token)
		code, raw := postSearch(t, srv, "/access/v1/search/subject", body)
		if code != http.StatusOK {
			t.Fatalf("page %d: status %d (body=%s)", pages, code, raw)
		}
		var out api.SubjectSearchResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Page == nil {
			t.Fatalf("page %d: missing page object", pages)
		}
		for _, r := range out.Results {
			seen = append(seen, r.ID)
		}
		pages++
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
		if out.Page.NextToken == "" {
			break
		}
		token = out.Page.NextToken
	}

	// Three Spiffe entities at one candidate per page.
	if pages != 3 {
		t.Errorf("pages: got %d want 3", pages)
	}
	if len(seen) != 1 || seen[0] != "spiffe://omega.local/alice" {
		t.Errorf("results across pages: got %v, want only alice", seen)
	}
}

// Section 8.2.1 defines limit as a non-negative integer, so zero is a
// legal value and not the same request as omitting the field. A PEP can
// use it to ask whether a search space is non-empty without paying for
// a single PDP evaluation.
func TestSearchLimitZeroIsHonouredNotTreatedAsAbsent(t *testing.T) {
	srv := entityStoreFixture(t, true)
	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"},
	  "page":     {"limit": 0}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 0 {
		t.Errorf("results: got %d, want 0 (limit 0 was treated as absent)", len(out.Results))
	}
	// The store holds three Spiffe entities, so there is more to come and
	// the token has to say so - that is what makes the zero-cost probe
	// answer anything at all.
	if out.Page == nil || out.Page.NextToken == "" {
		t.Fatalf("page: got %+v, want a continuation token", out.Page)
	}

	// Omitting limit entirely is a different request and still defaults
	// to the full window.
	code, raw = postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"},
	  "page":     {}
	}`)
	if code != http.StatusOK {
		t.Fatalf("no-limit: status %d (body=%s)", code, raw)
	}
	var full api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(full.Results) != 1 {
		t.Errorf("no-limit: got %d results want 1", len(full.Results))
	}
	if full.Page == nil || full.Page.NextToken != "" {
		t.Errorf("no-limit: got %+v, want a terminal page", full.Page)
	}
}

// Naming the search space twice is a 400 rather than a silent
// precedence rule. The OpenAPI schema says to supply one or the other,
// and a PEP that filled in both because it misread which field this PDP
// wants would otherwise never find out.
func TestSearchRejectsBothCandidateListAndPattern(t *testing.T) {
	srv := entityStoreFixture(t, true)

	for _, tc := range []struct{ name, path, body string }{
		{"subject", "/access/v1/search/subject", `{
		  "subjects": [{"type": "Spiffe", "id": "spiffe://omega.local/alice"}],
		  "subject":  {"type": "Spiffe"},
		  "action":   {"name": "GET"},
		  "resource": {"type": "HttpPath", "id": "/api/foo"}
		}`},
		{"resource", "/access/v1/search/resource", `{
		  "resources": [{"type": "HttpPath", "id": "/api/foo"}],
		  "resource":  {"type": "HttpPath"},
		  "subject":   {"type": "Spiffe", "id": "spiffe://omega.local/alice"},
		  "action":    {"name": "GET"}
		}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, raw := postSearch(t, srv, tc.path, tc.body)
			if code != http.StatusBadRequest {
				t.Fatalf("status: got %d want 400 (body=%s)", code, raw)
			}
			if !bytes.Contains(raw, []byte("not both")) {
				t.Errorf("error should say the two are exclusive, got %s", raw)
			}
		})
	}
}

// Section 8.2: every field except the token must be identical across a
// paginated sequence, and the PDP SHOULD error when one changed.
func TestSearchPageTokenIsBoundToItsRequest(t *testing.T) {
	srv := entityStoreFixture(t, true)
	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"},
	  "page":     {"limit": 1}
	}`)
	if code != http.StatusOK {
		t.Fatalf("first page: status %d (body=%s)", code, raw)
	}
	var first api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if first.Page == nil || first.Page.NextToken == "" {
		t.Fatal("first page should carry a next_token")
	}

	// Same token, different resource.
	code, raw = postSearch(t, srv, "/access/v1/search/subject", fmt.Sprintf(`{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/bar"},
	  "page":     {"limit": 1, "token": %q}
	}`, first.Page.NextToken))
	if code != http.StatusBadRequest {
		t.Fatalf("mismatched token: got %d want 400 (body=%s)", code, raw)
	}

	// Same token, same request: still valid.
	code, _ = postSearch(t, srv, "/access/v1/search/subject", fmt.Sprintf(`{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"},
	  "page":     {"limit": 1, "token": %q}
	}`, first.Page.NextToken))
	if code != http.StatusOK {
		t.Fatalf("matching token: got %d want 200", code)
	}
}

// The candidate-list extension must keep working unchanged with the
// flag off, since that is the only mode 0.4.0 had.
func TestSearchCandidateListStillWorksWithEntityStoreModeOff(t *testing.T) {
	srv := entityStoreFixture(t, false)
	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subjects": [
	    {"type": "Spiffe", "id": "spiffe://omega.local/alice"},
	    {"type": "Spiffe", "id": "spiffe://omega.local/bob"}
	  ],
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].ID != "spiffe://omega.local/alice" {
		t.Fatalf("results: got %+v, want only alice", out.Results)
	}
}

// page.limit above MaxSearchCandidates is clamped rather than rejected:
// section 8.2.1 defines limit as a maximum, so returning fewer is
// conformant, and the cap is what bounds PDP evaluations and audit rows
// per request.
//
// The search space has to exceed MaxSearchCandidates for this to test
// anything - against a three-entity store an unclamped limit and a
// clamped one produce the same single terminal page. Every entity is
// permitted here so the result count equals the window size, which is
// what makes the clamp directly observable rather than inferred.
func TestSearchLimitIsClampedToMaxCandidates(t *testing.T) {
	const total = api.MaxSearchCandidates + 50

	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "p.cedar"), []byte(`permit (
  principal,
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	entities := make([]string, 0, total)
	for i := range total {
		// Zero-padded so lexicographic order (what EntitiesOfType sorts
		// by) matches numeric order, and the window boundary is legible
		// when a failure prints ids.
		entities = append(entities,
			fmt.Sprintf(`{"uid": {"type": "Spiffe", "id": "spiffe://omega.local/w%03d"}, "attrs": {}, "parents": []}`, i))
	}
	if err := os.WriteFile(filepath.Join(policyDir, "entities.json"),
		[]byte("["+strings.Join(entities, ",\n")+"]"), 0o600); err != nil {
		t.Fatalf("write entities: %v", err)
	}
	pdp := policy.New()
	if err := pdp.LoadDir(policyDir); err != nil {
		t.Fatalf("load policy dir: %v", err)
	}
	dataDir := t.TempDir()
	store, err := storage.Open(filepath.Join(dataDir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dataDir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca, pdp).WithEntityStoreSearch(true).Handler())
	t.Cleanup(srv.Close)

	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"},
	  "page":     {"limit": 100000}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Without the clamp this page would hold all `total` results and
	// carry no continuation token.
	if len(out.Results) != api.MaxSearchCandidates {
		t.Errorf("results: got %d want %d (the clamp did not bound the window)",
			len(out.Results), api.MaxSearchCandidates)
	}
	if out.Page == nil || out.Page.NextToken == "" {
		t.Fatalf("page: got %+v, want a continuation token for the remaining %d",
			out.Page, total-api.MaxSearchCandidates)
	}

	// The rest is reachable, so clamping withholds nothing.
	code, raw = postSearch(t, srv, "/access/v1/search/subject", fmt.Sprintf(`{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"},
	  "page":     {"limit": 100000, "token": %q}
	}`, out.Page.NextToken))
	if code != http.StatusOK {
		t.Fatalf("second page: status %d (body=%s)", code, raw)
	}
	var rest api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &rest); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rest.Results) != total-api.MaxSearchCandidates {
		t.Errorf("second page: got %d results want %d", len(rest.Results), total-api.MaxSearchCandidates)
	}
	if rest.Page == nil || rest.Page.NextToken != "" {
		t.Errorf("second page: got %+v, want a terminal page", rest.Page)
	}
}

// Section 8.1 RECOMMENDS that a search traverse intermediate
// relationships: if alice is in group admins and admins may read the
// doc, a subject search must return alice. Enumeration lists bare
// entities, so this only holds because each candidate is evaluated
// against the full entity store, parents included.
func TestSearchResolvesGroupMembershipTransitively(t *testing.T) {
	policyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(policyDir, "p.cedar"), []byte(`permit (
  principal in Group::"admins",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "entities.json"), []byte(`[
  {"uid": {"type": "Group", "id": "admins"}, "attrs": {}, "parents": []},
  {"uid": {"type": "Spiffe", "id": "spiffe://omega.local/alice"}, "attrs": {},
   "parents": [{"type": "Group", "id": "admins"}]},
  {"uid": {"type": "Spiffe", "id": "spiffe://omega.local/bob"}, "attrs": {}, "parents": []}
]`), 0o600); err != nil {
		t.Fatalf("write entities: %v", err)
	}
	pdp := policy.New()
	if err := pdp.LoadDir(policyDir); err != nil {
		t.Fatalf("load policy dir: %v", err)
	}
	dataDir := t.TempDir()
	store, err := storage.Open(filepath.Join(dataDir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dataDir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca, pdp).WithEntityStoreSearch(true).Handler())
	t.Cleanup(srv.Close)

	code, raw := postSearch(t, srv, "/access/v1/search/subject", `{
	  "subject":  {"type": "Spiffe"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "HttpPath", "id": "/api/foo"}
	}`)
	if code != http.StatusOK {
		t.Fatalf("status: got %d want 200 (body=%s)", code, raw)
	}
	var out api.SubjectSearchResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].ID != "spiffe://omega.local/alice" {
		t.Fatalf("results: got %+v, want alice via her group membership", out.Results)
	}
}

func TestAuthzenDiscoveryUsesSpecSearchParameterNames(t *testing.T) {
	dataDir := t.TempDir()
	store, err := storage.Open(filepath.Join(dataDir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.New(identity.Config{
		Kind:        identity.KindDisk,
		TrustDomain: "omega.local",
		Issuer:      "https://pdp.example.com",
		Dir:         filepath.Join(dataDir, "ca"),
	})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca, policy.New()).Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/authzen-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// AuthZEN 1.0 section 9.1.1 registers these names. Emitting the
	// reversed spelling means a PEP that reads the metadata concludes
	// this PDP has no Search support.
	for _, want := range []string{"search_subject_endpoint", "search_resource_endpoint", "search_action_endpoint"} {
		if _, ok := doc[want]; !ok {
			t.Errorf("discovery is missing %q (got keys %v)", want, keysOf(doc))
		}
	}
	for _, unwanted := range []string{"subject_search_endpoint", "resource_search_endpoint", "action_search_endpoint"} {
		if _, ok := doc[unwanted]; ok {
			t.Errorf("discovery still emits the non-spec name %q", unwanted)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
