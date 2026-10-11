package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/storage"
)

// SCIMConfig lets one identity provider provision users and groups over
// SCIM 2.0 (RFC 7643, RFC 7644) at /scim/v2/{Name}/.
type SCIMConfig struct {
	// Name identifies the provider in the URL, the audit actor
	// ("scim:<name>") and the {idp} template placeholder.
	Name string
	// Domain owns the groups the provider creates.
	Domain string
	// TokenHash is the SHA-256 of the bearer token the provider sends.
	TokenHash [32]byte
	// Template maps a user to the SPIFFE ID its memberships are granted
	// to; it may use {idp}, {externalId} and {userName}.
	Template string
}

// WithSCIM enables SCIM provisioning for the given providers.
func (s *Server) WithSCIM(cfgs []SCIMConfig) *Server {
	s.scim = map[string]SCIMConfig{}
	for _, c := range cfgs {
		s.scim[c.Name] = c
	}
	return s
}

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimErrSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimMaxResults  = 1000
)

// scimHandler resolves the provider, checks its bearer token and runs h.
func (s *Server) scimHandler(h func(http.ResponseWriter, *http.Request, SCIMConfig)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, ok := s.scim[r.PathValue("idp")]
		if !ok {
			scimError(w, http.StatusNotFound, "", "no such SCIM provider")
			return
		}
		tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(tok))
		if !found || subtle.ConstantTimeCompare(sum[:], cfg.TokenHash[:]) != 1 {
			slog.Warn("scim: rejected a request with a missing or wrong bearer token", "idp", cfg.Name)
			w.Header().Set("WWW-Authenticate", `Bearer realm="omega-scim"`)
			scimError(w, http.StatusUnauthorized, "", "a valid bearer token is required")
			return
		}
		h(w, r, cfg)
	}
}

func scimError(w http.ResponseWriter, code int, scimType, detail string) {
	body := map[string]any{"schemas": []string{scimErrSchema}, "status": strconv.Itoa(code), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	scimJSON(w, code, body)
}

// scimDecode reads a JSON body, answering with a SCIM error on failure.
func scimDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)).Decode(dst); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			scimError(w, http.StatusRequestEntityTooLarge, "", "request body too large")
			return false
		}
		scimError(w, http.StatusBadRequest, "invalidSyntax", "invalid JSON body")
		return false
	}
	return true
}

func scimJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// scimStoreError maps a storage error to a SCIM error response.
func scimStoreError(w http.ResponseWriter, err error) {
	var bad *scimBadRequest
	switch {
	case errors.As(err, &bad):
		scimError(w, http.StatusBadRequest, bad.scimType, bad.msg)
	case errors.Is(err, storage.ErrNotFound):
		scimError(w, http.StatusNotFound, "", "resource not found")
	case errors.Is(err, storage.ErrAlreadyExists):
		scimError(w, http.StatusConflict, "uniqueness", "a resource with that name already exists")
	case errors.Is(err, storage.ErrUnknownMember):
		scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
	case errors.Is(err, storage.ErrNotLeader):
		w.Header().Set("Retry-After", "1")
		scimError(w, http.StatusServiceUnavailable, "", "not the leader")
	default:
		slog.Error("scim: request failed", "err", err)
		scimError(w, http.StatusInternalServerError, "", err.Error())
	}
}

type scimBadRequest struct{ scimType, msg string }

func (e *scimBadRequest) Error() string { return e.msg }

func badValue(format string, args ...any) error {
	return &scimBadRequest{"invalidValue", fmt.Sprintf(format, args...)}
}

// scimRun runs fn in a SCIM transaction and reloads the policy directory
// when it recorded a change.
func (s *Server) scimRun(r *http.Request, cfg SCIMConfig, fn func(*storage.SCIMTx) (storage.AuditEvent, error)) error {
	if s.scimFault != nil {
		inner := fn
		fn = func(t *storage.SCIMTx) (storage.AuditEvent, error) {
			ev, err := inner(t)
			if err == nil && ev.Kind != "" {
				err = s.scimFault(ev)
			}
			return ev, err
		}
	}
	ev, err := s.store.SCIM(r.Context(), cfg.Name, fn)
	if err != nil {
		return err
	}
	if ev.Kind != "" {
		s.refreshAfterWrite(r.Context())
	}
	return nil
}

func scimEvent(cfg SCIMConfig, kind, subject string, payload map[string]any) storage.AuditEvent {
	return storage.AuditEvent{Kind: kind, Actor: "scim:" + cfg.Name, Subject: subject, Decision: "ok", Payload: mustJSON(payload)}
}

// --- discovery ---

func (s *Server) scimServiceProviderConfig(w http.ResponseWriter, _ *http.Request, _ SCIMConfig) {
	scimJSON(w, http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]bool{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": scimMaxResults},
		"changePassword": map[string]bool{"supported": false},
		"sort":           map[string]bool{"supported": false},
		"etag":           map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer token", "description": "A static bearer token configured for this provider.", "primary": true,
		}},
	})
}

func (s *Server) scimResourceTypes(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	base := scimBase(r, cfg)
	types := []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema, "meta": map[string]string{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"}},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema, "meta": map[string]string{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"}},
	}
	scimJSON(w, http.StatusOK, scimList(types, 1))
}

func (s *Server) scimSchemas(w http.ResponseWriter, _ *http.Request, _ SCIMConfig) {
	attr := func(name, typ string, required bool, uniqueness string) map[string]any {
		return map[string]any{"name": name, "type": typ, "multiValued": false, "required": required, "caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": uniqueness}
	}
	schemas := []map[string]any{
		{"id": scimUserSchema, "name": "User", "attributes": []map[string]any{
			attr("userName", "string", true, "server"), attr("displayName", "string", false, "none"), attr("active", "boolean", false, "none"),
		}},
		{"id": scimGroupSchema, "name": "Group", "attributes": []map[string]any{
			attr("displayName", "string", true, "server"),
			{"name": "members", "type": "complex", "multiValued": true, "required": false, "mutability": "readWrite", "returned": "default", "subAttributes": []map[string]any{attr("value", "string", false, "none")}},
		}},
	}
	scimJSON(w, http.StatusOK, scimList(schemas, 1))
}

func scimList[T any](items []T, start int) map[string]any {
	if items == nil {
		items = []T{}
	}
	return map[string]any{"schemas": []string{scimListSchema}, "totalResults": len(items), "startIndex": start, "itemsPerPage": len(items), "Resources": items}
}

func scimBase(r *http.Request, cfg SCIMConfig) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/scim/v2/" + cfg.Name
}

// --- filters and paging ---

var scimFilter = regexp.MustCompile(`(?i)^\s*([A-Za-z.]+)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$`)

// parseFilter supports `<attr> eq "<value>"` on the attributes allowed.
func parseFilter(f string, allowed ...string) (attr, value string, err error) {
	if strings.TrimSpace(f) == "" {
		return "", "", nil
	}
	m := scimFilter.FindStringSubmatch(f)
	if m == nil {
		return "", "", &scimBadRequest{"invalidFilter", "only `<attribute> eq \"<value>\"` filters are supported"}
	}
	for _, a := range allowed {
		if strings.EqualFold(m[1], a) {
			v, uerr := strconv.Unquote(`"` + m[2] + `"`)
			if uerr != nil {
				return "", "", &scimBadRequest{"invalidFilter", "malformed filter value"}
			}
			return a, v, nil
		}
	}
	return "", "", &scimBadRequest{"invalidFilter", fmt.Sprintf("cannot filter by %q", m[1])}
}

// page applies startIndex (1-based) and count.
func page[T any](r *http.Request, items []T) ([]T, int, int, error) {
	start, count := 1, scimMaxResults
	if v := r.URL.Query().Get("startIndex"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, 0, 0, badValue("startIndex must be an integer")
		}
		start = max(n, 1)
	}
	if v := r.URL.Query().Get("count"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, 0, 0, badValue("count must be an integer")
		}
		count = min(max(n, 0), scimMaxResults)
	}
	total := len(items)
	if start > total {
		return nil, total, start, nil
	}
	end := min(start-1+count, total)
	return items[start-1 : end], total, start, nil
}

func writeSCIMList[T any](w http.ResponseWriter, r *http.Request, items []T) {
	pageItems, total, start, err := page(r, items)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	body := scimList(pageItems, start)
	body["totalResults"] = total
	scimJSON(w, http.StatusOK, body)
}

// --- users ---

type scimUserBody struct {
	Schemas     []string  `json:"schemas,omitempty"`
	ID          string    `json:"id,omitempty"`
	ExternalID  string    `json:"externalId,omitempty"`
	UserName    string    `json:"userName"`
	DisplayName string    `json:"displayName,omitempty"`
	Active      *bool     `json:"active,omitempty"`
	Meta        *scimMeta `json:"meta,omitempty"`
}

type scimMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
}

func userJSON(r *http.Request, cfg SCIMConfig, u storage.SCIMUser) scimUserBody {
	active := u.Active
	return scimUserBody{
		Schemas: []string{scimUserSchema}, ID: u.ID, ExternalID: u.ExternalID, UserName: u.UserName, DisplayName: u.DisplayName, Active: &active,
		Meta: &scimMeta{ResourceType: "User", Created: u.Created, LastModified: u.Modified, Location: scimBase(r, cfg) + "/Users/" + u.ID},
	}
}

// principalFor maps a user to its SPIFFE ID with the provider's template.
func (s *Server) principalFor(cfg SCIMConfig, u storage.SCIMUser) (string, error) {
	if strings.TrimSpace(u.UserName) == "" {
		return "", badValue("userName is required")
	}
	if strings.Contains(cfg.Template, "{externalId}") && u.ExternalID == "" {
		return "", badValue("externalId is required: this provider maps users to SPIFFE IDs by externalId")
	}
	id := strings.NewReplacer("{idp}", cfg.Name, "{externalId}", u.ExternalID, "{userName}", u.UserName).Replace(cfg.Template)
	sid, err := spiffeid.FromString(id)
	if err != nil {
		return "", badValue("the user maps to %q, which is not a valid SPIFFE ID: %v", id, err)
	}
	if td := s.ca.TrustDomain(); !td.IsZero() && sid.TrustDomain() != td {
		return "", badValue("the user maps to %q, outside the trust domain %q", id, td.Name())
	}
	return id, nil
}

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	attr, value, err := parseFilter(r.URL.Query().Get("filter"), "userName", "externalId")
	if err != nil {
		scimStoreError(w, err)
		return
	}
	var users []storage.SCIMUser
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		users, err = t.ListUsers(attr, value)
		return storage.AuditEvent{}, err
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	out := make([]scimUserBody, len(users))
	for i, u := range users {
		out[i] = userJSON(r, cfg, u)
	}
	writeSCIMList(w, r, out)
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	var u storage.SCIMUser
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		var err error
		u, err = t.GetUser(r.PathValue("id"))
		return storage.AuditEvent{}, err
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	scimJSON(w, http.StatusOK, userJSON(r, cfg, u))
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	var body scimUserBody
	if !scimDecode(w, r, &body) {
		return
	}
	u := storage.SCIMUser{UserName: body.UserName, ExternalID: body.ExternalID, DisplayName: body.DisplayName, Active: body.Active == nil || *body.Active}
	var err error
	if u.Principal, err = s.principalFor(cfg, u); err != nil {
		scimStoreError(w, err)
		return
	}
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		var err error
		if u, err = t.CreateUser(u); err != nil {
			return storage.AuditEvent{}, err
		}
		return scimEvent(cfg, "scim.user.create", u.Principal, map[string]any{"id": u.ID, "user_name": u.UserName, "active": u.Active}), nil
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	w.Header().Set("Location", scimBase(r, cfg)+"/Users/"+u.ID)
	scimJSON(w, http.StatusCreated, userJSON(r, cfg, u))
}

func (s *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	var body scimUserBody
	if !scimDecode(w, r, &body) {
		return
	}
	s.updateUser(w, r, cfg, "scim.user.replace", func(u *storage.SCIMUser) error {
		u.UserName, u.ExternalID, u.DisplayName = body.UserName, body.ExternalID, body.DisplayName
		u.Active = body.Active == nil || *body.Active
		return nil
	})
}

type scimPatch struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

func decodePatch(w http.ResponseWriter, r *http.Request) (scimPatch, bool) {
	var p scimPatch
	if !scimDecode(w, r, &p) {
		return p, false
	}
	if !slices.Contains(p.Schemas, scimPatchSchema) || len(p.Operations) == 0 {
		scimError(w, http.StatusBadRequest, "invalidSyntax", "a PatchOp with at least one operation is required")
		return p, false
	}
	return p, true
}

// scimBool accepts a JSON boolean or the strings "true" / "false", which
// some providers send.
func scimBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if v, err := strconv.ParseBool(s); err == nil {
			return v, nil
		}
	}
	return false, badValue("active must be a boolean")
}

func scimString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", badValue("expected a string")
	}
	return s, nil
}

// applyUserAttr sets one user attribute. Attributes Omega does not keep
// (name, emails, ...) are accepted and ignored.
func applyUserAttr(u *storage.SCIMUser, attr string, raw json.RawMessage, remove bool) error {
	var err error
	switch strings.ToLower(attr) {
	case "username":
		if remove {
			return badValue("userName cannot be removed")
		}
		u.UserName, err = scimString(raw)
	case "externalid":
		if remove {
			u.ExternalID = ""
			return nil
		}
		u.ExternalID, err = scimString(raw)
	case "displayname":
		if remove {
			u.DisplayName = ""
			return nil
		}
		u.DisplayName, err = scimString(raw)
	case "active":
		if remove {
			return badValue("active cannot be removed")
		}
		u.Active, err = scimBool(raw)
	}
	return err
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	p, ok := decodePatch(w, r)
	if !ok {
		return
	}
	s.updateUser(w, r, cfg, "scim.user.patch", func(u *storage.SCIMUser) error {
		for _, op := range p.Operations {
			kind := strings.ToLower(op.Op)
			if kind != "add" && kind != "replace" && kind != "remove" {
				return &scimBadRequest{"invalidSyntax", fmt.Sprintf("unknown op %q", op.Op)}
			}
			if op.Path != "" {
				if err := applyUserAttr(u, op.Path, op.Value, kind == "remove"); err != nil {
					return err
				}
				continue
			}
			var attrs map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &attrs); err != nil || kind == "remove" {
				return badValue("an operation without a path needs an object value")
			}
			for k, v := range attrs {
				if err := applyUserAttr(u, k, v, false); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// updateUser loads a user, applies edit, recomputes its SPIFFE ID and
// stores it, all in one transaction with the audit row.
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, cfg SCIMConfig, kind string, edit func(*storage.SCIMUser) error) {
	var u storage.SCIMUser
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		prev, err := t.GetUser(r.PathValue("id"))
		if err != nil {
			return storage.AuditEvent{}, err
		}
		u = prev
		if err := edit(&u); err != nil {
			return storage.AuditEvent{}, err
		}
		if u.Principal, err = s.principalFor(cfg, u); err != nil {
			return storage.AuditEvent{}, err
		}
		if u, err = t.ReplaceUser(u); err != nil {
			return storage.AuditEvent{}, err
		}
		payload := map[string]any{"id": u.ID, "user_name": u.UserName, "active": u.Active}
		if prev.Principal != u.Principal {
			payload["previous_principal"] = prev.Principal
		}
		return scimEvent(cfg, kind, u.Principal, payload), nil
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	scimJSON(w, http.StatusOK, userJSON(r, cfg, u))
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		u, err := t.GetUser(r.PathValue("id"))
		if err != nil {
			return storage.AuditEvent{}, err
		}
		if err := t.DeleteUser(u.ID); err != nil {
			return storage.AuditEvent{}, err
		}
		return scimEvent(cfg, "scim.user.delete", u.Principal, map[string]any{"id": u.ID, "user_name": u.UserName}), nil
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- groups ---

type scimMember struct {
	Value string `json:"value"`
}

type scimGroupBody struct {
	Schemas     []string     `json:"schemas,omitempty"`
	ID          string       `json:"id,omitempty"`
	ExternalID  string       `json:"externalId,omitempty"`
	DisplayName string       `json:"displayName"`
	Members     []scimMember `json:"members"`
	Meta        *scimMeta    `json:"meta,omitempty"`
	// OmegaGroup is the policy identity of the group, read-only.
	OmegaGroup string `json:"omegaGroup,omitempty"`
}

func groupJSON(r *http.Request, cfg SCIMConfig, g storage.SCIMGroup, withMembers bool) scimGroupBody {
	out := scimGroupBody{
		Schemas: []string{scimGroupSchema}, ID: g.ID, ExternalID: g.ExternalID, DisplayName: g.DisplayName, Members: []scimMember{},
		OmegaGroup: g.Domain + ":" + g.Group,
		Meta:       &scimMeta{ResourceType: "Group", Created: g.Created, LastModified: g.Modified, Location: scimBase(r, cfg) + "/Groups/" + g.ID},
	}
	if withMembers {
		for _, m := range g.Members {
			out.Members = append(out.Members, scimMember{Value: m})
		}
	}
	return out
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// GroupNameFromDisplay derives the Omega group name for a SCIM display
// name: lowercase, with every run of other characters turned into "-".
func GroupNameFromDisplay(display string) (string, error) {
	name := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(display), "-"), "-")
	if len(name) > 63 {
		name = strings.TrimRight(name[:63], "-")
	}
	if err := storage.ValidateGroupName(name); err != nil {
		return "", badValue("displayName %q does not give a usable group name", display)
	}
	return name, nil
}

func memberIDs(ms []scimMember) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Value)
	}
	return out
}

func excludesMembers(r *http.Request) bool {
	for a := range strings.SplitSeq(r.URL.Query().Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(a), "members") {
			return true
		}
	}
	return false
}

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	attr, value, err := parseFilter(r.URL.Query().Get("filter"), "displayName", "externalId")
	if err != nil {
		scimStoreError(w, err)
		return
	}
	var groups []storage.SCIMGroup
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		groups, err = t.ListGroups(attr, value)
		return storage.AuditEvent{}, err
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	out := make([]scimGroupBody, len(groups))
	for i, g := range groups {
		out[i] = groupJSON(r, cfg, g, !excludesMembers(r))
	}
	writeSCIMList(w, r, out)
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	var g storage.SCIMGroup
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		var err error
		g, err = t.GetGroup(r.PathValue("id"))
		return storage.AuditEvent{}, err
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	scimJSON(w, http.StatusOK, groupJSON(r, cfg, g, !excludesMembers(r)))
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	var body scimGroupBody
	if !scimDecode(w, r, &body) {
		return
	}
	name, err := GroupNameFromDisplay(body.DisplayName)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	g := storage.SCIMGroup{DisplayName: body.DisplayName, ExternalID: body.ExternalID, Domain: cfg.Domain, Group: name, Members: memberIDs(body.Members)}
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		var err error
		if g, err = t.CreateGroup(g); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return storage.AuditEvent{}, fmt.Errorf("domain %q configured for SCIM provider %q does not exist", cfg.Domain, cfg.Name)
			}
			return storage.AuditEvent{}, err
		}
		return scimEvent(cfg, "scim.group.create", g.Domain+":"+g.Group, map[string]any{"id": g.ID, "display_name": g.DisplayName, "members": g.Members}), nil
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	w.Header().Set("Location", scimBase(r, cfg)+"/Groups/"+g.ID)
	scimJSON(w, http.StatusCreated, groupJSON(r, cfg, g, true))
}

func (s *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	var body scimGroupBody
	if !scimDecode(w, r, &body) {
		return
	}
	name, err := GroupNameFromDisplay(body.DisplayName)
	if err != nil {
		scimStoreError(w, err)
		return
	}
	var g storage.SCIMGroup
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		prev, err := t.GetGroup(r.PathValue("id"))
		if err != nil {
			return storage.AuditEvent{}, err
		}
		g = prev
		g.DisplayName, g.ExternalID, g.Group, g.Members = body.DisplayName, body.ExternalID, name, memberIDs(body.Members)
		if g, err = t.ReplaceGroup(g); err != nil {
			return storage.AuditEvent{}, err
		}
		return scimEvent(cfg, "scim.group.replace", g.Domain+":"+g.Group, groupChange(prev, g)), nil
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	scimJSON(w, http.StatusOK, groupJSON(r, cfg, g, true))
}

var memberFilterPath = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+"([^"]*)"\s*\]$`)

func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	p, ok := decodePatch(w, r)
	if !ok {
		return
	}
	var g storage.SCIMGroup
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		prev, err := t.GetGroup(r.PathValue("id"))
		if err != nil {
			return storage.AuditEvent{}, err
		}
		g = prev
		for _, op := range p.Operations {
			if err := s.applyGroupOp(t, &g, strings.ToLower(op.Op), op.Path, op.Value); err != nil {
				return storage.AuditEvent{}, err
			}
		}
		if g, err = t.GetGroup(g.ID); err != nil {
			return storage.AuditEvent{}, err
		}
		return scimEvent(cfg, "scim.group.patch", g.Domain+":"+g.Group, groupChange(prev, g)), nil
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	if r.URL.Query().Get("excludedAttributes") != "" {
		scimJSON(w, http.StatusOK, groupJSON(r, cfg, g, !excludesMembers(r)))
		return
	}
	scimJSON(w, http.StatusOK, groupJSON(r, cfg, g, true))
}

// applyGroupOp applies one PATCH operation to a group.
func (s *Server) applyGroupOp(t *storage.SCIMTx, g *storage.SCIMGroup, op, path string, raw json.RawMessage) error {
	members := func() ([]string, error) {
		var ms []scimMember
		if err := json.Unmarshal(raw, &ms); err != nil {
			return nil, badValue("members must be a list of {\"value\": id}")
		}
		return memberIDs(ms), nil
	}
	rename := func(display string) error {
		name, err := GroupNameFromDisplay(display)
		if err != nil {
			return err
		}
		g.DisplayName, g.Group = display, name
		cur, err := t.GetGroup(g.ID)
		if err != nil {
			return err
		}
		cur.DisplayName, cur.Group, cur.ExternalID = g.DisplayName, g.Group, g.ExternalID
		_, err = t.ReplaceGroup(cur)
		return err
	}
	if m := memberFilterPath.FindStringSubmatch(path); m != nil && op == "remove" {
		return t.PatchMembers(g.ID, nil, []string{m[1]})
	}
	switch {
	case strings.EqualFold(path, "members"):
		switch op {
		case "add":
			ids, err := members()
			if err != nil {
				return err
			}
			return t.PatchMembers(g.ID, ids, nil)
		case "remove":
			if len(raw) == 0 || string(raw) == "null" {
				return t.RemoveAllMembers(g.ID)
			}
			ids, err := members()
			if err != nil {
				return err
			}
			return t.PatchMembers(g.ID, nil, ids)
		case "replace":
			ids, err := members()
			if err != nil {
				return err
			}
			if err := t.RemoveAllMembers(g.ID); err != nil {
				return err
			}
			return t.PatchMembers(g.ID, ids, nil)
		}
	case strings.EqualFold(path, "displayName") && op != "remove":
		display, err := scimString(raw)
		if err != nil {
			return err
		}
		return rename(display)
	case strings.EqualFold(path, "externalId"):
		g.ExternalID = ""
		if op != "remove" {
			v, err := scimString(raw)
			if err != nil {
				return err
			}
			g.ExternalID = v
		}
		return rename(g.DisplayName)
	case path == "" && op != "remove":
		var attrs map[string]json.RawMessage
		if err := json.Unmarshal(raw, &attrs); err != nil {
			return badValue("an operation without a path needs an object value")
		}
		for k, v := range attrs {
			if err := s.applyGroupOp(t, g, op, k, v); err != nil {
				return err
			}
		}
		return nil
	}
	return &scimBadRequest{"invalidPath", fmt.Sprintf("unsupported %s on %q", op, path)}
}

func groupChange(prev, g storage.SCIMGroup) map[string]any {
	added, removed := []string{}, []string{}
	for _, m := range g.Members {
		if !slices.Contains(prev.Members, m) {
			added = append(added, m)
		}
	}
	for _, m := range prev.Members {
		if !slices.Contains(g.Members, m) {
			removed = append(removed, m)
		}
	}
	out := map[string]any{"id": g.ID, "display_name": g.DisplayName, "added": added, "removed": removed}
	if prev.Group != g.Group {
		out["previous_group"] = prev.Domain + ":" + prev.Group
	}
	return out
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request, cfg SCIMConfig) {
	if err := s.scimRun(r, cfg, func(t *storage.SCIMTx) (storage.AuditEvent, error) {
		g, err := t.GetGroup(r.PathValue("id"))
		if err != nil {
			return storage.AuditEvent{}, err
		}
		if err := t.DeleteGroup(g.ID); err != nil {
			return storage.AuditEvent{}, err
		}
		return scimEvent(cfg, "scim.group.delete", g.Domain+":"+g.Group, map[string]any{"id": g.ID, "display_name": g.DisplayName}), nil
	}); err != nil {
		scimStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// refuseSCIMManaged answers 409 when an identity provider owns the
// group, so the Omega API cannot drift it from the provider's view.
func (s *Server) refuseSCIMManaged(w http.ResponseWriter, r *http.Request, domain, name string) bool {
	idp, managed, err := s.store.SCIMManaged(r.Context(), domain, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return true
	}
	if managed {
		writeErr(w, http.StatusConflict, fmt.Errorf("group %s:%s is provisioned by %q over SCIM; change it there", domain, name, idp))
		return true
	}
	return false
}
