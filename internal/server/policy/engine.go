// Package policy is the Omega Policy Decision Point.
//
// It wraps cedar-go to evaluate AuthZEN-style {subject, action, resource,
// context} requests against a Cedar policy set. Policies are loaded from
// a directory of .cedar files at startup; an optional entities.json in
// the same directory seeds the entity store with parents/attrs.
package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
)

// Engine holds a Cedar PolicySet plus the static entity map. It is safe
// for concurrent Evaluate calls; Reload swaps the underlying state under
// a write lock.
type Engine struct {
	mu       sync.RWMutex
	policies *cedar.PolicySet
	// static is the entity map from entities.json, directory the one
	// projected from control-plane state (SetDirectory); entities is
	// their union, with static winning on a UID collision.
	static cedar.EntityMap
	// sources and staticRaw are what LoadDir / LoadSources read, kept so
	// the exact policy set can be distributed to local evaluators.
	sources   map[string]string
	staticRaw []byte
	dirSpec   Directory
	directory cedar.EntityMap
	snap      directorySnapshot
	entities  cedar.EntityMap
	// byType is the entity map indexed by Cedar entity type, each bucket
	// sorted by id. Built once per load rather than per call: the map is
	// immutable between LoadDir calls, and Search reads it once per page,
	// so scanning and sorting on demand would make walking an N-entity
	// store cost O(N^2 log N) in total even though each page evaluates at
	// most MaxSearchCandidates candidates.
	byType map[string][]Entity
	// revision is the bundle revision last loaded with LoadBundle.
	revision string
}

// New returns an Engine with an empty policy set and no entities. A
// request against an empty engine will always evaluate to deny, matching
// Cedar's default-deny semantics.
func New() *Engine {
	return &Engine{
		policies:  cedar.NewPolicySet(),
		static:    cedar.EntityMap{},
		directory: cedar.EntityMap{},
		entities:  cedar.EntityMap{},
		byType:    map[string][]Entity{},
	}
}

// LoadDir reads every *.cedar file in dir as a Cedar policy and, if
// present, dir/entities.json as the entity map. The two are swapped in
// atomically; on error the engine is left untouched.
func (e *Engine) LoadDir(dir string) error {
	sources, raw, err := readDir(dir)
	if err != nil {
		return err
	}
	return e.LoadSources(sources, raw)
}

// LoadSources replaces the policy set with the given Cedar sources
// (file name -> text) and the static entity map (entities.json bytes,
// nil for none). On error the engine is left untouched.
func (e *Engine) LoadSources(sources map[string]string, entitiesJSON []byte) error {
	ps, ents, err := parseSources(sources, entitiesJSON)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.policies = ps
	e.static = ents
	e.sources = sources
	e.staticRaw = entitiesJSON
	e.rebuildLocked()
	e.mu.Unlock()
	return nil
}

// Snapshot returns what the engine evaluates against: the Cedar sources,
// the static entities.json bytes, and the projected directory.
func (e *Engine) Snapshot() (map[string]string, []byte, Directory) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sources, e.staticRaw, e.dirSpec
}

// indexByType groups the entity map by type, sorting each bucket by id.
//
// The sort is load-bearing rather than cosmetic: a Search page token
// encodes an offset into one of these slices, and Go randomises map
// iteration, so an unstable order would make the same offset name a
// different entity on the next call - silently skipping some and
// repeating others across a paginated sequence.
func indexByType(ents cedar.EntityMap) map[string][]Entity {
	idx := map[string][]Entity{}
	for uid := range ents {
		typ := string(uid.Type)
		idx[typ] = append(idx[typ], Entity{Type: typ, ID: string(uid.ID)})
	}
	for _, bucket := range idx {
		sort.Slice(bucket, func(i, j int) bool { return bucket[i].ID < bucket[j].ID })
	}
	return idx
}

// readDir reads every *.cedar file in dir and, if present,
// dir/entities.json.
func readDir(dir string) (map[string]string, []byte, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.cedar"))
	if err != nil {
		return nil, nil, fmt.Errorf("glob policies: %w", err)
	}
	sources := make(map[string]string, len(matches))
	for _, path := range matches {
		// #nosec G304 -- path comes from operator-supplied --policy-dir glob, not user input.
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
		sources[filepath.Base(path)] = string(raw)
	}
	entPath := filepath.Join(dir, "entities.json")
	// #nosec G304 -- path is operator-controlled --policy-dir, not user input.
	raw, err := os.ReadFile(entPath)
	if os.IsNotExist(err) {
		return sources, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", entPath, err)
	}
	return sources, raw, nil
}

func parseSources(sources map[string]string, entitiesJSON []byte) (*cedar.PolicySet, cedar.EntityMap, error) {
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)

	ps := cedar.NewPolicySet()
	for _, base := range names {
		fileSet, err := cedar.NewPolicySetFromBytes(base, []byte(sources[base]))
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", base, err)
		}
		// cedar-go names every parsed policy "policy0", "policy1", ... per
		// file, which collides as soon as the operator splits policies
		// across multiple .cedar files. Honour an explicit @id("...")
		// annotation when present and otherwise fall back to a
		// filename-stem-prefixed default - both forms collapse to a single
		// stable, human-readable id that flows through to /access/v1
		// reasons[] and the audit log.
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		for autoID, p := range fileSet.All() {
			id := cedar.PolicyID(stem + "::" + string(autoID))
			if v, ok := p.Annotations()["id"]; ok && v != "" {
				id = cedar.PolicyID(v)
			}
			if !ps.Add(id, p) {
				return nil, nil, fmt.Errorf("duplicate policy id %q (defined again in %s)", id, base)
			}
		}
	}

	ents := cedar.EntityMap{}
	if len(entitiesJSON) > 0 {
		if err := json.Unmarshal(entitiesJSON, &ents); err != nil {
			return nil, nil, fmt.Errorf("parse entities.json: %w", err)
		}
	}
	return ps, ents, nil
}

// Entity is the on-the-wire form of an AuthZEN subject/resource: a typed
// id pair plus optional free-form attributes. Action carries only Name
// (mapped to Cedar's Action::"name") and is represented separately.
type Entity struct {
	Type  string         `json:"type"`
	ID    string         `json:"id"`
	Attrs map[string]any `json:"properties,omitempty"`
}

type Action struct {
	Name string `json:"name"`
}

// EvalRequest mirrors the AuthZEN PDP API evaluation request shape.
type EvalRequest struct {
	Subject  Entity         `json:"subject"`
	Action   Action         `json:"action"`
	Resource Entity         `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvalResponse is the AuthZEN decision response. The optional
// `context` field defined by AuthZEN is intentionally omitted.
type EvalResponse struct {
	Decision bool     `json:"decision"`
	Reasons  []string `json:"reasons,omitempty"`
}

// ActionEntityType is the Cedar entity type reserved for actions. An
// AuthZEN action `{"name": "can_read"}` is `Action::"can_read"` to
// Cedar, so action enumeration reads the same entity store as subject
// and resource enumeration rather than a separate catalog.
const ActionEntityType = "Action"

// EntitiesOfType returns every entity of the given Cedar type held in
// the entity store (`entities.json` plus the domains from SetDirectory), as AuthZEN
// entities sorted by id. Attributes are deliberately not projected: the
// caller is enumerating a search space, and a Cedar Record does not
// round-trip losslessly into the `properties` bag.
//
// The returned slice is the engine's own and MUST NOT be mutated. It is
// shared rather than copied because the caller windows it to at most
// MaxSearchCandidates entries and only reads; copying the whole bucket
// per request would reintroduce the per-call cost the type index exists
// to remove. A concurrent LoadDir swaps in a new map and leaves this
// slice alone, so a request in flight keeps reading a consistent
// snapshot.
//
// This is the whole search space. Omega does not enumerate principals
// from SVID issuance history or resources from anywhere else, so an
// entity the operator did not declare is not searchable - a bound this
// is the only honest way to state, since the alternative is a short
// result set that reads as "these are all of them".
func (e *Engine) EntitiesOfType(typ string) []Entity {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.byType[typ]
}

// ActionNames returns the ids of every Action entity in the store, in
// sorted order. Actions that appear only in a policy's action scope and
// were never declared as entities are not returned; see EntitiesOfType
// for why the store is treated as the whole search space.
func (e *Engine) ActionNames() []string {
	ents := e.EntitiesOfType(ActionEntityType)
	out := make([]string, 0, len(ents))
	for _, ent := range ents {
		out = append(out, ent.ID)
	}
	return out
}

// Evaluate runs the request through the policy set and returns the
// AuthZEN decision. Missing subject/resource type or id is treated as a
// validation error rather than a silent deny.
func (e *Engine) Evaluate(req EvalRequest) (EvalResponse, error) {
	resp, _, err := e.EvaluateRevision(req)
	return resp, err
}

// EvaluateRevision is Evaluate that also returns the revision of the
// bundle the decision was made with ("" unless loaded by LoadBundle).
func (e *Engine) EvaluateRevision(req EvalRequest) (EvalResponse, string, error) {
	cedarReq, overlays, err := prepare(req)
	if err != nil {
		return EvalResponse{}, "", err
	}

	e.mu.RLock()
	ps := e.policies
	baseEnts := e.entities
	snap := e.snap
	rev := e.revision
	e.mu.RUnlock()

	// Seed per-request entities for subject/resource attrs so policies can
	// read `principal.kind`, `resource.x`, etc. without the operator
	// pre-declaring every transient identity in entities.json. Static
	// entities from LoadDir win on UID collision (we only fill in attrs
	// when the operator did not already define the entity).
	ents := baseEnts
	if len(overlays) > 0 {
		ents = baseEnts.Clone()
		for uid, ent := range overlays {
			if _, exists := ents[uid]; exists {
				continue
			}
			ents[uid] = ent
		}
	}

	ents = withSPIFFEParents(ents, snap, time.Now(), cedarReq.Principal, cedarReq.Resource)

	ok, diag := cedar.Authorize(ps, ents, cedarReq)
	resp := EvalResponse{Decision: bool(ok)}
	for _, r := range diag.Reasons {
		resp.Reasons = append(resp.Reasons, string(r.PolicyID))
	}
	return resp, rev, nil
}

// Validate reports whether Evaluate would reject req as malformed,
// without evaluating it. It lets a batch caller reject a bad entry
// before any entry has been decided or audited.
func Validate(req EvalRequest) error {
	_, _, err := prepare(req)
	return err
}

// prepare is every input check Evaluate performs, producing the Cedar
// request and the per-request entity overlays it evaluates against.
func prepare(req EvalRequest) (cedar.Request, cedar.EntityMap, error) {
	if err := validate(req); err != nil {
		return cedar.Request{}, nil, err
	}
	principalUID := cedar.NewEntityUID(cedar.EntityType(req.Subject.Type), cedar.String(req.Subject.ID))
	resourceUID := cedar.NewEntityUID(cedar.EntityType(req.Resource.Type), cedar.String(req.Resource.ID))
	ctxRecord, err := recordFromMap(req.Context)
	if err != nil {
		return cedar.Request{}, nil, fmt.Errorf("context: %w", err)
	}
	overlays, err := requestEntities(principalUID, req.Subject.Attrs, resourceUID, req.Resource.Attrs)
	if err != nil {
		return cedar.Request{}, nil, err
	}
	return cedar.Request{
		Principal: principalUID,
		Action:    cedar.NewEntityUID("Action", cedar.String(req.Action.Name)),
		Resource:  resourceUID,
		Context:   ctxRecord,
	}, overlays, nil
}

func validate(r EvalRequest) error {
	switch {
	case strings.TrimSpace(r.Subject.Type) == "" || strings.TrimSpace(r.Subject.ID) == "":
		return fmt.Errorf("subject.type and subject.id are required")
	case strings.TrimSpace(r.Action.Name) == "":
		return fmt.Errorf("action.name is required")
	case strings.TrimSpace(r.Resource.Type) == "" || strings.TrimSpace(r.Resource.ID) == "":
		return fmt.Errorf("resource.type and resource.id are required")
	}
	return nil
}

// requestEntities builds at most two ephemeral cedar entities (subject /
// resource) carrying the attrs supplied on the request. Returned entries
// are merged into a per-request clone of the static EntityMap and only
// take effect when no static entity already exists for that UID.
func requestEntities(subUID cedar.EntityUID, subAttrs map[string]any, resUID cedar.EntityUID, resAttrs map[string]any) (cedar.EntityMap, error) {
	out := cedar.EntityMap{}
	if len(subAttrs) > 0 {
		rec, err := recordFromMap(subAttrs)
		if err != nil {
			return nil, fmt.Errorf("subject.properties: %w", err)
		}
		out[subUID] = cedar.Entity{UID: subUID, Attributes: rec}
	}
	if len(resAttrs) > 0 && resUID != subUID {
		rec, err := recordFromMap(resAttrs)
		if err != nil {
			return nil, fmt.Errorf("resource.properties: %w", err)
		}
		out[resUID] = cedar.Entity{UID: resUID, Attributes: rec}
	}
	return out, nil
}

// recordFromMap converts a JSON-decoded context map into a Cedar Record.
// Only the JSON primitive shapes are bridged; nested arrays/objects fall
// through as Cedar strings of their JSON representation, which avoids
// pretending to support full Cedar value translation.
func recordFromMap(m map[string]any) (cedar.Record, error) {
	if len(m) == 0 {
		return cedar.NewRecord(cedar.RecordMap{}), nil
	}
	out := cedar.RecordMap{}
	for k, v := range m {
		val, err := valueOf(v)
		if err != nil {
			return cedar.Record{}, fmt.Errorf("%q: %w", k, err)
		}
		out[cedar.String(k)] = val
	}
	return cedar.NewRecord(out), nil
}

func valueOf(v any) (cedar.Value, error) {
	switch x := v.(type) {
	case nil:
		return cedar.String(""), nil
	case bool:
		if x {
			return cedar.True, nil
		}
		return cedar.False, nil
	case string:
		return cedar.String(x), nil
	case float64:
		// JSON has only one number type, so integers arrive as float64.
		// Cedar has no float type; truncating a fractional value would
		// silently corrupt comparisons (e.g. `5.9` -> `5`), so reject
		// anything with a fractional part. Whole-number floats (`5.0`)
		// still map cleanly to Long.
		if x != math.Trunc(x) {
			return nil, fmt.Errorf("number %v has a fractional part; Cedar has no float type (use a whole number or pass it as a string)", x)
		}
		// A whole-number float can still exceed the int64 range (e.g. 1e20);
		// converting that overflows and silently yields a garbage Long. Note
		// float64(math.MaxInt64) rounds up to 2^63, so reject at >= that bound.
		if x >= float64(math.MaxInt64) || x < float64(math.MinInt64) {
			return nil, fmt.Errorf("number %v is out of the supported int64 range", x)
		}
		return cedar.Long(int64(x)), nil
	case int:
		return cedar.Long(int64(x)), nil
	case int64:
		return cedar.Long(x), nil
	case []string:
		vals := make([]cedar.Value, 0, len(x))
		for _, s := range x {
			vals = append(vals, cedar.String(s))
		}
		return cedar.NewSet(vals...), nil
	case []any:
		vals := make([]cedar.Value, 0, len(x))
		for _, e := range x {
			val, err := valueOf(e)
			if err != nil {
				return nil, err
			}
			vals = append(vals, val)
		}
		return cedar.NewSet(vals...), nil
	default:
		raw, _ := json.Marshal(x)
		return cedar.String(string(raw)), nil
	}
}
