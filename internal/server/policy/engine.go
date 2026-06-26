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

	cedar "github.com/cedar-policy/cedar-go"
)

// Engine holds a Cedar PolicySet plus the static entity map. It is safe
// for concurrent Evaluate calls; Reload swaps the underlying state under
// a write lock.
type Engine struct {
	mu       sync.RWMutex
	policies *cedar.PolicySet
	entities cedar.EntityMap
}

// New returns an Engine with an empty policy set and no entities. A
// request against an empty engine will always evaluate to deny, matching
// Cedar's default-deny semantics.
func New() *Engine {
	return &Engine{
		policies: cedar.NewPolicySet(),
		entities: cedar.EntityMap{},
	}
}

// LoadDir reads every *.cedar file in dir as a Cedar policy and, if
// present, dir/entities.json as the entity map. The two are swapped in
// atomically; on error the engine is left untouched.
func (e *Engine) LoadDir(dir string) error {
	ps, ents, err := loadFromDir(dir)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.policies = ps
	e.entities = ents
	e.mu.Unlock()
	return nil
}

func loadFromDir(dir string) (*cedar.PolicySet, cedar.EntityMap, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.cedar"))
	if err != nil {
		return nil, nil, fmt.Errorf("glob policies: %w", err)
	}
	sort.Strings(matches)

	ps := cedar.NewPolicySet()
	for _, path := range matches {
		// #nosec G304 -- path comes from operator-supplied --policy-dir glob, not user input.
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
		base := filepath.Base(path)
		fileSet, err := cedar.NewPolicySetFromBytes(base, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
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
				return nil, nil, fmt.Errorf("duplicate policy id %q (defined again in %s)", id, path)
			}
		}
	}

	ents := cedar.EntityMap{}
	entPath := filepath.Join(dir, "entities.json")
	// #nosec G304 -- path is operator-controlled --policy-dir, not user input.
	if raw, err := os.ReadFile(entPath); err == nil {
		if err := json.Unmarshal(raw, &ents); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", entPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read %s: %w", entPath, err)
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

// Evaluate runs the request through the policy set and returns the
// AuthZEN decision. Missing subject/resource type or id is treated as a
// validation error rather than a silent deny.
func (e *Engine) Evaluate(req EvalRequest) (EvalResponse, error) {
	if err := validate(req); err != nil {
		return EvalResponse{}, err
	}

	principalUID := cedar.NewEntityUID(cedar.EntityType(req.Subject.Type), cedar.String(req.Subject.ID))
	resourceUID := cedar.NewEntityUID(cedar.EntityType(req.Resource.Type), cedar.String(req.Resource.ID))
	ctxRecord, err := recordFromMap(req.Context)
	if err != nil {
		return EvalResponse{}, fmt.Errorf("context: %w", err)
	}
	cedarReq := cedar.Request{
		Principal: principalUID,
		Action:    cedar.NewEntityUID("Action", cedar.String(req.Action.Name)),
		Resource:  resourceUID,
		Context:   ctxRecord,
	}

	e.mu.RLock()
	ps := e.policies
	baseEnts := e.entities
	e.mu.RUnlock()

	// Seed per-request entities for subject/resource attrs so policies can
	// read `principal.kind`, `resource.x`, etc. without the operator
	// pre-declaring every transient identity in entities.json. Static
	// entities from LoadDir win on UID collision (we only fill in attrs
	// when the operator did not already define the entity).
	ents := baseEnts
	overlays, err := requestEntities(principalUID, req.Subject.Attrs, resourceUID, req.Resource.Attrs)
	if err != nil {
		return EvalResponse{}, err
	}
	if len(overlays) > 0 {
		ents = baseEnts.Clone()
		for uid, ent := range overlays {
			if _, exists := ents[uid]; exists {
				continue
			}
			ents[uid] = ent
		}
	}

	ok, diag := cedar.Authorize(ps, ents, cedarReq)
	resp := EvalResponse{Decision: bool(ok)}
	for _, r := range diag.Reasons {
		resp.Reasons = append(resp.Reasons, string(r.PolicyID))
	}
	return resp, nil
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
