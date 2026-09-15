package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func loadFixture(t *testing.T, entitiesJSON string) *Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"),
		[]byte(`permit (principal, action, resource) when { false };`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if entitiesJSON != "" {
		if err := os.WriteFile(filepath.Join(dir, "entities.json"), []byte(entitiesJSON), 0o600); err != nil {
			t.Fatalf("write entities: %v", err)
		}
	}
	e := New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("load dir: %v", err)
	}
	return e
}

const enumerateFixture = `[
  {"uid": {"type": "User", "id": "carol"}, "attrs": {}, "parents": []},
  {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": []},
  {"uid": {"type": "User", "id": "bob"},   "attrs": {}, "parents": []},
  {"uid": {"type": "Doc",  "id": "d1"},    "attrs": {}, "parents": []},
  {"uid": {"type": "Action", "id": "write"}, "attrs": {}, "parents": []},
  {"uid": {"type": "Action", "id": "read"},  "attrs": {}, "parents": []}
]`

func TestEntitiesOfTypeFiltersAndSorts(t *testing.T) {
	e := loadFixture(t, enumerateFixture)

	got := e.EntitiesOfType("User")
	want := []string{"alice", "bob", "carol"}
	if len(got) != len(want) {
		t.Fatalf("got %d entities (%+v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Errorf("entity %d: got %q want %q", i, got[i].ID, want[i])
		}
		if got[i].Type != "User" {
			t.Errorf("entity %d: type %q want User", i, got[i].Type)
		}
	}
}

// Sorting is load-bearing, not cosmetic: an opaque page token is an
// offset into this slice, so an unstable order would silently skip and
// repeat entities between pages. Go randomises map iteration, so
// repeating the call is a real (if probabilistic) check.
func TestEntitiesOfTypeOrderIsStableAcrossCalls(t *testing.T) {
	e := loadFixture(t, enumerateFixture)

	first := e.EntitiesOfType("User")
	for i := range 50 {
		got := e.EntitiesOfType("User")
		for j := range got {
			if got[j].ID != first[j].ID {
				t.Fatalf("call %d differs at index %d: got %q want %q", i, j, got[j].ID, first[j].ID)
			}
		}
	}
}

// The type index is built once per LoadDir, not per call: Search reads
// it once per page, so rebuilding it on demand would make walking an
// N-entity store cost O(N^2 log N) overall. Sharing the backing array
// across calls is the observable consequence, and checking it is what
// keeps a future "just scan and sort here" refactor from reintroducing
// the cost silently.
func TestEntitiesOfTypeIsPrecomputedNotRebuiltPerCall(t *testing.T) {
	e := loadFixture(t, enumerateFixture)

	first := e.EntitiesOfType("User")
	second := e.EntitiesOfType("User")
	if len(first) == 0 {
		t.Fatal("fixture should declare User entities")
	}
	if &first[0] != &second[0] {
		t.Error("EntitiesOfType rebuilt its slice; the per-type index should be built at load time")
	}
}

func TestEntitiesOfTypeUnknownTypeIsEmpty(t *testing.T) {
	e := loadFixture(t, enumerateFixture)
	if got := e.EntitiesOfType("Nope"); len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}

func TestActionNamesReadsActionEntities(t *testing.T) {
	e := loadFixture(t, enumerateFixture)
	got := e.ActionNames()
	want := []string{"read", "write"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("action %d: got %q want %q", i, got[i], want[i])
		}
	}
}

// A policy dir with no entities.json is legal; enumeration then finds
// nothing, which is what makes the API layer's "no entities of this
// type" error the right response rather than an empty result set.
func TestEnumerationOnAnEmptyStore(t *testing.T) {
	e := loadFixture(t, "")
	if got := e.EntitiesOfType("User"); len(got) != 0 {
		t.Errorf("entities: got %+v, want empty", got)
	}
	if got := e.ActionNames(); len(got) != 0 {
		t.Errorf("actions: got %v, want empty", got)
	}
}
