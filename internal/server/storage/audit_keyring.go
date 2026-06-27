package storage

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// keyIDUnkeyed is the sentinel key_id recorded for rows that are not
// MAC'd under an operator-supplied HMAC key. It covers both legacy rows
// written before keying existed and rows written while the server runs
// without --audit-hmac-key-file. Such rows carry only the legacy
// (unkeyed SHA-256) integrity guarantee: tamper-evident against an actor
// who lacks the algorithm, which is nobody. See H1 in the trust-model
// design doc.
const keyIDUnkeyed = "unkeyed"

// AuditKeyring is the operator-supplied HMAC key material for the audit
// chain. It holds one active key (used to MAC new rows) and zero or more
// retired keys retained only for verification, each addressed by a short
// key_id. The keyring lives outside the database so a DB-only attacker
// cannot recompute valid row MACs.
//
// The zero value is not usable; construct via LoadAuditKeyring or
// NewAuditKeyring. AuditKeyring is safe for concurrent use; Reload swaps
// the key set atomically under a write lock.
type AuditKeyring struct {
	mu       sync.RWMutex
	path     string
	activeID string
	keys     map[string][]byte
}

// auditKeyringFile is the on-disk JSON shape of a keyring.
//
//	{
//	  "active_key_id": "2026-06",
//	  "keys": [
//	    {"id": "2026-06", "secret": "<base64 >= 16 bytes>"},
//	    {"id": "2026-01", "secret": "<base64>"}
//	  ]
//	}
//
// The active key MACs new rows; every listed key (active + retired) stays
// loadable so VerifyAudit can check rows written under a now-retired key.
// On rotation the operator appends a new key and points active_key_id at
// it, demoting the previous active key to retired (still listed).
type auditKeyringFile struct {
	ActiveKeyID string `json:"active_key_id"`
	Keys        []struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"keys"`
}

// minAuditKeyBytes is the lower bound on raw HMAC key length. 16 bytes
// (128 bits) is the floor for HMAC-SHA-256 to retain its security
// margin; operators should prefer 32 bytes.
const minAuditKeyBytes = 16

// NewAuditKeyring builds a keyring from an active key_id and a map of
// key_id -> raw secret. It validates that the active id is present and
// every secret meets the minimum length. Used by tests and by
// LoadAuditKeyring.
func NewAuditKeyring(activeID string, keys map[string][]byte) (*AuditKeyring, error) {
	if err := validateKeyset(activeID, keys); err != nil {
		return nil, err
	}
	cp := make(map[string][]byte, len(keys))
	for id, k := range keys {
		b := make([]byte, len(k))
		copy(b, k)
		cp[id] = b
	}
	return &AuditKeyring{activeID: activeID, keys: cp}, nil
}

func validateKeyset(activeID string, keys map[string][]byte) error {
	if strings.TrimSpace(activeID) == "" {
		return fmt.Errorf("audit keyring: active_key_id is required")
	}
	if activeID == keyIDUnkeyed {
		return fmt.Errorf("audit keyring: key_id %q is reserved", keyIDUnkeyed)
	}
	if len(keys) == 0 {
		return fmt.Errorf("audit keyring: at least one key is required")
	}
	if _, ok := keys[activeID]; !ok {
		return fmt.Errorf("audit keyring: active_key_id %q is not present in keys", activeID)
	}
	for id, k := range keys {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("audit keyring: empty key id")
		}
		if id == keyIDUnkeyed {
			return fmt.Errorf("audit keyring: key_id %q is reserved", keyIDUnkeyed)
		}
		if len(k) < minAuditKeyBytes {
			return fmt.Errorf("audit keyring: key %q is %d bytes, want >= %d", id, len(k), minAuditKeyBytes)
		}
	}
	return nil
}

// LoadAuditKeyring reads and validates a keyring file from path.
func LoadAuditKeyring(path string) (*AuditKeyring, error) {
	activeID, keys, err := readKeyringFile(path)
	if err != nil {
		return nil, err
	}
	kr, err := NewAuditKeyring(activeID, keys)
	if err != nil {
		return nil, err
	}
	kr.path = path
	return kr, nil
}

func readKeyringFile(path string) (string, map[string][]byte, error) {
	// #nosec G304 -- path is operator-supplied via --audit-hmac-key-file, not user input.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, fmt.Errorf("audit keyring: read %s: %w", path, err)
	}
	var f auditKeyringFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return "", nil, fmt.Errorf("audit keyring: parse %s: %w", path, err)
	}
	keys := make(map[string][]byte, len(f.Keys))
	for _, k := range f.Keys {
		id := strings.TrimSpace(k.ID)
		if _, dup := keys[id]; dup {
			return "", nil, fmt.Errorf("audit keyring: duplicate key id %q", id)
		}
		secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k.Secret))
		if err != nil {
			return "", nil, fmt.Errorf("audit keyring: key %q secret is not valid base64: %w", id, err)
		}
		keys[id] = secret
	}
	return strings.TrimSpace(f.ActiveKeyID), keys, nil
}

// Reload re-reads the keyring file and atomically replaces the in-memory
// key set. The new file must parse, validate, and still contain the
// currently-active key_id (now possibly retired) so an in-flight verify
// never loses a key it might need. Intended to back a SIGHUP handler.
func (kr *AuditKeyring) Reload() error {
	if kr.path == "" {
		return fmt.Errorf("audit keyring: not file-backed, cannot reload")
	}
	activeID, keys, err := readKeyringFile(kr.path)
	if err != nil {
		return err
	}
	if err := validateKeyset(activeID, keys); err != nil {
		return err
	}
	cp := make(map[string][]byte, len(keys))
	for id, k := range keys {
		cp[id] = k
	}
	// Hold the write lock across reading the previously-active id, the drop
	// check, and the swap, so concurrent reloads cannot interleave between
	// the check and the assignment and drop a still-referenced active key.
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if _, ok := cp[kr.activeID]; !ok {
		return fmt.Errorf("audit keyring: reload would drop previously-active key %q (rows written under it would become unverifiable)", kr.activeID)
	}
	kr.activeID = activeID
	kr.keys = cp
	return nil
}

// active returns the active key_id and its secret, used to MAC new rows.
func (kr *AuditKeyring) active() (string, []byte) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.activeID, kr.keys[kr.activeID]
}

// lookup returns the secret for keyID. ok is false when the keyring does
// not hold that id (e.g. a row written under a key that was dropped).
func (kr *AuditKeyring) lookup(keyID string) (secret []byte, ok bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	secret, ok = kr.keys[keyID]
	return secret, ok
}

// Snapshot returns a copy of the keyring's id->secret map taken under a
// single read lock. VerifyAudit takes one snapshot before walking the
// chain so per-row key lookups are lock-free and see a consistent set of
// keys even if SIGHUP rotates the keyring mid-verify.
func (kr *AuditKeyring) Snapshot() map[string][]byte {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	cp := make(map[string][]byte, len(kr.keys))
	for id, k := range kr.keys {
		cp[id] = k
	}
	return cp
}
