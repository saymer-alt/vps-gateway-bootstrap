package state

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fsatomic"
)

// PersistedStatePath is the default location of the bootstrap state record.
const PersistedStatePath = "/etc/vps-gateway/state.json"

// The persisted file is the LAST-KNOWN-GOOD record and must never be
// confused with the other state kinds the pipeline works with:
//
//	live discovered state (Model.Actual)  — rebuilt from Discovery on every
//	                                        run, never read from the file;
//	persisted last-known-good (this file) — written only after verified
//	                                        success, used as a fallback for
//	                                        ownership/desired BELOW explicit
//	                                        config, never above live discovery;
//	desired state (Model.Desired)         — what the operator asked for;
//	ownership (Model.Ownership)           — explicit declarations; UNKNOWN
//	                                        stays UNKNOWN and is persisted as
//	                                        UNKNOWN, never silently dropped
//	                                        or upgraded to OWNED/ABSENT.

// SaveModel atomically persists the state model as the last-known-good
// record. Per docs/state-model.md the file must only ever contain VERIFIED
// state — "apply → re-discover → validate → persist" — so this primitive
// refuses models that are not in a verified-good condition: non-OK status or
// unresolved blocking constraints. Persisting an unverified or partially
// applied result as successful is a contract violation.
//
// Before replacing an existing state file, SaveModel refuses to overwrite a
// document whose schema version this binary does not support (in particular
// a NEWER version written by a newer binary): silent downgrade-overwrites
// would discard evidence without a trace (TASK-27). Malformed or
// version-less existing files also refuse — corrupt evidence is not
// evidence of absence. Replacement is durable: atomic write with file fsync
// plus parent-directory fsync (fsatomic.WriteFileSyncDir), matching the
// journal and backup persistence paths (TASK-28).
func SaveModel(path string, m Model) error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("refusing to persist state with schema version %d (want %d)", m.SchemaVersion, SchemaVersion)
	}
	if m.UpdatedAt.IsZero() {
		return fmt.Errorf("refusing to persist state without updated_at timestamp")
	}
	if m.Status != StatusOK {
		return fmt.Errorf("refusing to persist non-verified state with status %q; only %q state may be recorded as last-known-good", m.Status, StatusOK)
	}
	for _, c := range m.Constraints {
		if c.Blocking {
			return fmt.Errorf("refusing to persist state with blocking constraint %s: %s", c.Code, c.Message)
		}
	}
	version, exists, err := existingStateVersion(path)
	if err != nil {
		return err
	}
	if exists {
		if version > SchemaVersion {
			return fmt.Errorf("refusing to overwrite state %s: on-disk schema version %d is newer than the highest supported version %d; the file was left untouched (a newer binary is required to read it)", path, version, SchemaVersion)
		}
		if version != SchemaVersion {
			return fmt.Errorf("refusing to overwrite state %s: unsupported on-disk schema version %d (supported: %d); the file was left untouched for manual review", path, version, SchemaVersion)
		}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return fsatomic.WriteFileSyncDir(path, append(data, '\n'), 0600)
}

// existingStateVersion reports the schema_version field of an existing state
// file, far enough to protect it from downgrade-overwrites without applying
// full model validation (an old export that would fail SaveModel-grade
// checks must still not be silently replaced). It returns exists=false only
// for a genuinely absent file; unreadable, malformed, version-less, or
// non-file destinations are errors that fail closed.
func existingStateVersion(path string) (version int, exists bool, err error) {
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("state %s: unable to read existing state before replacement: %w", path, readErr)
	}
	var probe struct {
		SchemaVersion *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return 0, false, fmt.Errorf("state %s: existing state is malformed and was left untouched: %w", path, err)
	}
	if probe.SchemaVersion == nil {
		return 0, false, fmt.Errorf("state %s: existing state has no schema_version field and was left untouched for manual review", path)
	}
	return *probe.SchemaVersion, true, nil
}

// LoadModel reads and validates a persisted state model.
func LoadModel(path string) (Model, error) {
	data, err := os.ReadFile(path)
	if err != nil { return Model{}, err }
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		return Model{}, fmt.Errorf("state %s: %w", path, err)
	}
	if m.SchemaVersion != SchemaVersion {
		return Model{}, fmt.Errorf("state %s: unsupported schema version %d (want %d)", path, m.SchemaVersion, SchemaVersion)
	}
	return m, nil
}

// LoadModelIfPresent loads persisted state without treating absence as an
// error: a machine that bootstrap never touched simply contributes no
// previous state. Explicit state paths are handled by callers using LoadModel.
func LoadModelIfPresent(path string) (*Model, error) {
	m, err := LoadModel(path)
	if err == nil { return &m, nil }
	if os.IsNotExist(err) { return nil, nil }
	return nil, err
}
