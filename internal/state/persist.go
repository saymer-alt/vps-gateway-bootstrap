package state

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fsatomic"
)

// PersistedStatePath is the default location of the bootstrap state record.
const PersistedStatePath = "/etc/vps-gateway/state.json"

// SaveModel atomically persists the state model. Per docs/state-model.md the
// file records the last KNOWN managed state and must only be written from
// verified state — persisting an unverified post-apply result as successful
// is a contract violation this primitive intentionally does not decide about.
func SaveModel(path string, m Model) error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("refusing to persist state with schema version %d (want %d)", m.SchemaVersion, SchemaVersion)
	}
	if m.UpdatedAt.IsZero() {
		return fmt.Errorf("refusing to persist state without updated_at timestamp")
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil { return err }
	return fsatomic.WriteFile(path, append(data, '\n'), 0600)
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
