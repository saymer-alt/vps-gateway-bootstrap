package state

import (
	"crypto/sha256"
	"encoding/hex"
)

// BuildDiff compares only explicitly specified desired values. Unspecified
// desired state is intentionally ignored: absence is not permission to change.
func BuildDiff(m Model) []DiffItem {
	var d []DiffItem
	add := func(resource string, current, desired any, kind DiffKind, owner Ownership, reason string) {
		d = append(d, DiffItem{Resource: resource, Current: current, Desired: desired, Kind: kind, Ownership: owner, Reason: reason})
	}

	if m.Desired.SSH != nil {
		owner := ownershipOf(m, "ssh")
		if m.Desired.SSH.Port != nil {
			if len(m.Actual.Security.SSHPorts) == 1 && m.Actual.Security.SSHPorts[0] == *m.Desired.SSH.Port {
				add("ssh.port", m.Actual.Security.SSHPorts, *m.Desired.SSH.Port, NoChange, owner, "effective SSH port already matches")
			} else if owner == Unknown {
				add("ssh.port", m.Actual.Security.SSHPorts, *m.Desired.SSH.Port, Conflict, owner, "SSH ownership is unknown")
			} else {
				add("ssh.port", m.Actual.Security.SSHPorts, *m.Desired.SSH.Port, Update, owner, "effective SSH port differs")
			}
		}
		if m.Desired.SSH.PasswordAuthentication != nil && m.Actual.Security.PasswordAuthentication != nil {
			if *m.Desired.SSH.PasswordAuthentication == *m.Actual.Security.PasswordAuthentication {
				add("ssh.password_authentication", *m.Actual.Security.PasswordAuthentication, *m.Desired.SSH.PasswordAuthentication, NoChange, owner, "effective SSH setting already matches")
			} else if owner == Unknown {
				add("ssh.password_authentication", *m.Actual.Security.PasswordAuthentication, *m.Desired.SSH.PasswordAuthentication, Conflict, owner, "SSH ownership is unknown")
			} else {
				add("ssh.password_authentication", *m.Actual.Security.PasswordAuthentication, *m.Desired.SSH.PasswordAuthentication, Update, owner, "effective SSH setting differs")
			}
		}
	}

	if m.Desired.Mihomo != nil && m.Desired.Mihomo.Integration != nil {
		owner := ownershipOf(m, "mihomo.integration")
		if *m.Desired.Mihomo.Integration {
			if !m.Actual.Gateway.MihomoInstalled {
				if owner == Unknown { add("mihomo.integration", false, true, Conflict, owner, "Mihomo ownership is unknown") } else { add("mihomo.integration", false, true, Create, owner, "Mihomo integration is requested") }
			} else { add("mihomo.integration", m.Actual.Gateway.MihomoActive, true, Update, owner, "integration requires effective runtime validation") }
		} else if m.Actual.Gateway.MihomoInstalled {
			add("mihomo.integration", true, false, ExternalDiff, owner, "Mihomo runtime is present; removal is not implied")
		}
	}

	if m.Desired.Mieru != nil && m.Desired.Mieru.Enabled != nil {
		owner := ownershipOf(m, "mieru")
		if *m.Desired.Mieru.Enabled == m.Actual.Gateway.MieruActive {
			add("mieru.enabled", m.Actual.Gateway.MieruActive, *m.Desired.Mieru.Enabled, NoChange, owner, "effective Mieru state already matches")
		} else if owner == External {
			add("mieru.enabled", m.Actual.Gateway.MieruActive, *m.Desired.Mieru.Enabled, ExternalDiff, owner, "Mieru runtime is externally owned")
		} else if owner == Unknown {
			add("mieru.enabled", m.Actual.Gateway.MieruActive, *m.Desired.Mieru.Enabled, Conflict, owner, "Mieru ownership is unknown")
		} else {
			add("mieru.enabled", m.Actual.Gateway.MieruActive, *m.Desired.Mieru.Enabled, Update, owner, "effective Mieru state differs")
		}
	}

	// Desired service runtime state. Only explicitly listed units are ever
	// considered; a unit missing from discovery is a conflict, not a gap to
	// fill by installing or starting something unverified.
	for _, sd := range m.Desired.Services {
		if sd.Name == "" || sd.Active == nil { continue }
		resource := "service." + sd.Name
		owner := ownershipOf(m, "service."+sd.Name)
		var actual *ServiceActual
		for i := range m.Actual.Services {
			if m.Actual.Services[i].Name == sd.Name { actual = &m.Actual.Services[i]; break }
		}
		if actual == nil {
			add(resource, nil, *sd.Active, Conflict, owner, "unit was not discovered on the machine")
			continue
		}
		switch {
		case *sd.Active == actual.Active:
			add(resource, actual.Active, *sd.Active, NoChange, owner, "service state already matches")
		case owner == Unknown:
			add(resource, actual.Active, *sd.Active, Conflict, owner, "service ownership is unknown")
		case owner == External:
			add(resource, actual.Active, *sd.Active, ExternalDiff, owner, "service is externally owned")
		default:
			add(resource, actual.Active, *sd.Active, Update, owner, "service state differs")
		}
	}

	// Desired managed files. Only explicitly listed paths are ever
	// considered; a path absent from the actual-state inspection is a CREATE
	// (backup records ABSENT so rollback removes it), never a guess about
	// what the file should contain.
	for _, fd := range m.Desired.Files {
		if fd.Path == "" || fd.Content == "" { continue }
		resource := "file." + fd.Path
		owner := ownershipOf(m, "file."+fd.Path)
		sum := sha256.Sum256([]byte(fd.Content))
		desiredHash := hex.EncodeToString(sum[:])
		var actual *FileActual
		for i := range m.Actual.Files {
			if m.Actual.Files[i].Path == fd.Path { actual = &m.Actual.Files[i]; break }
		}
		switch {
		case owner == Unknown:
			add(resource, actualHash(actual), desiredHash, Conflict, owner, "file ownership is unknown")
		case owner == External:
			add(resource, actualHash(actual), desiredHash, ExternalDiff, owner, "file is externally owned")
		case actual == nil:
			add(resource, nil, desiredHash, Conflict, owner, "file was not inspected before planning")
		case !actual.Exists:
			add(resource, nil, desiredHash, Create, owner, "file does not exist and is desired")
		case actual.SHA256 != desiredHash || actual.Mode != effectiveMode(fd.Mode):
			add(resource, actual.SHA256, desiredHash, Update, owner, "file content or mode differs")
		default:
			add(resource, desiredHash, desiredHash, NoChange, owner, "file already matches desired content")
		}
	}

	m.Diff = d
	return d
}

func actualHash(actual *FileActual) any {
	if actual == nil { return nil }
	return actual.SHA256
}

func effectiveMode(desired uint32) uint32 {
	if desired == 0 { return 0600 }
	return desired
}

func ownershipOf(m Model, resource string) Ownership {
	if m.Ownership == nil { return Unknown }
	if o, ok := m.Ownership[resource]; ok { return o }
	return Unknown
}
