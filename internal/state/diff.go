package state

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

	m.Diff = d
	return d
}

func ownershipOf(m Model, resource string) Ownership {
	if m.Ownership == nil { return Unknown }
	if o, ok := m.Ownership[resource]; ok { return o }
	return Unknown
}
