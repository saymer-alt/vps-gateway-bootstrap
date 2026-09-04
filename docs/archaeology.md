# Archaeology

This document explains where the current design came from. Historical scripts and notes are evidence, not implementation templates.

## Source repository

A major source of operational evidence is the earlier `saymer-alt/keenetic-auto-setup` project. Its historical VPS runbooks include Debian and Ubuntu setup notes, service installation notes, SSH/firewall experiments, Mieru integration and networking work.

The old material contains both working solutions and dead ends. Bootstrap therefore treats it as an archaeological record.

## Historical material consulted

Relevant historical files include:

```text
scripts/debian1.md
scripts/service
scripts/setup_debian12.sh
scripts/setup_debian12_final.sh
scripts/ubuntu.md
scripts/ubuntu1.md
scripts/ubuntu2,md
scripts/ubuntu3.md
scripts/ubuntu4.md
scripts/ubuntu5.md
scripts/ubuntu6.md
scripts/ubuntu8.md
scripts/ubuntu9.md
scripts/mieru.md
```

The exact historical implementation should not be copied wholesale because it encodes assumptions from particular servers and dates.

## What the archaeology established

### SSH

Historical Ubuntu work demonstrated that SSH socket activation matters. `ssh.socket`, its `ListenStream`, the effective sshd configuration and the actual listening socket all have to be considered.

**Modern consequence:** SSH discovery is a first-class bootstrap operation.

### Firewall

The old setup evolved through both restrictive and permissive egress policies. In particular, deny-outgoing firewall policy caused gateway/proxy failures.

**Modern consequence:** deny incoming / allow outgoing is the baseline; strict egress is explicit.

### Sysctl

Historical hosts accumulated settings such as:

```text
vm.swappiness=10
vm.overcommit_memory=1
BBR/fq
ip_forward=1
```

alongside increasingly aggressive TCP tuning.

**Modern consequence:** preserve useful operational baselines while classifying aggressive tuning as profile-dependent or experimental.

### Mieru

The historical Mieru work revealed a particularly important lifecycle detail: effective configuration requires `mita apply config`, and `mita describe config` is a better validation source than merely reading the JSON file.

Port ranges were also intentionally varied between servers and large ranges were reserved against ephemeral ports.

**Modern consequence:** the Mieru module delegates installation to the official installer and owns only host integration, reservation, firewall and validation.

### Mihomo

Historical proxy routing work demonstrated that Mihomo is most useful as an abstraction layer. It also demonstrated that automatic route manipulation can destroy host connectivity and that fake-IP ranges can collide with other routing state.

**Modern consequence:** Mihomo configuration remains externally supplied; Bootstrap validates it and integrates with it without assuming a particular upstream.

### AWG / Amnezia

Historical AWG→Mihomo scripts contained useful concepts such as policy routing, NAT, forwarding, MSS handling and route tables, but also hardcoded interfaces, subnets and topology assumptions.

**Modern consequence:** those scripts are reference material only. Amnezia is externally owned and its resulting topology must be discovered dynamically.

## Historical hardcoding that must not survive

The following patterns are explicitly rejected as universal implementation assumptions:

```text
eth0 / ens3 as a fixed external interface
172.29.172.0/24 as a fixed AWG subnet
198.18.x.x or another fixed fake-IP range without collision checking
fixed Mieru port ranges
fixed MTU
fixed Docker subnet
fixed routing table/priority without conflict detection
UFW reset on installation
blindly disabling rp_filter globally
blindly enabling Mihomo auto-route
```

## Why archaeology belongs in the repository

Without this document, future maintainers may see an old shell command and mistake it for a requirement. The purpose of archaeology is to preserve the reasoning behind the current design:

```text
old production incident
      ↓
observation
      ↓
lesson
      ↓
requirement
      ↓
new architecture
```

This keeps the project from repeating old failures while avoiding the opposite mistake of treating every historical workaround as permanent truth.

## Relationship to current implementation

Historical code may be mined for:

- failure modes;
- useful diagnostics;
- service-specific lifecycle commands;
- routing concepts;
- validation ideas;
- compatibility information.

Historical code must not automatically determine:

- current defaults;
- interface names;
- network ranges;
- firewall state;
- service topology;
- security policy;
- routing policy.

The current implementation should always follow the newer rule:

```text
real machine state
      ↓
current requirements
      ↓
minimal owned configuration
      ↓
validation
```
