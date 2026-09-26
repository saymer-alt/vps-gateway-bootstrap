# Lessons Learned

This document turns operational failures and successful fixes from real VPS deployments into engineering rules for the bootstrap framework.

## 1. A script that finishes is not necessarily a working gateway

Installation success is not the same as production readiness. Services may be enabled but fail to listen, routing may disappear after reboot, or a proxy may have a stale effective configuration.

**Rule:** validation must test effective state and runtime behaviour.

## 2. SSH is more complicated than `sshd_config`

Ubuntu 24.04 can use `ssh.socket`. A change to `sshd_config` can therefore fail to change the actual listening port.

**Rule:** discover the SSH architecture and verify the real socket before declaring migration successful.

## 3. Never reset the firewall during a rerun

Historical attempts using UFW reset behaviour risk destroying existing access and service rules.

**Rule:** inspect, back up and merge only the rules the bootstrap owns.

## 4. Deny-outgoing is dangerous for a gateway baseline

A gateway needs to initiate DNS, package downloads, proxy connections, updates and other outbound traffic. Historical deny-outgoing experiments caused operational breakage.

**Rule:** default to deny incoming / allow outgoing. Strict egress is opt-in.

## 5. Docker owns part of the networking problem

Docker creates interfaces, subnets and firewall rules. Host-level NAT or TPROXY changes can interact with Docker in surprising ways.

**Rule:** discover Docker topology first. Do not overwrite `daemon.json`, flush Docker rules or apply broad TPROXY rules without explicit topology handling.

## 6. `auto-route: true` can destroy SSH reachability

Mihomo's automatic route installation can replace the host default route in a gateway topology.

**Rule:** the bootstrap must not assume automatic route installation is safe. The routing strategy must be explicit and validated.

## 7. Fake-IP address space can collide with the host topology

A historical Mihomo configuration used an address space that conflicted with another part of the routing environment.

**Rule:** do not hardcode a global fake-IP range. Validate it against existing routes and interfaces.

## 8. Mieru has an application lifecycle beyond systemd

Changing `/etc/mita/server_config.json` and restarting `mita` is not always sufficient. Mieru maintains effective configuration state through its own command interface.

**Rule:** use `mita apply config` and validate with `mita describe config`.

## 9. Large Mieru ranges need Linux port reservation

A large service range can overlap ephemeral ports and produce hard-to-explain failures.

**Rule:** reserve the actual selected range through `ip_local_reserved_ports`, merging with existing reservations.

## 10. Transport availability is environment-dependent

One real VPS had TCP reachability problems while UDP remained usable. Other deployments deliberately used UDP or TCP depending on the environment.

**Rule:** Mieru transport is a per-server decision. Do not assume TCP or UDP is universally available.

## 11. Amnezia version changes can change topology

AmneziaVPN/AmneziaWG is externally installed and its Docker/container topology may change between releases.

**Rule:** treat Amnezia as a black box and discover the resulting interface/container/network state. Never patch internals because an old topology happened to work.

## 12. AWG interception is not universally required

Some clients can build the chain themselves. Others need the VPS to route AWG traffic through Mihomo. Interception can also reduce throughput substantially.

**Rule:** AWG→Mihomo is an optional integration, not a mandatory bootstrap stage.

## 13. Hardcoded interface names work until they don't

Historical servers used both `eth0` and `ens3`, often with alternate names.

**Rule:** derive the external interface from the default route.

## 14. Hardcoded subnets and MTUs are equally fragile

Tunnel addresses, AWG subnets, Docker networks and MTUs vary by installation.

**Rule:** discover actual topology and use supplied service configuration as the source of truth.

## 15. Append-only shell configuration causes drift

Repeated `echo >> /etc/sysctl.conf` or duplicated firewall/routing commands can create conflicting state on reruns.

**Rule:** use managed fragments and idempotent reconciliation.

## 16. Recovery must be designed before risky changes

SSH, firewall and routing are precisely the areas where a mistake can lock the administrator out.

**Rule:** backup first, apply the smallest change, validate the effective result, and preserve a recovery path until the new path is proven.

## 17. Reboot is a real test case

A service being active before reboot does not prove it will survive reboot with the same network topology.

**Rule:** production validation includes persistence across reboot, not merely `systemctl is-enabled`.

## 18. Keep installers small by delegating ownership

Mieru and Amnezia already have their own installers. Reimplementing them inside Bootstrap creates another failure surface.

**Rule:** invoke official installers where practical, then perform host integration and validation.

## 19. Discovery is more valuable than assumptions

The recurring pattern across SSH, Docker, Mihomo, AWG, firewall and routing failures is that the real machine differed from the imagined machine.

**Rule:** Discovery First, Configuration Second.

## 20. Production validation is the final contract

The project should be able to say not merely that software is installed, but that the gateway is ready for traffic.

```text
installed
  ↓
configured
  ↓
effective
  ↓
running
  ↓
reachable
  ↓
end-to-end validated
  ↓
READY FOR PRODUCTION
```

## 21. Test the real executor path, and treat configuration failures as pre-mutation checks

Two production experiments on Saymer3 (fail2ban repair) produced a two-step
lesson.

**Experiment #1 never reached the mutation.** It failed at BACKUP with
`no action registry configured`: the orchestrator bound the plan into the
registry but not into the kind executor's own action map. Unit tests passed
because they used fake executors that keep no action map. The fail-closed
semantics held — nothing ran, nothing was persisted — but the bare stage
name hid the real cause until action errors were surfaced in the CLI output.

**Between the experiments** the actual machine defect was found and repaired
with a verified one-off change (backup first, boundary checks, config test
after): `/etc/fail2ban/jail.local` contained a duplicate `[sshd]` section
(the stock template block), so `fail2ban-client -t` failed. A restart can
never repair a broken configuration, so the configuration test became an
executor preflight check (`fail2ban-client -t`), enforced in Prepare and
re-checked in Execute.

**Experiment #2 hit the same binding gap on the real production path** — the
real `ServiceExecutor` still rejected every action, proving the first fix was
incomplete because integration with real executors was only covered by fakes.
After the fix (`ActionBinder`, commit `eb93f8e`) the full lifecycle completed:
apply succeeded, re-discovery confirmed the unit active, convergence passed,
and the state was persisted.

**Rules:**
- Every new production wiring (orchestrator → real executor) needs at least
  one integration test that uses the real executor, not a fake. Fake-only
  coverage hid a production bug.
- A service that ships a read-only configuration test (e.g. `fail2ban-client
  -t`) must run it as an executor preflight check in Prepare and Execute.
  The check set is explicit per-service knowledge in code, never plan-supplied
  commands.
- Report failures with the concrete action error; a bare stage name hid the
  real cause during experiment #1.

## 22. Rollback needs ownership evidence before mutation

A live SE2 audit on 2026-09-23 exposed a failure pattern in the older
`amnezia-mihomo-gateway` workflow: after gateway removal, an installer-created
Docker DNS override, the `100 mihomo` routing-table registration and installer-era
Mihomo config changes could remain behind. The Docker DNS residue caused real
container resolution failures until it was removed.

The important lesson is broader than that repository. `link-generators` can define a
desired Mihomo VPS-Gateway configuration, and `amnezia-mihomo-gateway` can provide the
current integration mechanics, but neither a file name nor a familiar value proves that
Bootstrap owns the live resource.

**Rule:** before AWG/Mihomo integration mutates system-wide state, Bootstrap must discover
or record the exact pre-change state and ownership. Repair/uninstall may restore only
resources proven OWNED; generator output is desired-state input, never ownership proof.

## 23. A host-local service can work while its container consumer is still blocked

A live Ubuntu 24.04 AWG -> Mihomo gateway showed a subtle validation failure. Mihomo DNS
was healthy on the host and answered via the Docker bridge address, but the AWG container
timed out because UFW's incoming policy blocked container -> host port 53. Adding narrow
UDP and TCP allowances for the actual Docker bridge/subnet restored both DNS and HTTPS.

This is distinct from the earlier SE2 uninstall-residue case: here the gateway was still
active and the host service itself was healthy. The missing contract was firewall
reachability between an externally owned container and a host service introduced into its
runtime dependency chain.

**Rule:** if Bootstrap makes one component depend on another across a firewall boundary,
validation must originate from the real consumer side. The firewall allowance, if needed,
is an owned transactional resource: discover -> plan -> backup/record ownership -> apply ->
validate from the consumer -> rollback only the owned rule. Host-local success must never
stand in for end-to-end reachability.

The same host also carried a stale watchdog that treated `lookup mihomo` as different from
`lookup 100` and restarted routing every minute. Replacing it with alias-aware semantic
checks eliminated the loop. **Rule:** parse/compare effective routing state, not a single
human-readable rendering of an iproute2 table identifier.

## 24. Logging is a bounded resource on small VPS

A live Saymer3 audit on 2026-09-23 showed two independent ways a small gateway can
lose disk space to logs. First, a stale WARP watchdog was firing about once per minute,
mis-detecting a healthy named routing table and producing a systemd failure/restart loop.
Second, a custom logrotate stanza duplicated the distro rsyslog/UFW log ownership, so
`logrotate.service` itself failed with `duplicate log entry`. The operator had recently
seen more than 3 GB of low-value logs consume space on a small VPS disk.

The repair had two layers: fix the noisy producer first, then put an explicit storage
budget around logging. On Saymer3, successful watchdog checks were reduced to a 5-minute
cadence, rsyslog/UFW rotation was restored as daily with four retained rotations, and
journald was bounded to 128 MiB / 7 days while preserving at least 1 GiB of free space.
After applying the journal limits, reported journal usage was 104.9 MiB.

**Rule:** logging capacity is part of production resource management. Discovery/validation
must include logrotate health, journal disk usage and failed high-frequency timers/services.
A bootstrap should never rely on rotation alone to mask a restart/error loop: repair the
producer, verify `logrotate -d` has no duplicate ownership, and enforce an explicit
journald size/retention/free-space budget appropriate to the host.



## 25. Prefer application-level AWG -> Mihomo chaining when the ingress already supports it

A live Ubuntu 24.04 VPS test on 2026-09-26 used an AmneziaWG 3.1 inbound created
directly in 3X-UI/Xray and routed that inbound to Mihomo without the older
host-level AWG interception path. End-to-end external-IP testing showed the
Mihomo egress address rather than the VPS public address, so the target service
saw the selected Mihomo upstream as the traffic source.

In this topology the data path is conceptually:

```text
AWG client
   ↓
3X-UI / Xray AWG inbound
   ↓
Mihomo
   ↓
selected upstream
   ↓
Internet
```

rather than:

```text
AWG client
   ↓
host NAT / marking / policy routing
   ↓
Mihomo
   ↓
selected upstream
   ↓
Internet
```

The operator also observed higher throughput with the direct 3X-UI/Xray ->
Mihomo path than with the previous host-routing integration on this VPS. This
is an operational observation from one deployment, not a universal benchmark:
future validation should compare the two paths under the same endpoint,
client, transport and load before attributing a specific performance gain to
one mechanism.

**Rule:** when an ingress application can explicitly route its own AWG traffic
to Mihomo and end-to-end validation proves the intended external IP, prefer
that application-level chain over adding host-wide NAT/policy-routing state.
Use host-level AWG interception only for topologies that actually require it.
Bootstrap should discover and validate the selected mode instead of assuming
that every AWG deployment needs system routing integration.
