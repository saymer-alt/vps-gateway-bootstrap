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
UDP and TCP allowances from the actual Docker bridge/subnet restored both DNS and HTTPS.

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



Validation evidence from the same test:
- browser public IPv4 was `104.28.225.220` (Cloudflare, Stockholm), not the VPS
  public address `95.85.224.104`;
- no forwarded IP was detected by the leak-test page;
- IPv6 connectivity from the browser was not reachable, so no separate public
  client IPv6 address was exposed in that test;
- DNS resolution was observed through xTom/dns.sb and WoodyNet resolvers in
  Frankfurt, including `147.78.178.170`, `185.222.218.53`,
  `45.80.188.142`, `45.80.188.71`, `74.63.24.206` and
  `74.63.24.211`, plus IPv6 resolver addresses from the same resolver
  infrastructure;
- no ISP DNS and no VPS-host DNS address appeared in the reported resolver set.

These observations support the intended end-to-end path for this deployment:
application traffic exited through the selected Mihomo/Cloudflare path while
DNS requests were also resolved away from the client ISP. DNS egress location
did not match HTTP egress location (Frankfurt resolvers vs Stockholm public
IP), which is acceptable: resolver location and application egress are
independent properties and must be validated separately.

**Rule:** when an ingress application can explicitly route its own AWG traffic
to Mihomo and end-to-end validation proves the intended external IP, prefer
that application-level chain over adding host-wide NAT/policy-routing state.
Use host-level AWG interception only for topologies that actually require it.
Bootstrap should discover and validate the selected mode instead of assuming
that every AWG deployment needs system routing integration.


## 26. Network configuration must not contradict the host's IPv6 policy

A post-update validation of the four real VPS hosts on 2026-09-29 found the
fleet healthy after reboot: Mihomo 1.19.31 and Docker were active on all four
hosts, the AmneziaWG container was running on all four, and no reboot was
pending. Three hosts had no failed systemd units. On `hungry-boyd`
(Ubuntu 24.04.5), however, `ifup@ens3.service` and `networking.service`
were failed even though IPv4 connectivity, SSH, Mihomo, Docker and AWG were
working.

The boot journal showed the actual sequence:

```text
Error: ipv6: IPv6 is disabled on this device.
ifup: failed to bring up ens3
Error: ipv4: Address already assigned.
```

The live interface already had the working IPv4 configuration
`95.85.224.104/32` with default gateway `10.0.0.1`. The host's
`/etc/network/interfaces` simultaneously declared a static IPv6 address for
`ens3`, while `/etc/sysctl.conf` explicitly disabled IPv6 with
`net.ipv6.conf.all.disable_ipv6=1`,
`net.ipv6.conf.default.disable_ipv6=1`, and
`net.ipv6.conf.lo.disable_ipv6=1`. During boot, the IPv6 stanza therefore
failed; a later retry then encountered the IPv4 address that had already been
assigned.

The repair preserved the working IPv4 configuration, backed up
`/etc/network/interfaces`, removed only the obsolete `iface ens3 inet6
static` stanza, applied the intended IPv6-disabled sysctl policy, and reset
the stale failed-unit state. `systemctl --failed` then reported zero failed
units. The same cleanup also found a harmless duplicate
`vm.swappiness = 10` entry in `/etc/sysctl.conf`; it was reduced to one
entry without changing the effective value.

**Rules:**
- Discovery must compare declared interface configuration with effective
  sysctl IPv6 policy before treating a network-service failure as a real loss
  of connectivity.
- A host configured as IPv4-only must not retain an active static IPv6 stanza
  for the same interface.
- After package updates/reboot, validate both effective connectivity and
  `systemctl --failed`; a working SSH session does not prove that the boot
  network transaction completed cleanly.
- Repeated sysctl keys are configuration drift even when values are identical;
  managed configuration should keep one authoritative value.

### Follow-up: the AWG 2.0 outage was caused by whole-file sysctl reapplication, not proven to be IPv6 itself

Later on 2026-09-29, after the IPv6 cleanup, the Docker-based AWG 2.0 path on
`hungry-boyd` stopped accepting/forwarding client traffic while an AWG 3.1
inbound hosted directly by 3X-UI continued to work. A full VPS reboot restored
the Docker AWG 2.0 path without any further configuration change.

The important additional evidence is that the operator had run
`sysctl -p /etc/sysctl.conf` to apply the IPv6-disable settings. That command
also reapplied unrelated IPv4 tuning from the same file, including:

```text
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

This conflicts with the established `amnezia-mihomo-gateway` runtime contract:
its installer explicitly requires `rp_filter=0` for the asymmetric
Docker -> Mihomo/gVisor path, writes `all/default.rp_filter=0`, and its routing
service also forces every live per-interface `rp_filter` to zero. The reboot
therefore plausibly repaired the outage by re-running that routing service and
restoring `rp_filter=0`.

This is strong causal evidence, but not a packet-capture proof because the
broken runtime state was not inspected before reboot.

**Additional rule:** when applying one sysctl change on a production gateway,
do not use `sysctl -p` on a mixed-purpose monolithic file unless every setting
in that file has been revalidated against the live gateway contract. Apply the
specific key(s), or use an owned fragment, then verify critical routing sysctls
such as `rp_filter` before and after the change.


**Current status after recovery (2026-09-29):** after a full VPS reboot the
Docker-based AWG 2.0 path recovered and no active incident remained. No
immediate repair was required while the service was healthy. The remaining
risk is persistent configuration drift: `/etc/sysctl.conf` still contains
`net.ipv4.conf.all.rp_filter = 1` and
`net.ipv4.conf.default.rp_filter = 1`, while the gateway integration requires
`rp_filter=0`. Until that persistent conflict is reconciled, avoid running
`sysctl -p /etc/sysctl.conf` on this host. At the next maintenance window,
verify live `rp_filter` on `all`, `default`, the external interface,
`docker0` and `amn0`, then reconcile the persistent setting so a future
whole-file sysctl reload cannot silently break the Docker AWG path again.

## 27. Current UI defaults do not describe persisted Xray/WireGuard state

A four-VPS TUIC investigation on 2026-09-30 found an old 3X-UI WARP outbound
persisted with `noKernelTun: false`, even though current 3X-UI code creates new
WARP outbounds with userspace TUN (`noKernelTun: true`). Xray therefore created
`wg0`, installed IPv6 policy routing in table 10230 and re-enabled host IPv6
when the WARP config contained an IPv6 address. Deleting the WARP account in
the modal was not sufficient until the staged outbound removal was actually
saved to the Xray template; before that save, the generated config still
contained `tag=warp` and Xray logged `Using kernel TUN`.

A process/fd ownership check proved that `wg0` belonged to Xray under
`x-ui.service`, not Mihomo or the AWG inbound. The exact upstream Xray code also
confirmed the sysctl and route/rule side effects. See
`docs/tuic-warp-ipv6-incident-2026-09-30.md` for the evidence and source links.

**Rule:** for external applications, discover effective generated
configuration and live kernel objects. Never infer runtime behaviour from the
current UI default or from the fact that an account/object was deleted in one
screen. Persisted legacy state can survive upgrades and keep using an older
data path.

## 28. Share-link parameters are version-specific semantics, not native-config aliases

The same incident exposed a second independent TUIC failure. Mihomo 1.19.31's
TUIC `tuic://` converter intentionally removes/ignores the `allow_insecure`
field; it does not translate that query parameter to the native TUIC option
`skip-cert-verify`. Self-signed SE2 and Moscow TUIC nodes therefore failed TLS
even though their share links appeared to request insecure certificate
handling. SE2 logged a TLS cryptographic handshake failure before TUIC
authentication; its certificate/key pair, SAN, validity and serverAuth purpose
were all valid.

Converting the provider to native Mihomo YAML and explicitly setting
`skip-cert-verify: true` for the self-signed nodes made SE2 and Moscow work.

**Rule:** subscription/import formats are parsers with their own versioned
semantics. Validate the effective imported proxy object against the exact
installed Mihomo version. Do not assume a share-link field is equivalent to a
similarly named native YAML field. Keep a provider payload in one format
(URI-lines or YAML `proxies:`), not a mixture.

## 29. IPv6 readiness is per-interface and end-to-end

`Saymer3` demonstrated that a host can look dual-stack while IPv6 Internet is
actually a black hole. It simultaneously had
`net.ipv6.conf.all.disable_ipv6=1`, `default.disable_ipv6=1`, but
`ens3.disable_ipv6=0`; `ens3` held two global IPv6 addresses and a default IPv6
route. Direct tests then showed IPv4 Google connectivity 5/5 while IPv6 was
0/5, each failure timing out at about four seconds.

TUIC had already authenticated successfully and logged `[connect]
google.com:443`, so the broken address family manifested as intermittent
post-auth application failure: some checks returned a normal delay while
others stalled. After the operator set only
`net.ipv6.conf.ens3.disable_ipv6=1`, IPv6 failed fast and ten consecutive
Mihomo delay checks through the Moscow TUIC node succeeded. The setting was
recorded in an operator-managed narrow sysctl fragment for reboot persistence;
post-reboot validation is still required.

The provider-side reason for the broken advertised IPv6 path was not proven.
Only the host-side symptom and mitigation were proven.

**Rule:** IPv6 production validation must inspect per-interface effective
sysctls, addresses and routes and must perform independent real `-4`/`-6`
connectivity tests. Neither a global sysctl value nor the presence of an IPv6
address/default route proves usable IPv6. For intermittent domain-based
failures, test address families separately before changing the application.

## 30. Admission control and log control are separate policies

A live maintenance session on `Saymer` on 2026-10-05 found a 1.36 GiB rotated
`syslog` on a roughly 9 GiB root filesystem. Telemt was already running with
`--silent`; the dominant noise was WARN-level admission/handshake activity,
including users hitting intentional per-user connection limits. Raising a
shared/public user's limit would have reduced the warnings only by granting
that credential more of a multi-service VPS.

The successful repair kept the admission limits unchanged and instead applied
a narrow Rust log filter to the known noisy Telemt modules while preserving
global WARN visibility. Measured syslog growth afterwards was only 9,092 bytes
in five minutes. Storage was then bounded separately: `/var/log/syslog` gained
a daily `maxsize 50M` policy with seven rotations, while the systemd logrotate
timer was overridden from daily evaluation to hourly evaluation. The numeric
threshold is host-profile evidence, not a universal constant.

The same session also showed why maintenance diagnostics need output and secret
budgets: an unfiltered `mita describe config` can print thousands of lines for
a large port range, while Telemt startup journals can contain complete proxy
links with credentials.

**Rules:**
- Do not raise a valid resource/admission limit merely to silence expected
  rejection logs.
- Fix or selectively rate/filter a noisy producer first, then put a separate
  size/retention/cadence budget around log storage.
- A logrotate `maxsize` rule is only as responsive as the timer that evaluates
  it; discover both policy and cadence.
- Keep diagnostic output bounded and treat service journals as potentially
  secret-bearing before storing or publishing them.
- Cleanup after maintenance is evidence-based: inactive/disabled legacy units,
  package `rc` residue and regenerable caches may be removable; large active
  Docker/service/project data is not garbage merely because it consumes space.

See `docs/small-vps-maintenance-runbook.md` for the full observed workflow and
validation sequence.

## 31. Fleet maintenance policy must be evidence-driven per host

A Debian 12 maintenance session on `Saymer2` on 2026-10-05 provided a useful
counterexample to copying fixes from one VPS to another. `snapd.service` and
`snapd.socket` were masked, just as on the earlier Ubuntu `hungry-boyd` host,
but `snapd` was not installed, no snap-backed Livepatch consumer existed and
there was no restart loop. The same visible unit state therefore did not
represent the same defect.

Telemt also needed a different filter. On this host the proven repetitive WARN
producers were only `telemt::proxy::middle_relay::idle::read` and
`telemt::maestro::listeners::accept`. Filtering those two modules while keeping
other WARN classes visible reduced measured syslog growth to 725 bytes in five
minutes. The broader filters used on other VPS hosts were deliberately not
copied.

The same session updated Docker 29.8.1 -> 29.8.2 only after discovering the
active AmneziaWG container and its `restart=always` policy; post-upgrade checks
confirmed the container returned to `running`. Mita 3.36.0 -> 3.38.0 was backed
up using the files actually present on this Debian host (`server.json` and
`server.conf.pb`), not filenames assumed from Ubuntu.

**Rules:**
- Treat identical-looking system state as evidence, not diagnosis; prove the
  dependency/consumer relationship before repairing a masked or inactive unit.
- Derive service log filters from measured producers on the current host and
  keep the filter as narrow as the evidence allows.
- Before upgrading a container runtime, discover active consumers and restart
  policy; afterwards validate the real containers, not only the daemon.
- Discover application state-file layout before backup/upgrade; filenames may
  vary across distro/install history.
- Preserve one known-good fallback kernel on small production VPS hosts when
  disk pressure does not justify removing the recovery option.

See `docs/live-maintenance-saymer2-2026-10-05.md` for the full Debian evidence.

## 32. Application-managed Mihomo updates can preserve PID while invalidating dependent routing

During the 2026-10-05 `Saymer3` maintenance session the operator manually
started a Mihomo 1.19.31 -> 1.19.32 update from MetaCubeXD. The journal showed
Mihomo shutting down and immediately reinitializing at 15:34:46, but systemd
kept the same `MainPID=750`, the old service start timestamp and
`NRestarts=0`. The on-disk binary and `/proc/750/exe` then matched the new
1.19.32 image, and the configuration test remained successful.

About 38 seconds later, the semantic WARP routing watchdog reported that it had
successfully restored the routing contract. Earlier and later checks were
clean, and a forced final watchdog check performed no repair. This is strong
operational evidence that an application-managed Mihomo update/re-exec can
recreate or reinitialize `tun-mihomo` and leave dependent host routing needing
re-assertion even though systemd never records a service restart. The exact
failed routing predicate was not logged, so the evidence does not identify
which individual rule/route/firewall object disappeared.

**Rules:**
- Do not use PID continuity, service start timestamp or `NRestarts=0` as proof
  that a network daemon's runtime objects remained unchanged across an
  application-managed update.
- Treat Mihomo TUN lifecycle as a dependency boundary: after update/re-exec,
  validate the TUN, dependent policy rules/routes and owned firewall/routing
  state.
- Polling watchdogs should log the exact failed predicate before repair; where
  possible, add immediate post-update/post-reinit validation so correctness
  does not depend solely on the polling interval.

See `docs/live-maintenance-saymer3-2026-10-05.md` for the full evidence.
