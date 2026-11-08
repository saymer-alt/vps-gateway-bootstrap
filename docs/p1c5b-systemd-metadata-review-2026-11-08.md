# P1-C5B — read-only fail2ban systemd definition metadata (synthetic only)

Date: 2026-11-08. Follows merged P1-C5A [#80](https://github.com/saymer-alt/vps-gateway-bootstrap/pull/80). Tracks [Stage-3 #79](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/79) and [Core MVP #56](https://github.com/saymer-alt/vps-gateway-bootstrap/issues/56).

## One bounded question

Before the operator signs a service adoption ceremony, which definition *metadata* does systemd currently report for the **exact** `fail2ban.service` unit, and does that metadata stay the same between observations?

`internal/serviceunitmeta.Inspect` uses a caller-injected runner and emits **one** fixed query: `systemctl --system show --all fail2ban.service` with the exact seven `--property=` selectors for `Id`, `LoadState`, `FragmentPath`, `DropInPaths`, `SourcePath`, `Transient`, and `UnitFileState`. `--all` requests empty properties so their absence can be distinguished from an empty value. There is no production runner or new external command dispatch in this PR. The existing `internal/serviceobs` observes runtime invocation identity, a DIFFERENT domain; it is not extended or conflated with definition provenance.

Only well-formed complete, bounded, unique and canonical fields are reportable. A not-found/masked/unloaded or aliased ID never appears `REVIEWABLE_METADATA_ONLY`. Missing or ambiguous fields, unknown keys, contradictory duplicates, malformed UTF-8, oversized output, invalid paths and runner failures refuse. Generated/transient, linked/runtime install, non-empty drop-ins or source paths are `NEEDS_REVIEW`. Empty `DropInPaths` is ONLY what the manager reported, not proof that no other configuration or manager exists. A structurally reviewable result is NOT an ownership verdict.

`Compare` reports `CHANGED`, `UNCHANGED_METADATA_ONLY`, or `UNCOMPARABLE`. It never reports `TRUSTED`, `OWNED`, `AUTHORIZED` or `READY`.

## Important unclosed trust gap

These manager **strings** are NOT a cryptographic identity of the backing files or of their live loaded contents. The path `/lib/systemd/system/fail2ban.service` may be a symlink; metadata may be stale if the unit file changed without `daemon-reload`, and no file hashes, inode/symlink resolution, drop-in content, package manager ownership, process executable or agent-independent collector are proven here. A foreign manager could still own that service. A malicious injected runner can emit plausible properties: synthetic output is not a trusted OS provenance channel.

The systemd documentation explicitly says `systemctl show` is machine-parseable and that `systemctl cat` reads backing files on disk which may differ from the manager's loaded state; this slice therefore does **not** claim content attestation. See [systemctl manual](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) and [org.freedesktop.systemd1 interface](https://man7.org/linux/man-pages/man5/org.freedesktop.systemd1.5.html).

The previously merged `internal/serviceadoption` validates a purpose-separated adoption **intent** only. Combining a signed unit-name statement with these fields would STILL NOT make independently authorized adoption: that requires a separately reviewed signed, precisely observed unit identity, trusted live source and clock, off-box operator ceremony, durable operator-authorized adoption record, and fresh admission under lock. The full `brokerplan.Candidate.Snapshot().Ready=false` remains unchanged.

## Tests / STOP

Synthetic runner tests pin one immutable read-only command shape and fail-closed behavior on not-found synthesized data, wrong unit, masked/unknown load states, missing/malformed properties, alternate/transient/source/drop-in configurations, invalid paths, command error/cancellation and metadata change. No production command, actual VPS, real systemd, service restart, signing key, journal or release is modified or inspected.

P1-C5B is **repository-only synthetic metadata classification**, NOT Stage-3 positive ownership proof, foreign-manager detection or live lab acceptance. A dedicated Linux lab with owner authorization and real unit content/loaded-state verification is required separately; no code here establishes a trusted executable broker. If metadata-based service adoption remains too complex, review a project-owned-file Core MVP instead of weakening denial checks.

No merging without separate owner GO.
