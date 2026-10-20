# Rollback staging procedure — incident I-1 prevention (ZAI-90E)

Mandatory operator procedure for staging and running the Test rollback
script. It exists because ZAI-90D incident I-1 ran the historical live
pre-#15 script by accident: it was invoked (with `--check`, which it
ignored) before the corrected script had been transferred. Structural
rules below make that mistake impossible to repeat.

1. **Stage under a NEW, explicitly versioned filename.** Never overwrite
   the historical live copy, and never execute any file under its old
   name. Example target: `/root/zai85/rollback-zai85.sh.zai90e-1`.
2. **Transfer first, verify second, execute last.** The corrected script
   supports `--check`; the historical one does not. Therefore nothing on
   the host may be invoked until the transferred artifact is proven to
   be the corrected version.
3. **Cryptographic verification.** Compare the full SHA256 of the
   transferred file with the repository artifact hash recorded in the
   acceptance PR (CI-green commit). Record both values in the evidence.
4. **Static identity inspection before any execution:**
   - `grep -n "ROLLBACK_VERSION=" <staged>` must show the expected
     version string (e.g. `zai90e-1`);
   - `grep -n -- "--check" <staged>` must show supported argument
     handling;
   - `sh -n <staged>` must pass (syntax).
   A script that fails any of these is not the corrected version — stop.
5. **Read-only preflight by full path only:**
   `<staged-full-path> --check`. Snapshot service/routing/firewall state
   (or counters) before and after; the preflight must produce **zero**
   mutations. Its PASS message includes the version marker.
6. **Execution is a separate, owner-authorized step:**
   `<staged-full-path>` with no arguments, exactly once. Never run any
   other rollback variant "to compare".
7. **Unit file permissions:** deploy `.service` files with
   `install -m 644` (systemd warns about executable unit files; C-4).
8. The original historical script stays preserved on disk under its
   renamed `.pre-<task>` name without ever being invoked.
