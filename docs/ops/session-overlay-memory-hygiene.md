# Session overlay process-memory hygiene (ONE-1944)

This is defense in depth, not a promise that private data never reaches physical media.
ARCH-0052 D1 defines “never touches disk” as **never enters vault storage, indexes,
sync state or exports**. The overlay remains RAM-only and budget-fenced; there is no spill.

- Overlay single/duplicate rows (keys and values), staged mutations, typed journal
  `Put`/`Text`/`Vector`/`Phonetic` payloads, and promote-plan copies wipe owned
  allocations on drop with `zeroize`. The in-room alias copy and short-id lookup
  scratch buffers also wipe on drop. Emit-adjacent off-record receipt logs wipe
  their string fields at close or if abandoned. Close's live-row census counts
  through references instead of copying private row bodies into a temporary plan.
- Each COW keyspace and each journal entry wipes **its own** buffers at its last
  drop. Close first drains generation leases. It does not overwrite an Arc held
  by another snapshot, nor clear the closed registry entry before its taint
  membership is unpublished. A caller-owned read result or promote outcome has
  its own lifetime and is not scrubbed by closing the overlay.
- `zeroize` limits residual data in owned allocations; it cannot guarantee that
  compiler temporaries, earlier allocator copies, base-vault data, caller-owned
  clones, or preexisting swap/dump images are wiped. Hostile process inspection
  and live memory access remain outside this guarantee.

## Dumps and swap by host platform

The engine does **not** change process-wide dump state: a library sharing its
process with other applications cannot disable their crash diagnostics without
host consent. Overlay maps use Rust's normal allocator, not dedicated page-aligned
mappings. `madvise(MADV_DONTDUMP)` on these allocations would also mark unrelated
objects on a shared allocator page and would miss later COW allocations; it is
**not supported** for overlay pages on Linux or other targets. `mlock` likewise
cannot safely cover shared allocator pages and is not a swap guarantee here.

| Host | Supported host policy (outside the engine) | Engine page-level policy |
| --- | --- | --- |
| Linux | A dedicated host process can opt out of core dumps with `prctl(PR_SET_DUMPABLE, 0)` and/or `setrlimit(RLIMIT_CORE, 0)` before opening sessions. Control swap at the host/container level. | Unsupported; no `MADV_DONTDUMP` on shared allocator pages. |
| macOS / BSD | A dedicated host can set `RLIMIT_CORE=0` and configure OS crash-report and swap policy. | Unsupported; no page-specific guarantee. |
| Windows | A dedicated host can control WER/local crash dumps, minidump generation and pagefile policy. | Unsupported; no page-specific guarantee. |
| Other targets | Host-specific dump and swap policy is required. | Unsupported. |

These host actions reduce accidental dump exposure, but cannot retract earlier
dumps or swap images. An embedding host needing stronger isolation must run the
session in a separately governed process; the engine cannot impose that policy
on every consumer.
