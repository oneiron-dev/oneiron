# ONE-1884 — follow-up adversarial audit packet

[ONE-1884](https://linear.app/oneiron/issue/ONE-1884/audit-follow-up-round-under-covered-surfaces) is a **scope ticket**, not a defect report. Baseline: `e17eeb2b2824c8e0e0ffd0e23ea4fd013c5a3f0d` (`origin/main` at packet assembly). The July 22, 2026 completeness critique described *then*-missing coverage; it is not evidence that any alleged failure persists. Refresh the code/canon/PR state before executing a packet after this baseline. In particular, do not treat open PRs as landed.

## Contract and method

- Canon governs the observable invariant; `CLAUDE.md` keeps prompt/persona content in consumer-supplied configuration. The engine's sync, erasure, identity and read-door contracts are cited beside each probe. Where canon does not prescribe a testing order, use one public caller, one hostile variant and one negative control per question before widening the search.
- Probe through the *real* entry point and its callers: vault API, sync export/import, HTTP request or Node host. Do not prove a private helper in isolation and call the boundary safe. Run featureless and all-feature tiers when a base-mode module is changed; sync-only tests use `sync,test-hooks`.
- Record a **finding** only after a reproducible, observable failure on an exact revision, with the command, fixture, expected and actual outcome, and a counterexample that rules out setup error. Keep hypotheses, known fixes and unrun questions out of the findings ledger. File each confirmed defect as its own ticket with a small regression that fails before its fix; do not mix the fix into this scope packet.
- The packet is bounded to the eight July surfaces below. Each surface has a stopping rule. A green test of one path does not certify the entire surface. Changes to an in-flight PR require re-baselining that path rather than declaring it clean.

| Packet | July surface and current scope | State at this baseline |
| --- | --- | --- |
| [Consumer and inbound](consumer-inbound.md) | 1. Generated lenses/context packs/prompt packages; 2. inbound consent and identity | Lenses now have generated atoms, mediated read/write, and persisted intent (#1023); context projection/pack and prompt include tests exist. Inbound has a renderer-neutral inbox lens and provider admission, not the July empty surface. #1027/#1035 remain separate in-flight lens changes. Probe final caller boundaries, not an invented mailbox. |
| [Sync and erasure](sync-erasure.md) | 3. sync rematerialization, quarantine, checkpoint/intent; 4. sidecar erasure; 8. topology-delete verdict | Window replay has byte/marker safeguards, but restore of device-local Pending intent and active sidecar erasure remain precise questions. Received DAG Parent-edge failure was already probed in September (#985 pending). Applied participant deletion is separately owned by ONE-1862; use the split/merge scratch probe for disposition. |
| [Claims and clocks](claims-clocks.md) | 5. claims-read enforcement heads; 6. caller-clock audit | The comm descriptors are pure data and type-132 is still read; ONE-1752 owns the one-wave cutover. Prior grant/authority clock review was partial; checkout and symbol leases remain clock probe candidates. #976 is pending for a different known floor gap. |
| [Host boundaries](host-boundaries.md) | 7. server and napi auth, vault routing and single-writer reentrancy | The September remote/MCP audit and merged #984 are *partial* coverage, not an HTTP or real Node-host security verdict. |

[Findings ledger](findings.md) is separate from this list of unverified targets. Every packet's `A1`–`D2` identifiers are proposed probes, not finding IDs.

### Execution ownership and limits

One independent investigator per packet; run a single Cargo writer per target directory, and give each native run a timeout. Each investigator records a before/after source trace (entry → caller → store/output), one executed negative control and the result in the ledger. Stop after the listed probes, or pause on a confirmed finding that needs its own fix ticket; mark any remaining cases unprobed, then resume them only with a new bounded run. Do not turn the packet into an engine-wide review. Never widen a destructive test to a real user vault. Coordinate against #982/#1002 (plumbing), #1005 (authority cache), #976 (recall scope), and the DAG/storage/retrieval audit-fix PRs before editing overlapping code.
