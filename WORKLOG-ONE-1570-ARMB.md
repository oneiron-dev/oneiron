# WORKLOG — ONE-1570 Arm B settle (retrieval-telemetry registration door)

branch · `ONE-1570-ARMB` off `origin/main` 4f5360daa (post-fence tree; 1731 #640 merged)
worktree · `/Volumes/Cinema/w5-lt/retrieval-api`
role · Opus IMPL · serialized behind RETRIEVAL-API (free)
source contract · `/Users/olety/.claude-wave5/blueprints/STALE/ONE-1570.md` §"Resolved retrieval-telemetry Arm B"

---

## ARM_B_HOST

```
ARM_B_HOST: /Users/olety/Desktop/code/oneiron/crates/oneiron/src/facade.rs
ARM_B_ENTRY: MemoryFacade::recall_in_session  (named public production entry point; sibling of the
             existing public MemoryFacade::witness_into_session, which is already the crate's only
             public production surface taking an explicit &OffRecordSession)
```

### Census record (first action, run BEFORE any edit)

Three candidate hosts were censused exactly as the contract names them.

**1. `oneiron-server` context-pack API handlers — REJECTED (no session surface).**
`crates/oneiron-server/src/api/context_pack.rs` + `api.rs` + `mcp.rs` carry zero off-record
concepts. The only `session_ref`-shaped token in the whole crate is
`context_pack.rs:342-344 voice_session_ref`, which the crate's own test at
`api/tests.rs:8597` documents as "the ILD-3 roster seam is accepted but inert" — a voice-roster
string, not an off-record session ref, never reaching `Vault::off_record_session`. Selecting this
host would require inventing an HTTP off-record session lifecycle (enter/flip/close over the wire)
across `api.rs`, the routers and `openapi.rs`. That is a new feature, not a settle, and lands far
outside the granted claims.

**2. `oneiron-napi` `lib.rs` session surfaces — REJECTED (no session surface).**
`rg 'off_record|OffRecord|session_ref' crates/oneiron-napi/src/` returns ZERO hits. Its
`lib.rs:620 context_pack` / `lib.rs:659 context_pack_scoped` build on `self.vault.context_pack()`
with no session concept at all. Same objection as (1), plus an N-API surface change.

**3. `facade.rs` — SELECTED.**
It is the only censused host that already owns a public production entry point taking an explicit
`&OffRecordSession`: `MemoryFacade::witness_into_session` (`facade.rs:1814`). It is simultaneously
the crate's public retrieval door: `MemoryFacade::recall` (`facade.rs:2842`) is the named public
production entry point that drives `vault.context_pack()` — precisely the telemetry seam the
settle contract governs. The settle therefore adds ONE sibling in an existing established pattern
(`*_into_session`) rather than inventing a host.

The `#[cfg(feature = ...)]` question does not arise: no arm of this work is sync-gated.

### Packet consequence

`crates/oneiron/src/facade.rs` enters the packet as the census-named host file, per the relay's
"(census-named host file(s) ONLY after the census lands them in the worklog)" and the artifact's
granted-claim row "the production host that supplies the off-record `session_ref`". No other
facade region is touched; the footprint is one added method plus its imports.

---

## POST-P6 SUBSTRATE RE-GROUNDING (deviation from the fence-era contract's literal wording)

The contract was authored against the fence-era tree. ONE-1731 (#640) deleted
`note_off_record_context_receipt` and the `offrecord_receipt:v0:` marker family. Re-grounded, the
settle semantics are preserved verbatim but ride the surviving substrate:

| Contract wording (fence era) | Post-P6 substrate (this tree) |
|---|---|
| register through `note_off_record_context_receipt` | stage the retrieval-run row into the session overlay `VaultMeta` keyspace via `SessionStoreView::record_retrieval_run_in_txn` |
| the session-local close set | the overlay rows under `store::RETRIEVAL_RUN_KEY_PREFIX` (`retr_run:v0:`), which `close_off_record_session`'s PRE-CLOSE CENSUS counts as `context_receipts_deleted` (`lifecycle.rs:1380-1390`) |
| close removes the run + `offrecord_receipt:v0:` marker | close drops the overlay; the rows evaporate with the transcript |
| exactly ONE additive optional session-**ref** channel | `PipelineBuilder::in_session(&SessionStoreView)` (`pipeline.rs:595`) — strictly stronger than a bare ref: it cannot be forged from ambient state, the caller must hold a live session handle |

The relay's framing — "session-local, close-consumed, never a durable `vault_meta` marker" — holds
exactly under this mapping. The overlay VaultMeta keyspace is session-local and evaporates at
close; nothing durable is written to base.

Note the module docs (`off_record/lifecycle.rs:47-56`) are precise on this and distinguish TWO
substrates: retrieval-run context receipts ride the **overlay VaultMeta keyspace**, while
emit-adjacent dispatch receipts ride `SessionLocalReceiptLog` (`Vault::off_record_receipt_log`).
The relay brief compressed these two into one. Arm B is the RETRIEVAL half, so it rides the overlay
keyspace, not the emit receipt log. Recorded as a deviation for the board.

---

## STATE OF THE TREE AT DISPATCH (what P6 already landed vs. the Arm B gap)

Already present post-P6 (must NOT be rebuilt):
- `store.rs:1412 SessionStoreView` telemetry seam — `record_retrieval_run_in_txn`,
  `record_context_pack_provisional_retrieval_run_in_txn`,
  `finalize_context_pack_retrieval_run_in_txn`, `delete_retrieval_run_in_txn`,
  `retrieval_runs_in_txn`. Whole-cloth, `#[allow(dead_code)]` pending its callers.
- `pipeline.rs:548 session_view` field + `pipeline.rs:595 in_session()` builder
  (`#[allow(dead_code)]` — zero production callers).
- `pipeline.rs:1944-1972` registration site already routes on `self.session_view`.
- `off_record/lifecycle.rs:656 search_text_routed` already registers the BM25 path into the room.
- `close_off_record_session` already censuses the overlay run rows.

The Arm B gap (this lane):
1. **No production caller reaches `in_session`.** The context-pack/pipeline door is unreachable
   from any host, so a production off-record retrieval still lands its run in BASE.
2. **Context-pack finalize is base-only — the exactly-once break.** `ContextPackRun.store` and
   `UnfinalizedContextPack.store` are `&Store`; `finalize_context_pack_telemetry` and
   `discard_failed_context_pack_telemetry` (`context_pack.rs:1376`, `:1404`) call
   `store.finalize_context_pack_retrieval_run` / `store.delete_retrieval_run` on BASE. A
   session-routed provisional run stages into the OVERLAY, so finalize would target a base row that
   does not exist — the provisional overlay row would survive un-finalized while finalize errors,
   violating "registers the final surviving run EXACTLY ONCE".
3. **`pipeline.rs` log-and-continue on the session arm.** `pipeline.rs:1971-1979` swallows a failed
   run write with `tracing::warn!` and returns the retrieval as successful. On the session arm that
   is exactly the forbidden "log-and-continue": a successful off-record retrieval would return with
   its run absent from the close set.

---

## PROGRESS LOG

- [x] Read the ratified Arm B settle contract (artifact lines 175-200 + granted claims + settle bar).
- [x] Host census over `oneiron-server`, `oneiron-napi`, `facade.rs`; `ARM_B_HOST` recorded above,
      in the artifact's `ARM_B_HOST:` field, and in `STALE/CLAIMS.md` — all three BEFORE any edit.
- [ ] Implementation (see plan below).
- [ ] Final gate: `cargo test -p oneiron --all-features` + clippy on touched crates.

## DEVIATIONS / PACKET_AMEND CANDIDATES

See the DEVIATIONS section at the end of this file — nothing is silently absorbed.
