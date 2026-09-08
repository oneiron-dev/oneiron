# Wave-6 module-split map (2026-08-26)

Machine-readable old->new map for the fifteen wave-6 well splits merged to `main` at
`ce47e61e` (15 move-only commits, one per module, PRs #746-#760). Each former monolith
`X.rs` became a directory module `X/` with `mod.rs` as the re-export seam; the `pub mod X;`
line in `lib.rs` and every `crate::X::*` import path are unchanged. `tests.rs` children were
either pre-existing siblings or extracted in the split; either way the module's tests now
live at `X/tests.rs`. Use this map to re-anchor tickets, docs, and tooling that pin the old
paths.

The Children column is regenerated from the tree (`ls` per module directory) and was last
refreshed on 2026-09-08; it lists every child today, not only the ones the split created. A
trailing `/` marks a nested directory module. `consent/`, `outbound/`, `gate/` and
`dreamer_consolidation/` now carry a `tests/` directory alongside `tests.rs`.

| Old path | New module directory | Children |
|---|---|---|
| `crates/oneiron/src/session_overlay.rs` | `crates/oneiron/src/session_overlay/` | `mod.rs`, `journal.rs`, `keyspace.rs`, `overlay.rs`, `route.rs`, `short_id.rs`, `snapshot.rs`, `tests.rs` |
| `crates/oneiron/src/repo_mutation.rs` | `crates/oneiron/src/repo_mutation/` | `mod.rs`, `conflict.rs`, `conflict_value.rs`, `git.rs`, `oplog.rs`, `queue.rs`, `snapshot.rs`, `support.rs`, `tests.rs`, `trailer.rs`, `types.rs`, `worktree.rs` |
| `crates/oneiron/src/dreamer_consolidation.rs` | `crates/oneiron/src/dreamer_consolidation/` | `mod.rs`, `conflict.rs`, `executor.rs`, `extracted_people.rs`, `gap.rs`, `partition.rs`, `provenance.rs`, `support.rs`, `tests/`, `tests.rs`, `watermark/`, `watermark.rs` |
| `crates/oneiron/src/connector_key.rs` | `crates/oneiron/src/connector_key/` | `mod.rs`, `accounting.rs`, `charter.rs`, `codec.rs`, `lifecycle.rs`, `meter.rs`, `record.rs`, `tests.rs`, `txn.rs` |
| `crates/oneiron/src/code_run.rs` | `crates/oneiron/src/code_run/` | `mod.rs`, `codec.rs`, `consent.rs`, `dispatcher.rs`, `payload.rs`, `replay.rs`, `storage.rs`, `support.rs`, `tests.rs`, `types.rs`, `vault_read/`, `vault_read.rs` |
| `crates/oneiron/src/consent.rs` | `crates/oneiron/src/consent/` | `mod.rs`, `adapters.rs`, `bound.rs`, `codec.rs`, `doors.rs`, `effect.rs`, `grant.rs`, `registry.rs`, `support.rs`, `tests/`, `tests.rs` |
| `crates/oneiron/src/receipt.rs` | `crates/oneiron/src/receipt/` | `mod.rs`, `brief_share.rs`, `family.rs`, `field_set.rs`, `grant.rs`, `identity_kind.rs`, `kernel.rs`, `ledgers.rs`, `projection.rs`, `send_receipt_txn.rs`, `session.rs`, `tests.rs` |
| `crates/oneiron/src/deletion.rs` | `crates/oneiron/src/deletion/` | `mod.rs`, `delete.rs`, `erase.rs`, `gate.rs`, `publish.rs`, `receipt.rs`, `rendezvous.rs`, `sweep_queue.rs`, `tests.rs`, `timeline.rs`, `tombstone.rs` |
| `crates/oneiron/src/outbound.rs` | `crates/oneiron/src/outbound/` | `mod.rs`, `capability.rs`, `connector_task.rs`, `dispatch_attempt_id.rs`, `dispatch_pipeline/`, `dispatch_pipeline.rs`, `dispatch_types.rs`, `executor.rs`, `intent.rs`, `manifests.rs`, `receipt_fields.rs`, `retry_audit.rs`, `tests/`, `tests.rs`, `window_door.rs` |
| `crates/oneiron/src/booking/anti_abuse.rs` | `crates/oneiron/src/booking/anti_abuse/` | `mod.rs`, `amendment.rs`, `evaluation.rs`, `quarantine.rs`, `rate.rs`, `rules.rs`, `scope_tests.rs`, `storage.rs`, `tests.rs` |
| `crates/oneiron/src/saved_query.rs` | `crates/oneiron/src/saved_query/` | `mod.rs`, `definition.rs`, `evaluator.rs`, `evidence.rs`, `filter.rs`, `lifecycle.rs`, `membership.rs`, `pack_drift.rs`, `storage.rs`, `support.rs`, `tests.rs` |
| `crates/oneiron/src/dreamer_runner.rs` | `crates/oneiron/src/dreamer_runner/` | `mod.rs`, `admission.rs`, `claim_authoring.rs`, `codec.rs`, `constants.rs`, `milestone.rs`, `progress.rs`, `store.rs`, `tests.rs`, `types.rs` |
| `crates/oneiron/src/pipeline.rs` | `crates/oneiron/src/pipeline/` | `mod.rs`, `authority.rs`, `authority_corpus_tests.rs`, `authority_tests.rs`, `blend.rs`, `budget.rs`, `builder.rs`, `channels.rs`, `corpus_coping_tests.rs`, `corpus_filter.rs`, `corpus_gate_tests.rs`, `corpus_tests.rs`, `decay_tests.rs`, `execution.rs`, `execution_binding.rs`, `filters.rs`, `scoped_channels.rs`, `support.rs`, `tests.rs`, `trace.rs`, `types.rs`, `world_authority.rs`, `world_authority_tests.rs` |
| `crates/oneiron/src/skill_hub.rs` | `crates/oneiron/src/skill_hub/` | `mod.rs`, `adapter.rs`, `doors.rs`, `index.rs`, `package.rs`, `record.rs`, `support.rs`, `tests.rs`, `verdict.rs` |
| `crates/oneiron/src/gate.rs` | `crates/oneiron/src/gate/` | `mod.rs`, `breaker.rs`, `bundle.rs`, `ceiling.rs`, `confirm.rs`, `constants.rs`, `decision.rs`, `decode.rs`, `default_manifest.rs`, `definition_ceiling.rs`, `doors/`, `doors.rs`, `dreamer_precommit.rs`, `effect.rs`, `grants.rs`, `input.rs`, `repair.rs`, `repair_tests.rs`, `resolution/`, `resolution.rs`, `retrieval_filter/`, `retrieval_filter.rs`, `share.rs`, `tests/`, `tests.rs`, `witness_message.rs` |
