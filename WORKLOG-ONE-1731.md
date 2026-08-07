# WORKLOG — ONE-1731 [L1-SPINE S1-L3] fence-family deletion sweep + 1570 fold

Branch `ONE-1731`, cut from `origin/main` 47ac630 (1728 #578/#590 + 1730 #632 + 1729 #633 merged — THE JOIN satisfied).
Blueprint: `/Users/olety/.claude-wave5/blueprints/L1-STORAGE-SPINE/ONE-1731.md`, including owner ruling **R-20260807-06** (the ONE-1570 fold).

Final gate: `cargo test -p oneiron --all-features` — **3942 passed / 0 failed / 6 ignored**, plus every integration target green. `cargo clippy -p oneiron --all-features --all-targets` clean. `cargo fmt` applied.
(Impl tip measured 3938; the VERDICT-FIX leg in §10 restored 4 collaterally-deleted CONTRACT tests → 3942.)

Net: **40 files, +917 / −4213.**

---

## 1. What the sweep deleted

The fence was ONE mechanism expressed in ~12 places. All of it is gone, with **no durable substitute**.

**Durable state.** `offrecord_fence:v0:` key prefix, `off_record_fence_key`, `OFF_RECORD_CLOSED_FENCE_VALUE` (the sessionless closed-fence tombstone), `OFF_RECORD_MAX_FENCED_TURNS`, `OffRecordSessionRecord::fenced_turns`. No inherited-fence family existed on the rebased tree (searched: `offrecord_inherited_fence`, `off_record_visibility_hidden` — zero hits outside the oracle's own pin list).

**Probes and doors.** `off_record_fence_active`, `off_record_fences_present`, `off_record_orphaned_live_fence_session_ref`, `guard_off_record_entity_put`, `Vault::is_turn_off_record_fenced`, `Vault::tag_turn_off_record`, `Vault::scrub_tagged_turn_in_live_window`, `Vault::ensure_no_open_off_record_session`, `Store::delete_gate_decisions_for_missing_off_record_turn_in_txn`.

**Vault-open apparatus.** `OFF_RECORD_OPEN_LOCK_FILE`, `acquire_off_record_open_lock`, `downgrade_off_record_open_lock`, `Vault::_off_record_open_lock`, `sole_opener`, `sweep_orphaned_off_record_fences`, and the delete-at-open fallback plus its ordering commentary. ONE-1878 collapses to a residue check, as the blueprint predicted.

**Retrieval.** `pipeline.rs` lost `off_record_fences_present` from `PipelineFilterConfig` / `TemporalCandidateCollectionContext` / `TemporalIndexCollectionContext`, both `apply_off_record_fence` applications (pre-`blend_allowed_ids` and post-PPR-expansion), `contains_off_record_fence`, `truncate_vector_fence_replacements`, `next_vector_fence_search_limit`, `temporal_fence_scan_budget`, `apply_off_record_fence_with_cap`, the vector and text widening loops, all six per-candidate temporal probes, and both late per-candidate filters. `collect_temporal_index_rows` / `normalize_backward_boundary_bucket` / `collect_index_candidates` shed their now-unused `store`/`rtxn` plumbing. `bm25.rs` needed no edit — P4a had already left it fence-free (declared deviation from the blueprint's expectation, below).

**Readers.** `context_pack.rs` lost both `edge.target` probes (serialized edge lists + hop-1 neighbour walk).

**Sync.** `scrub_off_record_fenced_carriers`, `off_record_fenced_ids`, `scrub_outbox_for_off_record_fence_in_txn`, the `fenced_rejections` set + its post-pass scrub, the bridge incident-edge endpoint walk, the client-side scrub mirrors (`scrub_window_before_export` + 5 call sites), the server-side scrub mirror in `oneiron-server`, and `deletion.rs`'s scrub inside `resolve_window_snapshot_mode`. `scrub_fenced_entity_crdt_carriers` was RENAMED to `remove_entity_crdt_carriers` (kept: the ONE-1865 SECRET_CUSTODY seal is its other caller).

**Typed errors.** `OffRecordTurnNotFenced`, `OffRecordFencedTurnWriteRejected`, `OffRecordExportRefused` and their `ErrorKind` arms. The six preserved variants are untouched: `OffRecordSessionAlreadyExists`, `OffRecordSessionNotFound`, `OffRecordSessionClosing`, `OffRecordOverlayFull`, `OffRecordOverlayLeaseClosed`, `OffRecordTalkOnly` (plus P4a's `OffRecordWitnessDoorRejected`, P4b's `OffRecordGuestTurnRefRejected`, and `OffRecordTaintedBaseWrite`).

**Close.** No ARCH-0038 `PolicyDelete`, no close-delete accounting, no redaction cascade for session rows, no closed-fence retention. `OffRecordCloseOutcome` dropped `turns_missing`, `fence_rows_retained`, and `redaction_receipt_ids`; `turns_deleted` is now exactly the pre-close overlay transcript census.

## 2. What the sweep preserved (explicitly checked, not assumed)

- **P4a live-overlay taint preflight** — `check_decode_point_taint_guard` and `BaseWriteOrigin::exempts` are intact and still raise `OffRecordTaintedBaseWrite`.
- **`FloorWrites`** — egress gate decisions, REDACTION_AUDIT writes, P5 `promote`.
- **P4b policy rejections** — durable memory verbs, typed `GuestTurnRef` refusal.
- **Ordinary sync recovery** — `pm:` replay, `rm:`, `dt:` hard-delete markers, reverse rematerialization, quarantine for non-off-record protocol violations, the ONE-1865 custody seal, history-free-window pinning (now driven only by the custody scrub).
- **1924 `BlockedBy` arms and 1375 streak machinery** — untouched; no edit landed in `habit.rs`, `edge.rs`, or `src/tests.rs`, and the `apply_ops_with_gate_mode` hook points are byte-identical.
- **`base_leak_sweep_every_reader_family_sees_no_overlay_rows`** — active, unmodified.

## 3. The two egress doors (R-20260807-06 fold)

Both are born on live overlay membership. Each is ONE named function containing exactly ONE `OffRecordSessionRegistry::contains_entity` call, with no fence-key lookup, fences-present fast path, scrub, or second predicate around it.

- `crates/oneiron/src/sync/window.rs` → `window_packing_excludes_entity(vault, id)`. Called once from `replay_pending_mirrors` and once from `reverse_rematerialize`; the edge-target sets in both packing paths and in phase-2 backfill are DELETED (a base edge cannot name a live overlay member — the K4 guard refuses that write — so the filter was provably dead).
- `crates/oneiron/src/batch/export.rs` → `whole_vault_export_excludes_entity(vault, id)`. `ensure_no_open_off_record_session` is removed from all four vault-bound manifest entry points; export now **succeeds while a session is live**. The OF-222/ONE-1240 row enumerator does not exist and was NOT invented — the door carries the contract sentence for it.

Source audit of the egress functions this lane owns: 2 predicates, 2 doors, 0 duplicates.

## 4. `guard_off_record_entity_put` → `reject_overlay_member_base_write` (judgment call, declared)

The deleted door judged TWO things: live-overlay membership of the materialized id, and durable fence state. Only the second half was fence machinery; the first half is the P4a taint semantics the blueprint says to PRESERVE, and K4 deliberately does not judge the materialized id (it delegates). Deleting the whole door would have left a base put AT a live overlay id unjudged on the sync-replay path, which never enters `check_decode_point_taint_guard`.

So the live half moved into the K4 preflight family in `batch.rs` as `reject_overlay_member_base_write`, called from `apply_put` (the wider materialization chokepoint) and the gate preflight loop. The `replicated` parameter is gone — membership is refused for every origin except the granting promote. Error identity collapses to `OffRecordTaintedBaseWrite`, so `sync/quarantine.rs`'s remote-rejection list swaps one arm rather than gaining one.

## 5. Deviations, judgment calls, and PACKET_AMEND candidates

**PACKET_AMEND candidates** (all mechanically forced — the crate does not compile otherwise — or named in blueprint prose but absent from the Claims list):

| File | Why | Nature |
|---|---|---|
| `crates/oneiron/src/disclosure.rs` (+ `disclosure/tests.rs`) | Named in blueprint prose ("...raw-get, **disclosure**, and ScopedRead readers"), absent from Claims. Not claimed by any other lane in CLAIMS.md. | tier rule 1 repointed; 1 test deleted |
| `crates/oneiron/src/batch/export/tests.rs` | Sibling of the claimed `batch/export.rs` under the fold. | 1 test replaced; 4 unrelated CONTRACT import tests kept (see §10) |
| `crates/oneiron/src/edit_distance/reservoir.rs` (+ tests) | Consumed `off_record_fence_active`. | tripwire repointed; 4 tests rewritten |
| `crates/oneiron/src/skill_convert.rs` (+ tests) | Consumed `is_turn_off_record_fenced` + a deleted error variant. | `refuse_fenced` deleted; 1 test rewritten |
| `crates/oneiron/src/m8_forward_oracle.rs` | Consumed `tag_turn_off_record` + `is_turn_off_record_fenced`. | 1 ignored oracle deleted |
| `crates/oneiron/src/facade.rs` | Doc comment naming `tag_turn_off_record`. | comment only, zero logic |
| `crates/oneiron/src/sync/connection.rs`, `sync/server_state.rs` | Consumed the deleted client scrub / 1 scrub test. | 1 call site, 1 test |
| `crates/oneiron-server/src/handler.rs`, `server.rs`, `handler/tests.rs` | **`oneiron-server/**` is explicitly NOT claimed (L1-ENTITY).** Consumed `scrub_off_record_fenced_carriers`; without this edit the workspace does not build. | 2 scrub call sites + the `scrubbed_fenced_carrier` relay branch + `persist_sanitized_window` + 3 tests |

**Judgment calls that could reasonably have gone the other way — flagging for the screen:**

1. **`disclosure.rs` rule 1 repointed rather than deleted.** The blueprint prose lists disclosure among readers to sweep, but design §7 names live overlay membership as tier rule 1, and the P4a author's own comment reads "live overlay membership, with the legacy fence retained as a fail-closed backstop **until ONE-1731 removes fence symbols**" — i.e. P4a intended this lane to strip the durable half and keep the live half. I kept the live half (`contains_entity`) and deleted the backstop. Deleting rule 1 outright would reverse a documented design rule, which is ONE-1732 doc territory, not a deletion sweep's.
2. **Reservoir tripwire repointed rather than deleted.** Same shape: one predicate in, one predicate out, no durable substitute. Deleting it was defensible under "assert, build no taint machinery", but the tripwire is EXISTING machinery whose live half is the preserved taint semantics, and the behaviour has real test coverage. Declared rather than silently absorbed.
3. **`skill_convert::refuse_fenced` deleted outright.** Here the architecture genuinely is the replacement: `convert_messages_to_skill` holds a canonical `&Vault`, which cannot address an overlay row, so a selection naming a room member fails at `entity_type()` with `EntityNotFound` — in the same pre-refiner loop, before the refiner tier. The container-hop half died with it (a base `edges_in` walk cannot reach overlay children). Test rewritten to pin the new refusal.
4. **`bm25.rs` needed zero edits.** The blueprint expected "search overfetch/post-filter helpers" there; on the rebased tree those live in `pipeline.rs` (`scoped_text_channel_limit`, `truncate_widened_channel_results_to_scope`) and the fence-specific ones are deleted. No claim exercised.
5. **Forward-remat no longer scrubs the rejected CRDT carrier.** The blueprint deletes the carrier scrub, so a replicated op naming a live overlay member is quarantined (durable evidence) and the local apply refused, but the body stays in the peers' shared CRDT history. This is a real behaviour delta from the fence era and is asserted explicitly in `forward_remat_quarantines_overlay_member_rejection_and_continues`.
6. **`STORAGE_ABI_VERSION` untouched** (1732 owns the bump). `Cargo.toml`/`Cargo.lock` untouched — a `cargo fix` run briefly staged a regenerated `Cargo.lock`; caught and reverted in commit `0b303a8`, and `git diff --name-only origin/main..HEAD` now contains no `Cargo*` path.

**Charged to no lane (1) — pre-existing red.** `oneiron-server`'s `the_real_codec_rows_run_the_same_codec_package_axum_resolves` fails on this tree (`tokio-tungstenite@0.28.0` vs `0.29.0` — the lock carries three versions and axum resolves a different one than the row pins). **Verified pre-existing** by checking out 47ac630's `crates/` and re-running: identical failure. Not touched by this lane; `cargo test -p oneiron --all-features` (the lane's stated final gate) is fully green.

**Charged to no lane (2) — flake.** `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once` went red on one full-suite run ("migrated first-seen must be the local observation (1786085149), not learned_at (2)") and green on the re-run and in isolation. Its body reads `crate::unix_seconds_now()` and compares against the authority first-seen floor; it references no off-record, fence, or overlay surface. Wall-clock boundary flake, not a lane regression. Flake guard applied: re-ran on the same tree, **EXIT=0, 3938 passed / 0 failed / 6 ignored**.

---

## 6. TEST INVENTORY (the acceptance artifact)

Rebuilt on the rebased tree. Authoring census was 89 total / 28 CONTRACT / 24 MIXED / 37 MECHANISM (a drift check only — no per-test artifact shipped with the blueprint).

**Rebuilt: 71 tests enumerated across the fence blast radius — 41 MECHANISM (deleted) / 18 MIXED (rewritten on overlay setup) / 12 CONTRACT (kept: 6 needed a signature- or comment-only touch, 6 wholly untouched and listed for completeness) — plus 3 NEW.**

Drift explanation, both directions. **Down from 89 → 71:** enumeration here is BODY-based (a test counts iff its body touches fence machinery), and 11 tests that match only the English word "fence" in unrelated TOCTOU / lease / replay / markdown prose are excluded — `sweep/tests.rs`, `attempt_queue/tests.rs`, `outbound_consent/tests.rs`, `outbound_intent_ledger/tests.rs`, the two `engine_executor/tests.rs` markdown-code-fence tests, and `src/tests.rs`'s "defence-in-depth". The remaining gap is P4a/P5 (1728/1730) having already retired fence-era tests before this lane cut. **Up from 37 → 41 MECHANISM:** the rebase added four mechanism tests that did not exist at authoring — the two `store/tests.rs` gate-decision purge tests for `delete_gate_decisions_for_missing_off_record_turn_in_txn`, `disclosure::tier_rule_1_durable_fence_backstop_is_tier_a`, and the `#[ignore]`d `m8` 1687 oracle. Correspondingly CONTRACT fell (28 → 12) and MIXED fell (24 → 18), because the classes that survive P6 are far narrower than authoring expected: once base cannot hold a session row, most "durable off-record behaviour" tests turn out to have been asserting the fence, not the behaviour.

Legend: **M** = MECHANISM (deleted) · **X** = MIXED (rewritten on overlay setup, behaviour preserved) · **C** = CONTRACT (kept/ported) · **N** = new.

### `crates/oneiron/src/off_record/tests.rs`
| # | Test | Class | Disposition |
|---|---|---|---|
| 1 | `off_record_tag_scrubs_offline_updates_and_preserves_ordinary_state` | M | deleted (tag + outbox scrub both gone) |
| 2 | `off_record_enter_is_explicit_marked_and_single_shot` | X | rewritten — `fenced_turns` assert → `promoted_turns` |
| 3 | `off_record_registry_evaporates_without_base_residue_on_reopen` | C | kept unchanged |
| 4 | `off_record_crash_orphaned_fence_is_gated_then_swept_on_reopen` | M | deleted (orphan sweep + export refusal) |
| 5 | `live_overlay_membership_is_hidden_by_retrieval_fence` | M | deleted — asserts the deleted retrieval filter over a base row, via a state the K4 guard forbids; contract now covered by `base_leak_sweep` |
| 6 | `entity_put_guard_rejects_live_overlay_membership` | X | rewritten — error identity → `OffRecordTaintedBaseWrite` |
| 7 | `mode_flip_seals_overlay_writes_but_keeps_composed_reads` | C | kept unchanged |
| 8 | `off_record_fenced_turns_are_unextractable_including_post_flip` | M | deleted (same as #5) |
| 9 | `off_record_outbound_rejected_in_mode_with_typed_error` | C | kept unchanged |
| 10 | `off_record_close_deletes_transcript_keeps_floor_and_base_receipts` | X | rewritten — tagged turns → commissioned base writes that SURVIVE close; asserts zero REDACTION_AUDIT minted; receipt-binding + floor + base-run halves preserved verbatim |
| 11 | `off_record_closing_flag_freezes_record_against_mutators` | X | rewritten — tag mutator replaced by `record_emit_receipt`; promote-during-close is still the load-bearing arm |
| 12 | `off_record_close_rejects_late_write_for_missing_turn_without_audit_artifacts` | M | deleted (closed-fence tombstone + tag-before-write) |
| 13 | `off_record_close_retry_keeps_completed_delete_out_of_missing_counts` | M | deleted (PolicyDelete retry accounting) |
| 14 | `off_record_session_ref_bounds_are_enforced_everywhere` | X | rewritten — tag arm dropped, other five verbs kept |
| 15 | `off_record_fence_blocks_ppr_expansion_and_context_pack_edges` | M | deleted (deleted PPR/edge filters; covered by `base_leak_sweep`) |
| 16 | `promote_replay_refuses_another_live_rooms_overlay_id_and_rolls_back` | C | kept unchanged |
| 17 | `tag_rejects_re_fencing_a_durably_promoted_turn_in_a_later_session` | M | deleted (tag verb gone) |
| 18 | `off_record_crash_sweep_is_skipped_when_a_peer_holds_the_open_lock` | M | deleted (flock apparatus gone) |

### `crates/oneiron/src/sync/window/tests.rs`
| # | Test | Class | Disposition |
|---|---|---|---|
| 19 | `off_record_fence_defers_window_packing_for_every_fenced_turn` | X | rewritten → **`window_packing_door_skips_overlay_members_and_packs_commissioned_writes`** (the egress regression: both packing paths, `pm:` stays pending, close releases) |
| 20 | `off_record_tag_eagerly_scrubs_an_already_open_window` | M | deleted |
| 21 | `persist_state_scrubs_fenced_carriers_and_preserves_ordinary_content` | M | deleted |
| 22 | `off_record_tag_eagerly_scrubs_an_already_open_live_window` | M | deleted |
| 23 | `off_record_tag_eagerly_scrubs_every_live_cross_window_carrier` | M | deleted |
| 24 | `forward_rematerialization_scrubs_a_fenced_remote_carrier` | M | deleted |
| 25 | `persist_state_scrubs_fenced_carriers_before_snapshot_export` | M | deleted |
| 26 | `off_record_fence_scrubs_preexisting_window_carriers` | M | deleted |
| 27 | `off_record_fence_scrubs_preexisting_cross_window_target_edges` | M | deleted |
| — | helper `assert_fenced_history_absent_from_export` | M | deleted with its callers |

### `crates/oneiron/src/pipeline/tests.rs`
| # | Test | Class | Disposition |
|---|---|---|---|
| 28 | `fenced_text_rows_do_not_consume_channel_limit_slots` | M | deleted |
| 29 | `fenced_recency_text_rows_do_not_exhaust_overfetch_window` | M | deleted |
| 30 | `fenced_vector_rows_do_not_consume_channel_limit_slots` | M | deleted |
| 31 | `unrelated_vector_fence_preserves_scoped_overfetch` | M | deleted |
| 32 | `vector_fence_replacement_does_not_apply_post_fusion_type_filter` | M | deleted |
| 33 | `vector_fence_widening_grows_in_bounded_batches` | M | deleted |
| 34 | `temporal_fence_replacement_scan_budget_is_bounded` | M | deleted |
| 35 | `vector_widening_probe_does_not_export_discarded_claim_gate_decisions` | M | deleted |
| 36 | `fenced_temporal_rows_do_not_consume_channel_limit_slots` | M | deleted |
| 37 | `fenced_temporal_candidates_do_not_stop_adaptive_widening` | M | deleted |
| 38 | `unrelated_temporal_fence_does_not_expand_candidate_window` | M | deleted |
| 39 | `backward_boundary_replay_keeps_live_row_behind_fences` | M | deleted |
| 40 | `long_interval_scan_counts_only_spanners_toward_cap` | C | kept — signature-only edit (`execute_temporal` arity) |
| 41 | `long_interval_scan_does_not_spend_cap_on_preexisting_ids` | C | kept — signature-only edit |
| 42 | `backward_seek_preserves_lowest_ids_with_same_timestamp` | C | kept — `collect_index_candidates` arity only |

### `crates/oneiron/src/batch/tests.rs`
| # | Test | Class | Disposition |
|---|---|---|---|
| 43 | `standalone_claim_write_does_not_record_gate_decision_before_closed_fence_rejection` | X | rewritten → `..._before_taint_rejection` (overlay member, `OffRecordTaintedBaseWrite`) |
| 44 | `off_record_close_removes_preflight_gate_decision_for_never_written_turn` | M | deleted (tag-before-write + close-side receipt purge) |
| 45 | `replicated_put_is_rejected_while_off_record_fence_is_live` | X | rewritten → `replicated_put_is_rejected_at_a_live_overlay_member_id`; ADDS a post-close arm proving the door is keyed to LIVE membership |
| 46 | `taint_guard_rejects_edge_targeting_a_live_overlay_id` | C | kept — comment reference to the renamed door only |

### `crates/oneiron/src/batch/export/tests.rs`
| # | Test | Class | Disposition |
|---|---|---|---|
| 47 | `every_whole_vault_export_entry_refuses_live_session_without_artifact_then_allows_close` | X | rewritten → **`whole_vault_export_runs_during_a_live_session_and_skips_only_overlay_members`** (all four entry points succeed; door excludes the member, admits the commissioned write) |
| 47b | `export_manifest_import_rejects_unsupported_manifest_version` | C | CONTRACT-keep; collaterally deleted by the #47 rewrite, restored verbatim |
| 47c | `export_manifest_import_rejects_unsupported_storage_abi` | C | CONTRACT-keep; collaterally deleted by the #47 rewrite, restored verbatim |
| 47d | `export_manifest_import_rejects_unsupported_storage_schema` | C | CONTRACT-keep; collaterally deleted by the #47 rewrite, restored verbatim |
| 47e | `export_manifest_import_rejects_unsupported_db_manifest_shape` | C | CONTRACT-keep; collaterally deleted by the #47 rewrite, restored verbatim |

Rows 47b–e (with their `manifest_json_value` helper) carry zero off-record/fence content — they pin
`ExportManifest::from_json_for_import`'s fail-closed import branches, which this lane never touched.
Their deletion was collateral of the neighbouring #47 rewrite and is corrected in §10.

### `crates/oneiron/src/sync/{bridge,quarantine,client,queue}/tests.rs`, `sync/server_state.rs`
| # | Test | Class | Disposition |
|---|---|---|---|
| 48 | `observer_b_quarantines_fenced_edge_before_apply_and_keeps_ordinary_control` | X | rewritten → `observer_b_quarantines_overlay_member_edge_...`; quarantine reason → `OffRecordTaintedBaseWrite`, raised by K4 inside the apply txn |
| 49 | `forward_remat_quarantines_closed_off_record_fence_rejection_and_continues` | X | rewritten → `forward_remat_quarantines_overlay_member_rejection_and_continues`; asserts the carrier is NOT scrubbed (behaviour delta, §5.5) |
| 50 | `vv_response_scrubs_fenced_carrier_before_export` | M | deleted |
| 51 | `inbound_set_then_delete_fenced_body_persists_history_free_with_ordinary_control` | M | deleted |
| 52 | `off_record_fence_scrub_drops_ordinary_rows_and_preserves_delete_bearing` | M | deleted (outbox scrub gone) |
| 53 | `persist_window_snapshot_scrubs_fenced_carriers_and_keeps_controls` | M | deleted |

### `crates/oneiron/src/{store,context_pack,disclosure,skill_convert,edit_distance/reservoir}` tests + oracles
| # | Test | Class | Disposition |
|---|---|---|---|
| 54 | `store::off_record_purge_deletes_the_grant_ref_index_rows_with_the_primaries` | M | deleted (helper gone) |
| 55 | `store::off_record_purge_deletes_claim_index_rows_with_the_primaries` | M | deleted (helper gone) |
| 56 | `context_pack::n1_owner_absent_tier_a_and_out_of_scope_ids_appear_nowhere` | X | rewritten — off-record case staged as a live overlay member |
| 57 | `disclosure::tier_rule_1_live_overlay_membership_is_tier_a` | C | kept unchanged |
| 58 | `disclosure::tier_rule_1_durable_fence_backstop_is_tier_a` | M | deleted |
| 59 | `skill_convert::fenced_refs_are_refused_before_the_refiner_runs` | X | rewritten → `live_room_refs_are_refused_before_the_refiner_runs` (`EntityNotFound`, refiner call count still 0) |
| 60 | `reservoir::a_fenced_session_contributes_no_candidates_at_all` | X | rewritten → `a_live_session_contributes_no_candidates_at_all` |
| 61 | `reservoir::a_fenced_source_turn_aborts_the_export_before_the_first_byte` | X | rewritten → `a_live_session_source_turn_aborts_...` |
| 62 | `reservoir::an_unfenced_source_turn_exports_normally` | X | rewritten → `an_ordinary_source_turn_exports_normally` |
| 63 | `reservoir::no_override_api_on_the_export_surface` | X | rewritten — needle list re-spelled off the deleted vocabulary |
| 64 | `reservoir::a_pair_with_no_source_turn_passes_the_tripwire` | C | kept — doc wording only |
| 65 | `reservoir::the_index_rebuild_shares_the_export_tripwire` | X | rewritten on overlay setup |
| 66 | `m8::one_1687_summary_compacted_from_a_fenced_window_is_fenced_at_creation` | M | deleted (`#[ignore]`-gated future oracle built entirely on tag + fence probe) |
| 67 | `branch_store_oracle::base_leak_sweep_every_reader_family_sees_no_overlay_rows` | C | **kept active, unmodified** |
| 68 | `branch_store_oracle::fence_symbol_census_returns_zero_hits` | C | **UNIGNORED + extended** 8 → 16 symbols; green |

### `crates/oneiron-server/src/handler/tests.rs`
| # | Test | Class | Disposition |
|---|---|---|---|
| 69 | `vv_request_scrubs_fenced_carrier_before_server_export` | M | deleted |
| 70 | `inbound_update_with_fenced_carrier_is_not_relayed_verbatim` | M | deleted |
| 71 | `inbound_set_then_delete_fenced_body_relays_and_persists_history_free` | M | deleted |

### NEW (N)
| # | Test | Where |
|---|---|---|
| N1 | `window_packing_door_skips_overlay_members_and_packs_commissioned_writes` | `sync/window/tests.rs` — the sync half of the egress regression |
| N2 | `whole_vault_export_runs_during_a_live_session_and_skips_only_overlay_members` | `batch/export/tests.rs` — the export half |
| N3 | post-close arm inside `replicated_put_is_rejected_at_a_live_overlay_member_id` | `batch/tests.rs` — proves LIVE-keying, i.e. no durable substitute survives close |

**Counts: M = 41 · X = 18 · C = 16 · N = 3 (75 enumerated + 3 new).**

Per-file M/X/C: `off_record/tests.rs` 9/5/4 · `sync/window/tests.rs` 8/1/0 · `pipeline/tests.rs` 12/0/3 · `batch/tests.rs` 1/2/1 · `batch/export/tests.rs` 0/1/4 · sync `{bridge,quarantine,client,queue}/tests.rs` + `server_state.rs` 4/2/0 · `store`/`context_pack`/`disclosure`/`skill_convert`/`reservoir`/oracles 4/7/4 · `oneiron-server/src/handler/tests.rs` 3/0/0.

No surviving test asserts a fence key, a scrub count, or a close-delete implementation detail.

---

## 7. Done-means status

| Item | Status |
|---|---|
| No `offrecord_fence:*` / inherited / closed-fence / fence-receipt family; no durable substitute | ✅ |
| `vault.rs` has no flock/open-lock field, sole-opener branch, orphan sweep, delete-at-open fallback, or fence downgrade | ✅ |
| Close: no `PolicyDelete`, no close-delete, no redaction cascade, no closed-fence retention; drops overlay after lease drain; keeps P5 rows | ✅ |
| Batch/pipeline/BM25/context-pack/base-reader free of fence guards, fences-present threading, scan budgets, overfetch-then-filter; P4a taint preflight active and typed | ✅ |
| Sync free of carrier scrub, defer-sync holdout cluster, history-free pin driven by fences, incident-edge walk, bridge/outbox/quarantine mirror, closed-fence tombstone; ordinary `pm:`/`rm:`/`dt:`/quarantine intact | ✅ |
| Source audit: one predicate in the central sync door, one in whole-vault export, no duplicates, no deleted door | ✅ |
| Egress regression: overlay TURN absent from sync + export; commissioned base write present in both | ✅ N1/N2 |
| Export succeeds while a session is live; `OffRecordExportRefused` + `ensure_no_open_off_record_session` have zero references | ✅ |
| Every MECHANISM deleted, every MIXED rewritten; full per-test inventory shipped | ✅ §6 |
| `base_leak_sweep_...` remains active | ✅ |
| `fence_symbol_census_returns_zero_hits` unignored, extended to the audit list, green | ✅ |
| Direct repository audit: zero production hits for all ten named symbols + deleted error variants | ✅ (only non-src hit is `HOST_OFF_RECORD_SESSION_MARKER_LINE` in `crates/oneiron/tests/prompt_blocks.rs` — a HOST-side test const proving the host owns marker composition; not production, not in the oracle's `src/` walk, and left deliberately) |
| Session-path tracing is ids-only | ✅ — every `tracing::*` in `off_record/{lifecycle,promote}.rs` carries only `turn.to_hex()`, `window.key`, counts (`replayed`, `markers`, `mirrored`), and `error = %error` over typed errors that render ids/static strings |
| Fence-lane filter green, rewritten MIXED suite green, new egress properties green, clippy green, no `Cargo.lock` change | ✅ |

## 8. Downstream notes

- **ONE-1732 (P7)** inherits a zero-fence source shape. `STORAGE_ABI_VERSION` is untouched; the `vault_meta` keyspace lost the `offrecord_fence:v0:` prefix entirely, which is the shape its doc rewrite should describe.
- **ONE-1878** — the flock surface is gone, so the audit collapses to a residue check as predicted.
- **OF-222 / ONE-1240** — when the whole-vault row enumerator lands, its sole entity-row loop must call `whole_vault_export_excludes_entity` and nothing else. The contract sentence lives on that function's doc comment.
- **SEAM with 1376 (E1-L3, live)** — this lane touched `batch.rs` only in the taint-guard/`apply_put`/gate-preflight regions and `error.rs` only by removing three variants. Zero edits to `habit.rs`, `edge.rs`, or `src/tests.rs`; 1375's streak tail call and 1924's `BlockedBy` arms are untouched. A merge-in at publish is orchestrator-owned.

---

## 9. SIMPLIFY pass (K3) — verdict: NO EDIT WARRANTED

Deletion-biased review of this lane's own additions only (the sweep itself is the deletion; the pass hunted structure the impl leg ADDED). Examined, with verdicts:

- **The two egress doors** (`window_packing_excludes_entity`, `whole_vault_export_excludes_entity`) — thin named wrappers over `OffRecordSessionRegistry::contains_entity`. KEEP: the blueprint keystone mandates named central doors ("the single central door owns the decision"; the export door carries the OF-222 contract sentence), and the N1/N2 acceptance tests call them by name. Inlining them would delete a ratified seam, not structure.
- **`reject_overlay_member_base_write`** (`batch.rs`) — the relocated live half of the deleted `guard_off_record_entity_put`, two call sites (`apply_put` chokepoint + gate preflight loop), one predicate, one typed error. KEEP: this is the preserved P4a taint semantics the hard laws forbid deleting; collapsing it into its callers would duplicate the door.
- **`let turns_deleted = overlay_transcript_deleted`** rename binding at the close-outcome construction (`lifecycle.rs`) — deliberate semantic hand-off from the pre-close census name to the public outcome field, documented in place. Renaming the tuple binding instead would be churn, not simplification.
- **Dead-structure sweep** — grep-verified zero residue of every deleted symbol outside the census oracle; zero newly-dead helpers (`export_window_updates_since`, `has_overlay_entities`, `persist_imported_update` all retain live callers); zero unused imports (clippy-clean tree). The `m8` oracle's `surfaced_summary_ids`/`working_set_summary_ids` probes died with their only caller — already removed by the impl.
- **Comments** — every touched comment re-derives from the new shape (disclosure rule 1, facade lock-ordering, deletion.rs hoist rationale, reservoir tripwire module doc). No stale fence references survive.

Tests, fixtures, and public API untouched by design. Cheap gates re-verified on the impl tip `e08cdeb`: `cargo fmt --all -- --check` clean; `cargo clippy -p oneiron -p oneiron-server --all-features --all-targets` clean (zero warnings). No code changed, so the impl's full-gate result (3938 passed / 0 failed / 6 ignored) stands unmodified.

---

## 10. VERDICT-FIX (Opus fix leg, on the simplify tip `7910913`)

One verdict-verified REAL finding from the finder + verdict legs. One item, one fix, no
production-code change.

### F1 — P2 `contract-test-deletion` (CONFIRMED) — `crates/oneiron/src/batch/export/tests.rs`

**Defect.** The lane's rewrite of the live-session export test (#47) deleted four *neighbouring but
unrelated* tests as collateral — `export_manifest_import_rejects_unsupported_{manifest_version,
storage_abi,storage_schema,db_manifest_shape}` — together with their `manifest_json_value` helper.
They are pure CONTRACT tests: zero off-record, fence, or session content in their bodies, and
nothing in this lane's fence-family deletion mandate reaches them. Independently re-verified here:
the five symbols exist on the pre-lane parent `47ac630` (`batch/export/tests.rs` lines 269–360) and
had **zero hits anywhere in the tree** at the simplify tip — not moved, not renamed, not replaced.

**Consequence.** The production code they guard is fully intact — `ExportManifest::from_json_for_import`
→ `validate_import_supported` (`crates/oneiron/src/batch/export.rs:324`, data-shape arm at `:436`)
still carries every distinct fail-closed branch. So a regression that *admits an incompatible export
artifact* (wrong manifest version / storage ABI / storage schema / DB-manifest shape) would have
passed the suite. A real coverage hole on a fail-closed import boundary; not P1, because runtime
behaviour was never altered and the repair is mechanical.

**Fix.** Restored all four tests plus the `manifest_json_value` helper **verbatim** from
`git show 47ac630:crates/oneiron/src/batch/export/tests.rs`, placed after the rewritten egress
regression (N2). Byte-identical to the parent text — verified by `diff` against the extracted
parent range, zero differences. All required symbols were already in scope via `use super::*`
(`EXPORT_MANIFEST_VERSION`, `STORAGE_ABI_VERSION`, `STORAGE_SCHEMA_VERSION`, `Error`,
`ExportManifest::clear`); no imports added. **Zero production-code lines changed** (`git diff HEAD --
crates/oneiron/src/batch/export.rs` is empty) — none were needed and none were wanted.

**Test-inventory law repaired.** §6 now enumerates rows **47b–47e** under
`crates/oneiron/src/batch/export/tests.rs`, class **C**, disposition "CONTRACT-keep; collaterally
deleted by the #47 rewrite, restored verbatim". Per-file M/X/C for that file corrected
**0/1/0 → 0/1/4**; lane totals corrected **C = 12 → 16**, enumerated **71 → 75**. The §5 claims
table's Nature column for the file now reads the restoration too.

### Mutation verification (red-before / green-after)

Each of the four guards in `validate_import_supported` was deleted **one at a time** and the lib
suite re-run; the tree was `git checkout`-restored between rounds. The binding is exactly 1:1 —
each mutation reds its own test and only its own test, so no restored test is riding on another
guard's coverage:

| Guard removed (`batch/export.rs`) | Red test | Other three |
|---|---|---|
| `manifest_version != EXPORT_MANIFEST_VERSION` | `..._rejects_unsupported_manifest_version` FAILED | ok |
| `storage_abi_version != STORAGE_ABI_VERSION` | `..._rejects_unsupported_storage_abi` FAILED | ok |
| `storage_schema_version != STORAGE_SCHEMA_VERSION` | `..._rejects_unsupported_storage_schema` FAILED | ok |
| `named_databases` len/zip shape check | `..._rejects_unsupported_db_manifest_shape` FAILED | ok |

Unmutated tree: all four green (`3 passed` → `10 passed` across `batch::export`).

### Gates

- Scoped: `cargo test -p oneiron --all-features --lib batch::export` → **10 passed / 0 failed**.
- `cargo fmt --all -- --check` clean; `cargo clippy -p oneiron -p oneiron-server --all-features --all-targets` clean.
- Final: `cargo test -p oneiron --all-features` → **3942 passed / 0 failed / 6 ignored** (lib), every
  integration target green, zero `FAILED` / zero panics in the whole log. Exactly +4 over the impl
  tip's 3938 — the four restored tests and nothing else.
- Diff ⊆ packet: the only source file touched is `crates/oneiron/src/batch/export/tests.rs` (test-only)
  plus this worklog. **No `Cargo.toml`, no `Cargo.lock`** — the lockfile that cargo re-touched during
  the mutation rounds was reverted with `git checkout -- Cargo.lock`. `STORAGE_ABI_VERSION` untouched
  (1732 owns the bump). No fence-family symbol resurrected; the §7 done-means table stands unchanged.
