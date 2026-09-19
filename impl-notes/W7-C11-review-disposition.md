# W7-C11 review disposition — reviewed head 41c32f86

## Review collection

The all-state, paginated PR head lookup returned `[[]]`. Paginated repository PR
search for `W7-C11` returned zero items (`incomplete_results=false`). The actual
branch is `w7/W7-C11` in `oneiron-dev/oneiron`. Thus no C11 PR exists, and there
are no Qodo, Codex or CodeRabbit issue comments, reviews or inline threads to
paginate or answer. No provider quota error occurred. Do not post to PR933 or
another ticket. The explanation below must accompany C11's eventual publication.

Original Opus/Grok roots, their calendar and pack/conflict/stream subreviews,
unfinished notes/recovery/DAG/ports subreview records, and the earlier `.w7`
audits are preserved. `target/w7-logs/review-fix/internal-ledger.md` gives the
complete deduplicated source index S1–S12; `ports-context.md` records migration
seams and remaining calls found during the edit. No replacement reviewers or
build fanout was launched.

## Dispositions

- **F-GROK-1..7 (S2; step 21): fix.** Claim reads, writes, lifecycle, target checks,
  expression preference and session-scoped visibility now consume the entity,
  edge and short-ID ports. This also removes related uncited direct reads.
  Historical/raw corruption handling, bounded scans, D19/policy checks and
  session overlay composition are retained. The earlier census counted claim/
  as part of the adapter; this repair removes that disputed boundary rather
  than broadening the exemption. Production claim-subtree census is empty.
- **F-GROK-8 (S2/S3; steps 6–9): fix.** Both calendar connectors now commit EVENT
  birth with an Auto/Active projector-recorded imported origin and the required
  source/external ID fields in one transaction. Semantic candidates still cross
  the imported-evidence Gate as Proposed. Feed and connector drift share one
  origin-preserving writer, including native recurrence/calendar fields.
- **F-OPUS-1 (S1): skip as invalid.** NOTE (1–5), calendar engine (6–9), recovery
  (10–12), criticality (15–16), persistent conflicts/ranking (18–20), MESSAGE
  streaming (24) and all 24 implementation-note entries already exist at the
  reviewed commit. The partial diff did not show them. Source/test paths are
  listed in the internal ledger and the existing per-step notes.
- **S4, S6, S7, S8:** retain existing landable findings and evidence for
  criticality/conflict/stream, recovery, DAG, Android and ports. Unfinished
  subreview drafts are preserved as drafts, not promoted to final reviews.
- **F-S5-DRAFT:** skip. The seventh descriptor is the existing opinion/take kind,
  not a missing required kind. The raw NOTE test also refuses at an earlier
  authoring guard; replicated and authored doors still enforce the kind gate.
- **S9 F1/F5:** skip as disproved by current compilation evidence and the existing
  include_forks HTTP assertion. **S9 F2/F3/F4/F6/F7:** skip as nonblocking
  documentation/naming/extra-coverage suggestions; engine guards and required
  acceptance are covered. No correctness change was alleged by these rows.
- **S10 clock residual:** already fixed by 5c00dadf, before this review. **S10
  regeneration-completion caller:** host-projector API by recorded design; these
  port contracts do not promise an autonomous regeneration worker.

## Latest internal review — S13

Source: `tickets/W7-C11/logs/review-opus-2.jsonl`, completed
2026-09-19T22:34:52Z, source c82d8809 with cb39cbb0 notes. No new review root was
created by this repair seat. Its nine allegations are all **skipped as invalid**:

| S13 finding | Existing implementation / reason |
|---|---|
| 1: Missing notes | This committed `impl-notes/W7-C11.md` has all 24 per-step entries. |
| 2: Missing NOTE system | `note.rs`, `note/kinds.rs`, `note/documents.rs`, `note/verbs.rs`, `note/proposals.rs`; authored and replay kind guards already exist. |
| 3: Calendar is DTO-only | `calendar/origin.rs` validates and stages live origins; batch write guard, imported connector fix b3a4678b and 105 passing calendar tests refute it. |
| 4: Missing canonical recovery | `recovery/canonical.rs`, `recovery/document.rs`, `recovery/ladder.rs`, `recovery/quarantine.rs` implement these doors. |
| 5: Missing DAG vault methods | `conversation_dag/writes.rs:263,268` implements append/move; `scopes.rs:174` resolves scope; `migration.rs:129` migrates; `scope_summary/doors.rs:187,279` implements spawn and mint/land. The completed server build and tests call these engine methods. |
| 6: Criticality fields never populated | `pipeline/criticality.rs` and context-pack hydration resolve the policy; `serialize/pack_preparation.rs:292,300` updates count/overflow; `serialize/token_budget.rs` enforces budgets and emits the warning. Existing criticality tests assert the values. |
| 7: Missing conflicts/ranking | `dreamer_consolidation/conflict.rs`, `dreamer_consolidation/tests/persistent_conflicts.rs`, `context_pack/source_ranking.json`. |
| 8: Missing port traits/adapters | `ports/query.rs:11,52` defines EntityStoreRead/EdgeStoreRead; `ports/lmdb_query.rs` and `ports/memory/query.rs` implement the storage readers. Full compilation and conformance tests completed. |
| 9: Missing MESSAGE streaming | `message_stream/mod.rs`, `policy.rs`, `receipts.rs`, `types.rs`, `tests.rs` implement all five verbs and receipts. |

S13-1..4/6..9 duplicate the already-refuted partial-diff inference in F-OPUS-1.
S13-5 adds the DAG assertion, refuted above. No implementation was removed or
replaced to satisfy these false omissions. The S1–S12 source roots and valid
Grok-finding fixes remain intact.

## Validation — actual results, not event status

`impl-notes/W7-C11-review-validation.json` binds the evidence to source c82d8809
and the factory-tested cb39cbb0 notes-only successor. All saved Rust hashes match.
Calendar integration passed 105 tests. The fixed featureless scoped-read suite
passed 20. Both core all-target Clippy lanes (featureless/all-features) exited 0.

The review chain itself ended **101**, not green: its final six-package command
passed 9,154 and failed one scheduling-sensitive deletion fixture, with 21
pre-existing ignores. It could not construct a race within three attempts. That
test file is unchanged by this repair; no production invariant assertion fired.
The failure is retained and no flake fix is claimed.

The already-owned, normal factory tests-after-review then exited **0** at
2026-09-19T22:33:39.731Z on the same source: **9,155 passed, zero failed or filtered,
21 identical pre-existing ignores**. The formerly failing deletion test passed.
This later factory run, not the failed review-chain command or old 9,154 receipt,
is the final six-package evidence. No additional run was launched, no source was
mutated during factory custody, and no factory state or guard was changed.

Final paginated all-state C11 PR lookup again returned `[[]]`. No actual C11
external review surface or posting target exists; no unrelated GitHub post was
made. Provider quota was not an issue. Android NDK/API36.1 and earlier native
proofs remain separately scoped. No full workspace verify.sh or new Android/Node
runtime result is claimed.
