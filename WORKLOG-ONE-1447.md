# WORKLOG — ONE-1447 [SKILL-CONV-2] skill staleness on source-message deletion

Lane SKILLS, stack **SKC layer 2 of 2** (1446 → 1447). Branch `ONE-1447` off
`origin/main` @ `8a624d5` (1446 merged, #600). Blueprint:
`~/.claude-wave5/blueprints/SKILLS/ONE-1447.md`.

## What landed

The lifecycle half already existed on main (`SkillLifecycle::Stale`, the
`Active ⇄ Stale` transitions, `loads_as_canon == false`, and the pinned test
`stale_fold_one_1447_is_reversible_and_never_canon`). This ticket adds the
DELETION HOOK and the index that makes it affordable.

| piece | where |
|---|---|
| reverse source index (`source → skills`) over `vault_meta`, the stale sweep, the staleness note, the CID-7 rebuild door, the two public readers | `crates/oneiron/src/skill_convert.rs` (+~360) |
| index maintenance at the batch put chokepoint, beside the content-hash index | `crates/oneiron/src/batch.rs` (+~20) |
| the sweep on both active-store tear primitives | `crates/oneiron/src/deletion.rs` (+11) |
| `apply_skill_record_body` opened to the crate for the engine-authored flip | `crates/oneiron/src/skill.rs` (+6, one visibility word) |
| exports | `crates/oneiron/src/lib.rs` (+4) |
| 9 tests | `crates/oneiron/src/skill_convert/tests.rs` (+~270) |

Shape, in one line: a deleted entity's id is one `vault_meta` prefix seek; any
skill it hits and whose lifecycle may legally move goes `stale` in the SAME
transaction, with the cause written to a sidecar note.

## Done-means

| acceptance | evidence |
|---|---|
| delete a source → dependent skill flips to Stale in the same txn; `loads_as_canon` false; record intact | `a_deleted_source_stales_the_skill_it_grounded_without_losing_it` — asserts the whole record is byte-equal to the pre-delete one except `lifecycle_status` |
| stale reason inspectable (cause + deleted refs) | same test, via `skill_stale_note` — **see deviation D1: the note is a sidecar, not record provenance** |
| reversible; re-delete of another source re-stales | `the_owner_reverses_the_fold_and_a_later_loss_re_stales` |
| 2 sources: deleting one stales (conservative); non-source delete does NOT | `one_lost_source_of_two_is_enough_and_the_survivor_stays_indexed`, `deleting_a_message_the_skill_never_cited_leaves_it_active` (NEG) |
| reverse-index rebuild identity; delete path works after drop+rebuild | `the_source_index_rebuilds_to_identity_and_the_delete_path_survives_it` — drops every row, rebuilds, asserts identity + idempotence, then deletes a source and asserts the flip |
| `stale_fold_one_1447_is_reversible_and_never_canon` still green | green |
| fmt · clippy `-D warnings` · nextest `-p oneiron --all-features` | green — **3869/3869** (see "Gate note") |

Extra pins beyond the list: `a_second_loss_in_one_episode_grows_the_note`,
`a_soft_deleted_source_stales_the_skill_too` (the other tear primitive),
`a_candidate_conversion_is_left_to_the_admission_gate` (D5),
`a_citation_row_outliving_its_skill_is_pruned_by_the_sweep` (D6).

## Deviations from the blueprint — declared, none absorbed silently

**D1 — the staleness note is a `vault_meta` sidecar, NOT the record's
provenance.** Blueprint §3 asked for `{"stale_reason": …, "deleted_refs": […]}`
"in the record's free-form provenance". That is not writable as a state flip:
`skill_content_changed` (`skill.rs:624`) normalizes away ONLY
`approval_status`, `lifecycle_status` and `confidence`, so a provenance edit is
a CONTENT change, and `validate_skill_update` then demands
`"version must change when updating skill body"` — and rejects the edit outright
on an `Imported` record. Bumping the version on a staleness mark would mint a
phantom revision, contradicting ARCH-0053 §7 (a revision's identity IS its
content; `convert_version` derives the version FROM the content hash) and the
ratified pin in `stale_fold_one_1447_is_reversible_and_never_canon` — *"A state
flip, not a content revision: same version, no bespoke flag."* So the note
lives beside the reverse index, keyed by skill id, and the acceptance
("inspectable") is served by `skill_stale_note`. Note semantics: it describes
the CURRENT episode, so it reads `None` once the owner reverses to `active`, and
a fresh episode replaces rather than merges (a re-stale inside one episode
appends).

**D2 — the `vault_meta` prefix consts live in `skill_convert.rs`;
`store.rs` is NOT touched.** Packet SHRINK. `CLAIMS.md` records both a store.rs
claim (line 36) and the house pattern that supersedes it (line 35: *"key consts
live in the owning module over vault_meta"*); the precedent is
`skill_hub.rs:41-43`, which owns the content-hash index's own prefixes. Net
effect: the declared w4 store.rs rebase risk on this lane is gone.

**D3 — `mark_dependent_skills_stale_in_txn` has its BODY in `skill_convert.rs`;
`deletion.rs` carries only the two call statements.** The blueprint sketched it
under a `deletion.rs` header. This mirrors the twin exactly —
`maintain_skill_content_hash_index_on_delete_in_txn` lives in `skill_hub.rs` and
is CALLED from `deletion.rs:2567` — and holds this lane's footprint in the
w4-contended `deletion.rs` to 2 statements plus comments. Signature unchanged
from the skeleton.

**D4 — index maintenance is hooked at the BATCH put chokepoint (`batch.rs`),
not at the skill put door.** Blueprint §2 said "hook in the skill put door".
`apply_skill_record_body` reaches only the typed doors; SKILL bodies also land
through raw `put_entity` and through sync rematerialization, and a replica that
never indexed its citations would not stale on a delete that originates on it.
`batch.rs:3613` is where the twin content-hash index is already maintained, so
this is the same chokepoint rather than a new one — one site, every road.
**This is the PACKET_AMEND candidate; see below.**

**D5 — only lifecycles the transition table permits actually flip.** The
blueprint asked me to "verify the in-txn primitives' rules permit the
engine-authored Stale flip". They permit it from `Active` only, plus the
`Stale` self-loop (`skill.rs:151`). So the sweep asks
`can_transition(Stale)` and leaves `candidate` / `quarantined` / `superseded`
alone: a candidate has not been admitted and the admission gate is where its
lost evidence gets its hearing; the other two already never load as canon. I did
NOT widen the table — reversing a ratified design decision needs three
independent groundings, and the fold has none. Pinned by
`a_candidate_conversion_is_left_to_the_admission_gate`.

**D6 — no skill-side index-drop hook; the sweep PRUNES dead citation rows as it
reads.** Unspecified in the blueprint. A skill that leaves the active store
would otherwise leave rows that resolve to nothing. Dropping them at skill-delete
time would need two more call sites (hard purge + soft erase) for a row that is
already harmless; pruning on read is one rule in one place, self-healing, and
leaves the rebuild door authoritative. Rows for a source that was deleted while
the skill lives are deliberately KEPT — the record still cites that source, so a
rebuild would recreate them, and keeping them is what makes rebuild an identity.

**D7 — `rebuild_skill_source_index` clears the prefix before rebuilding.** The
blueprint said "Rebuildable (CID-7 door)"; acceptance asks for "rebuild
identity", which a merge would not give. Clear-then-rebuild, pinned as identity
+ idempotent.

Blueprint note honoured as written: no special hard-erase hook. The sweep sits
on the two active-store tear primitives (`soft_erase_active_store_in_txn`,
`purge_entity_active_store_in_txn`), which every local and replayed delete
reason funnels through; erase semantics stay the ERASE family's.

## PACKET_AMEND candidate

**`crates/oneiron/src/batch.rs`** — additive, ~20 lines, at the existing SKILL
put-maintenance site (`batch.rs:3613`), plus one local widened in place
(`previous_skill_content_hash: Option<SkillContentHash>` →
`previous_skill_record: Option<SkillRecord>`, so the prior body is decoded ONCE
and serves both indexes). Rationale in D4. `CLAIMS.md` lists batch.rs for
SKILLS 1892 (activation consult) and 1739 (merged, #596), and for w4
S-AUTH1/S-AUTH4 with a rebase note — this edit is additive and disjoint from
the activation consult.

**Negative amendment:** the declared `crates/oneiron/src/store.rs` claim (D2) is
UNUSED by this lane and can be released.

Declared-and-used, no amendment needed: `skill_convert.rs` (+ tests),
`skill.rs`, `deletion.rs`, `lib.rs` — all inside the ticket's claim slice.
`deletion.rs` is the w4-ERASE-contended file; both hunks are one statement each
at an existing maintenance site, so the cheap-rebase posture the dispatcher
ruled on holds.

## Gate note — a PRE-EXISTING flake, charged to no lane

Two early full-suite runs on this branch failed
`batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`
(`batch/tests.rs:3672`). It is NOT this lane's:

- **Mechanism.** `authority_observation_secs_for_domain`
  (`authority.rs:1451`) anchors a monotone clock at `floor(wall)` on its first
  call per domain and thereafter returns `anchor_secs + floor(elapsed)`. The
  test compares that value against a later raw `unix_seconds_now()`. Whenever
  the anchor lands late in a wall second and the window to the comparison
  crosses the boundary, the assertion loses by exactly 1. Every captured
  failure showed `migrated == wall − 1`, which is that signature and no other.
- **Reachability.** The diff touches `apply_put` only inside
  `if entity_type == ENTITY_TYPE_SKILL` / `if old_type == ENTITY_TYPE_SKILL`;
  this test writes AUTHORITY_LOG entities and never enters the skill arms.
- **Measurement.** Naïve A/B was confounded — the arms ran at different wall
  times on a shared box. Building both lib-test binaries and interleaving them
  1:1 under identical sustained load, n=60 each:
  **HEAD 5/60 failures, BASE (`8a624d5`) 3/60.** Indistinguishable.

Banked as a known hole: the assertion should compare against the anchored
observation clock, not raw wall time (or the test should pin the clock). Not
fixed here — out of packet, and it is a test defect, not a production one.

**Final gate on the lane tree, box otherwise quiet: `3869/3869 passed, 64
skipped`.** `cargo fmt` clean; `cargo clippy -p oneiron --all-features
--all-targets -- -D warnings` clean.

## Notes for the screener

- The sweep runs BEFORE `deindex_entity` on the purge path: it reads the skills
  that cited the id, not the id's own rows, and both acts must land in the one
  transaction that destroys the evidence.
- Strictness is asymmetric on purpose in
  `maintain_skill_source_index_for_put`: a malformed `source_messages` in the
  INCOMING body is refused (that is where corruption enters, and
  `source_message_refs`'s doc-comment requires the sweep never read a broken
  linkage as "cites nothing"); an unreadable PRIOR body only costs unindexed
  rows and is left to the rebuild door.
- The flip preserves the record's `occurred` range and moves only `learned_at`:
  the skill did not happen again, this vault merely learned its evidence is
  gone.
