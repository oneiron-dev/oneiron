# WORKLOG — ONE-1446 [SKILL-CONV-1] message-to-skill conversion

Branch `ONE-1446`, cut off `origin/main` @ `8225cec` (SK stack merged through #596).
Canon: ARCH-0017 (`oneiron-arch-0017-message-to-skill-v1`), ARCH-0053 §5/§6/§7.
Blueprint: `~/.claude-wave5/blueprints/SKILLS/ONE-1446.md`.

## What landed

| file | change |
|---|---|
| `crates/oneiron/src/skill_convert.rs` **(new, ~470 lines)** | the conversion door + the refiner seam |
| `crates/oneiron/src/skill_convert/tests.rs` **(new)** | 11 unit tests |
| `crates/oneiron/src/skill.rs` | `put_skill_record` split into `put_skill_record_in_txn` (pub(crate)) + public wrapper; fork-parent check reads in-txn |
| `crates/oneiron/src/skill_hub.rs` | `skill_entity_for_content_hash_in_txn` widened to `pub(crate)` (**PACKET_AMEND**, see below) |
| `crates/oneiron/src/lib.rs` | `pub mod skill_convert` + re-export block |

The flow: `convert_messages_to_skill(vault, request, refiner, occurred, learned_at)`
→ resolve + fence-check the selection → retrieve nearest skills → refine →
recompute canonical identity from the returned tree → **one write transaction**
holding the exact-hash dedup lookup and the create together.

## Done-means

- [x] Fixture messages → `SkillRecord` created: `candidate` lifecycle, `approved`
      approval (ARCH-0017: initiation IS consent), `generated`/`ClaimSource::Generated`,
      `content_hash` recomputed from the refined tree, `source_messages` provenance
      populated, landed through the existing put path.
- [x] Exact dup → `DupPointer` to the holder, no second entity (`skill_count` unchanged).
- [x] Near-dup → `MergeProposed { existing, proposal }`: the proposal is a `candidate`
      revision carrying the TARGET's `skill_id` and a fresh version, stamped `proposed`,
      with `merge_of` + `dedup_rationale` on its provenance. The existing record is
      byte-identical afterwards (asserted).
- [x] Genuinely-new → `Created` with the mint justification receipted on the record.
- [x] Same-namespace: `manual_conversion_dedups_against_a_dreamer_extracted_skill`
      seeds a Dreamer-style generated skill and converts onto its exact bytes → `DupPointer`.
      `an_insistent_mint_verdict_cannot_buy_a_second_holder` pins the tier ordering.
- [x] OF-206 "doc status proposed" surfaced in the module doc (and in the PR note below).
- [x] Fenced-ref NEG: `fenced_refs_are_refused_before_the_refiner_runs` asserts both
      the typed error and `refiner.calls() == 0`.
- [x] Distinct from `Routine` (ONE-248): no routine symbol imported or minted; the
      boundary is stated in the module doc.
- [x] Gates: `cargo fmt --check`, `cargo clippy -p oneiron --all-features --all-targets
      -- -D warnings`, `cargo test -p oneiron --all-features` — all green.

## Deviations from the blueprint (each with its reason)

1. **`llm.rs` untouched.** The blueprint said "add a `CallPurpose` variant if the enum
   is closed; reuse a generic one if not". It is NOT closed — `CallPurpose::Other { name }`
   exists and is the established idiom for exactly this
   (`ACTOR_DISTILL_CALL_PURPOSE_NAME`, `ATTRIBUTION_CALL_PURPOSE_NAME`). So
   `skill_convert_call_purpose()` returns `Other { name: "skill_convert_refine" }`
   and the `llm.rs` claim row goes unused.

2. **No `&WriteEnvelope` parameter.** The keystone sketch had
   `convert_messages_to_skill(vault, req, envelope)`. `WriteEnvelope` is a
   CLAIM-write concept: every consumer is in `claim.rs` / `batch.rs`'s claim-candidate
   doors, and no SKILL door accepts one. Its four axes (actor, source, provenance,
   approval) have nowhere to land on a `SkillRecord` — three of them are already
   fields the door stamps directly, and there is no actor field at all. A threaded-but-
   unread parameter is a lie about where authority comes from, so it is not threaded.
   The door's time params match `put_skill_record`'s instead.

3. **"Receipted" = durable provenance on the landed artifact, not a `ReceiptRecord`.**
   There is no free-standing receipt-write door in this engine: every `ReceiptKind`
   PROJECTS from a substrate row ("Projects from the type-76 resolution ledger event;
   there is no separate receipt store"). Minting a kind for this would be a wire-schema
   addition in `receipt.rs`, which is ONE-1737's claim and out of packet. The rationale
   lands on the record it justified (`dedup_rationale`), which is durable, queryable,
   and is the substrate any later projection would read anyway.

4. **The `SkillRecord` has no `spec` field, so the refined SKILL.md bytes are not
   persisted here.** This matches the hub import door exactly: a `HubPackage`'s files
   are hashed into `content_hash` and the bytes stay the host's (DEC-0002 filesystem
   interface). `RefinedSkill.files` is `Vec<HubFile>` — reusing the engine's ONE skill-
   file-tree type rather than minting a near-identical `SkillFile`.

5. **No merge-target-superseded check.** It would be unreachable: `MergeInto` must name
   a skill from the brief, and `nearest_skills` excludes `Superseded`. The filter is the
   chokepoint; a second guard at the call site would be dead code.

## PACKET_AMEND (needs ratification)

`crates/oneiron/src/skill_hub.rs` is CLAIMS-owned by **1892**, not 1446. The change is
**one visibility keyword plus a doc line**: `fn skill_entity_for_content_hash_in_txn`
→ `pub(crate) fn`. That function IS the shared-namespace probe the ticket's dedup
contract requires, and it already existed; the alternative was duplicating
`CONTENT_HASH_INDEX_PREFIX` into `skill_convert.rs`, which would give the shared
namespace two sources of truth — precisely what the ticket exists to prevent.
No collision: 1892 adds `skill_scan.rs` / hub-inline scanning, not a rewrite of this
lookup. No semantic change; every existing caller is unaffected.

## Notable design calls

- **Error reuse over a new taxonomy.** The fenced-ref refusal raises
  `Error::OffRecordFencedTurnWriteRejected { turn_ref }` — the SAME variant
  `guard_off_record_entity_put` raises at the batch write door, so a caller matches ONE
  `ErrorKind` for "off-record refused" wherever it is raised. Adding a variant would
  have meant an out-of-packet `error.rs` edit for a kind that already exists.
  *Caveat for the screener:* that variant's Display text ends "…its session is closed or
  closing", which is narrower than this call site (the session is typically live). The
  `ErrorKind` is right; the message tail is imprecise. Generalising the text is a 1-line
  `error.rs` edit — out of packet here, cheap for whoever owns `error.rs` next.
- **`confidence` seeded from the prior, not from `1.0`.** `fork_skill_record` stamps
  `1.0`; ARCH-0053 §5 puts "conversation convert" under `ProvenanceTrustClass::Generated`,
  whose prior is Beta(1,2) — mean 0.333. The cache is seeded from
  `SkillReliabilityPosterior::seeded_from_provenance(Generated).mean()`, so a converted
  skill starts WEAK, as the canon intends, and no new number is invented.
- **Version = `convert-<first-16-hex-of-content-hash>`.** A revision's identity IS its
  content (ARCH-0053 §7), so the version names the content instead of counting behind it.
  This also settles the merge-proposal case for free: the proposal's version differs from
  the target's because their bytes differ, with no counter to parse out of a free-form
  version string (existing versions range over `"1"`, `"1.0.0"`, semver, …).
- **Neighbour retrieval runs on the SELECTED WORDS, not the refined name/description**,
  because the latter do not exist until after the refine call. A second pass to earn a
  better query would double the ticket's only LLM cost to re-rank eight rows.
  Scoring is deterministic lexical token overlap over `skill_id + desc`, tie-broken by
  entity id so two replicas hand their refiners the same shortlist.
- **`put_skill_record` refactor.** Split rather than duplicated: the dedup lookup and
  the create must commit together, or two concurrent conversions of one passage both
  read "no holder" and both mint. The public signature and every existing error string
  are unchanged.

## Known holes / follow-ups (banked, not fixed here)

- `utterance` / `message_order` in `skill_convert.rs` duplicate ~30 lines of body-key
  tolerance with `actor_claims.rs`'s `decode_utterance` / `message_order`. Extracting a
  shared turn-text reader is the right cleanup, but `actor_claims.rs` is ONE-1739's file
  and the extraction has no obvious owner module yet. Flagged for the post-wave cleanup pass.
- The refined tree is not size-bounded here (the hub door bounds its own because bytes
  arrive from an untrusted remote; this tree comes from the host's own in-process
  refiner). Deliberate non-addition.
- ONE-1447 consumes `PROVENANCE_SOURCE_MESSAGES_KEY` + `source_message_refs()`; the
  reverse index over that key is 1447's `store.rs` claim, not built here.

## PR note (OF-206)

Registry OF-206 / ARCH-0017 is stamped **`proposed`**, not ratified. Built anyway per the
SOW — the acceptance list is the contract. The flag is recorded in the `skill_convert.rs`
module header so a later ratification pass can see exactly which door was built ahead of
the stamp.
