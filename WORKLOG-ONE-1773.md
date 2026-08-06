# WORKLOG — ONE-1773 [CA-02] SAVED_QUERY entity + staged eval + verdict cache

Lane: CA · Chain CA-A, layer L3 of 4 (`1771 → 1772 → 1773 → 1774`).
Worktree: `/Volumes/Cinema/w5-lt/ca-1773` · Branch: `ONE-1773`.
Base: `8225cec4f` (`origin/main` at cut time) — base=main, no stacking.
`ONE-1771` (#583) and `ONE-1772` (#587) are ancestors; the inherited `gate.rs`
GATE edge is satisfied (`ONE-1728` and `ONE-1772` merged) and `gate.rs` is NOT
claimed by this lane.

## What landed

### `crates/oneiron/src/saved_query.rs` (CREATE)

- **Pack registration.** `register_saved_query_kind(vault, assigned_type_byte)`
  → `Vault::register_structural_kind(byte, "sq", TypeByteBand::Crm,
  CRM_PACK_ID)`. No constant, no `registry.rs` row, zero static bytes.
- **Definition model.** `SavedQueryDefinition` (schema version, `owner_actor`,
  `QueryScope`, `definition_version`, `FilterAst`, `MatcherSpec`, `EvalPolicy`,
  `SavedQueryLifecycle`) + create/update/archive request DTOs and
  `SavedQueryRecord`.
- **Filter AST.** Hand-written `parse_filter_ast` over `serde_json::Value`.
  `all`/`any`/`not`/`claim`/`edge_exists` only; `RANKED_OPERATORS` (`top_k`,
  `topk`, `ppr_score`, `ppr`, `rank`, `percentile`, `global_count`,
  `relative_score`) are rejected BY NAME with the law in the message.
  `validate_per_entity_decidable` is the same law for Rust-built ASTs.
  `filter_dependencies` derives the evidence axes from the AST + matcher, so the
  hash input can never drift from what the query actually reads.
- **Lifecycle API.** `create_saved_query` binds `owner_actor` from the
  authenticated principal (no owner field on the DTO); `read` answers `None` and
  `update`/`archive` answer `EntityNotFound` for a non-owner — ownership IS the
  read, not a post-hoc filter, so a stranger cannot learn a query exists.
  `update`/`archive` are version-CAS'd; archive is a lifecycle transition and the
  record stays addressable for ONE-1778.
- **Staged evaluation.** `SavedQueryEvaluator::evaluate_entity` runs: lifecycle
  gate → scope authorization → evidence → hash → memo → stage 1 → stage 2.
  Stage 2 is reached from exactly ONE place, inside the stage-1 success branch.
  `evaluate_wake_batch` honors `max_entities_per_wake` / `max_judges_per_wake`
  and returns `resume_after`.
- **Verdict memos.** `compute_evidence_hash` is a domain-separated,
  length-prefixed SHA-256 over the definition version, the EFFECTIVE scope, and
  only the declared-relevant evidence. `verdict_memo` / `put_verdict_memo` store
  rows keyed `(query_ref, entity_ref, evidence_hash)` with the
  `SavedQueryDerivationEnvelope` mirroring `Of360DerivationEnvelope`'s fields.
- **Membership.** `MembershipEvent` / `MembershipWritePlan` /
  `MembershipCommitOutcome`, `next_membership_epoch`, `derived_member_value`,
  `commit_membership_plan`, `membership_events`. The commit validates that the
  CA-01 claim value and the event agree, compare-and-sets the monotonic
  `(query, entity)` watermark, and writes the event row + the `campaign.member`
  claim in ONE txn.
- **Pack drift.** `PackMigrationMap` / `PackPredicateRewrite` +
  `repair_pack_drift`, worst-case-wins across affected predicates:
  `Rename` → `AutoMigrated`, `Equivalent` → `AutoRewritten` (notice),
  `SemanticsChanging` → `ProposalRequired` (nothing rewritten), unmapped →
  `Paused { error }` stored on the record.

### `crates/oneiron/src/campaign.rs` (MODIFY)

`register_crm_pack(vault, campaign_byte, saved_query_byte) ->
CrmPackRegistration`. ONE pack entry point, ONE pack identity (`oneiron-crm`),
so a host cannot install half a pack. `register_campaign_kind` is unchanged.

### `crates/oneiron/src/lib.rs` (MODIFY)

`pub mod saved_query;` + a re-export block. Module/re-export wiring only.

### Tests

- `crates/oneiron/src/saved_query/tests.rs` — 15 unit tests: memo-key
  canonicalization (prefix + three fixed-width components, swap-sensitive),
  event-key epoch ordering, malformed-row rejection (truncated / unknown verdict
  / short hash / missing field → `CorruptedIndex`), definition + memo codec
  round-trips, canonical-JSON order independence, watermark row length, cosine
  clamping, fingerprint sensitivity, scope-intersection semantics, evidence-hash
  coverage and length-prefix anti-smearing, judge-response closed set, and the
  watermark verdict table.
- `crates/oneiron/tests/saved_query_oracle.rs` — 18 public-surface tests, one per
  done-means bullet (see below).

## Gates

- `cargo fmt -p oneiron --check` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — zero warnings.
- `cargo test -p oneiron --all-features` — 3524 lib + 18 oracle green.
  - One PRE-EXISTING flake, charged to no lane:
    `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`
    failed once under full parallel load, passed in isolation and on a clean
    re-run of the whole lib suite. The assertion is a wall-clock race —
    `observed_before = unix_seconds_now()` then `migrated >= observed_before` at
    second granularity (`crates/oneiron/src/batch/tests.rs:3670`). `batch.rs` is
    untouched by this lane.

## Done-means coverage

| Blueprint bullet | Test |
|---|---|
| dynamic CRM-band registration, no static byte | `saved_query_registers_dynamically_in_crm_band_without_static_byte` |
| source oracle: no `ENTITY_TYPE_SAVED_QUERY`, no byte, no `registry.rs` edit | `no_static_saved_query_type_byte_exists_in_source` |
| CRUD round-trip + archive without delete | `saved_query_crud_round_trips_and_archives_without_delete` |
| write boundary binds authenticated owner | `saved_query_write_boundary_binds_authenticated_owner` |
| AST accepts only per-entity-decidable operators | `filter_ast_accepts_only_per_entity_decidable_operators` |
| AST rejects `top_k` / `ppr_score` at parse | `filter_ast_rejects_top_k_and_ppr_score_at_parse` |
| stage-1 failure never invokes stage 2 | `stage_one_failure_never_invokes_stage_two` |
| judge uses injected backend + budget lease | `llm_judge_uses_injected_backend_and_budget_lease` |
| owner is the only evaluation principal | `owner_actor_is_the_only_evaluation_principal` |
| memo hits on identical evidence hash | `verdict_memo_hits_on_identical_evidence_hash` |
| memo invalidates on relevant/definition change | `verdict_memo_invalidates_on_relevant_evidence_or_definition_change` |
| CA-01 optional-derivation contract | `campaign_member_uses_ca01_optional_derivation_contract` |
| closed cause set | `membership_events_use_closed_causes` |
| re-entry is a new epoch | `membership_epoch_reentry_is_new_epoch` |
| watermark-guarded, not dedupe-guarded | `membership_commit_is_watermark_guarded_not_dedupe_guarded` |
| OF-241 absence does not block evaluation | `of241_absence_does_not_block_evaluation` |
| wake budget degrades with visible progress | `wake_budget_degrades_with_visible_progress` |
| pack-drift ladder ordered and loud | `pack_drift_repair_ladder_is_ordered_and_fails_loud` |
| memo-key canonicalization + malformed-row rejection | `src/saved_query/tests.rs` (15 tests) |

## Bug the oracle caught during implementation

`owner_actor_is_the_only_evaluation_principal` failed on first run with
`Match` where `NoMatch` was required. The evidence hash was computed over the
DECLARED scope, so revoking the owner's world grant left the hash unchanged and
the memo from the granted evaluation answered "member" for a principal who no
longer had reach.

Fixed at the chokepoint, not the call site: `evaluate_staged` now (a) resolves
the effective scope FIRST and returns early on a closed scope WITHOUT reading or
writing any memo — an authorization outcome is not a derivation and must never be
cached — and (b) evaluates against a definition whose `scope` has been narrowed
to the effective scope, so a grant change the definition version cannot see still
moves the hash. The oracle now also asserts that restoring the grant restores
membership, proving the denial cached nothing.

## Blueprint deviations (declared, none silently absorbed)

1. **serde derives dropped from every type containing `EntityId`.** The keystone
   skeletons put `Serialize, Deserialize` on `SavedQueryDefinition`, `QueryScope`,
   `FilterAst`, `MatcherSpec`, `RelevantEvidence`, `EvidenceDependencies`,
   `VerdictMemoKey`, `VerdictMemoRow`, `MembershipEvent`, `WakeEvaluationReport`,
   and the request/record DTOs. `EntityId` has NO serde impl and `entity_id.rs`
   is a hard non-claim, so those derives do not compile. Resolved exactly as
   CA-01 resolved it for `CrmStageValue`: hand-written codecs with entity
   references as canonical hex. Types with no `EntityId` keep their derives.
   This is also required independently — the done-means demand named `top_k` /
   `ppr_score` errors, which `#[serde(tag = "op")]` cannot produce.

2. **`SavedQueryEvaluator` shape.** Blueprint: `{ vault, llm: Option<&dyn
   LlmBackend>, budget_lease: Option<&BudgetLease> }`. Shipped:
   `{ vault, owner_grants: &QueryScope, judge: Option<SavedQueryJudgeBinding> }`.
   - `llm` + `budget_lease` collapse into one binding (backend + lease +
     envelope). Two independent `Option`s let a caller present a backend with no
     lease; the done-means says the judge "cannot run without explicit backend
     plus budget lease", and a single binding makes that a type-level fact rather
     than a runtime check.
   - `envelope: &CallEnvelope` is host-supplied. The blueprint forbids provider
     selection and model policy in this module; building a `CallEnvelope` here
     would be exactly that. The module still assembles the messages (rubric +
     evidence, both canonical JSON, zero authored prompt text).
   - `owner_grants` is new. The blueprint requires "the intersection of the
     query's declared scope and that owner's grants at evaluation time", but
     engine Rust has NO world/facet grant primitive — `AccessGrantScope` has
     exactly one variant (`CompanionProfile`) — and minting a grant registry is a
     prohibited mechanism. The owner's reach therefore enters as a typed input
     and the intersection is computed at one chokepoint. **Spec is UNDERDEFINED
     here; this is the proposed amendment.**

3. **`commit_membership_plan` is `pub`, not `pub(crate)`.** Its own done-means
   test (`membership_commit_is_watermark_guarded_not_dedupe_guarded`) is named for
   the oracle, which is an external test crate; and `MembershipWritePlan` /
   `MembershipCommitOutcome` are already `pub` in the blueprint, so a crate-private
   consumer of public types was incoherent. ONE-1774 is in-crate either way.

4. **Records live in `vault_meta`, not as SAVED_QUERY entities.** Ground-checked:
   `registry::validate_entity_type` (`src/registry.rs:606`) resolves against the
   STATIC `ENTITY_TYPE_REGISTRY` only. A *dynamically* registered structural kind
   reserves a byte and a short-id namespace but is **not writable through the
   batch put path today** — `vault.put_entity(id, 101, …)` would fail with
   `InvalidEntityType(101)`. Making it writable means editing `batch.rs` /
   `registry.rs`, both hard walls. So this lane does what CA-00 did for CAMPAIGN:
   register the kind, write no entities, and keep the records as module-owned
   versioned `vault_meta` sidecars. The blueprint already required that for memo
   rows; it is silent on the record itself. **This is a real engine gap worth a
   ticket** (see below).

5. **Additions not in the skeleton, all in-file:** `SAVED_QUERY_SCHEMA_VERSION`,
   `EVIDENCE_HASH_LEN`, `QueryScope::intersect` / `is_closed_against`,
   `next_membership_epoch`, `derived_member_value`, `membership_events`,
   `PackMigrationMap` / `PackPredicateRewrite` / `put_pack_migration_map`
   (the drift ladder needs a source for its classifications; the blueprint gives
   the ladder but not the map), and `as_str` / `parse` token pairs on the closed
   enums (the CA-01 house style).

## PACKET_AMEND candidates — NONE TAKEN

Two were considered and rejected in favor of an in-packet solution. Recorded so
a reviewer can rule differently:

- **`crates/oneiron/src/error.rs`.** The house pattern is one error variant per
  body family (`InvalidSkillBody`, `InvalidAgentDefBody`, `InvalidAttemptQueueRecord`,
  …), which would suggest `InvalidSavedQueryDefinition` + an owner-mismatch
  variant. `error.rs` is unlisted in the blueprint manifest and CLAIMS.md, and it
  is a hot cross-lane seam (4 wave-5 lanes touched it in the last 8 commits).
  Reused instead: `InvalidConfig(String)` for owner-supplied runtime-configuration
  rejection (its existing use in `pipeline.rs` is exactly this shape),
  `ConcurrentWrite` for the version CAS, `EntityNotFound` for the
  no-existence-leak ownership answer, `CorruptedIndex` for malformed rows,
  `InvalidClaimBody` for plan/claim incoherence, and `UpstreamToolFailure` for
  judge failures. No new variant needed.
- **`crates/oneiron/src/entity_id.rs`.** Adding serde impls would have let the
  blueprint's derives stand. Hard non-claim; solved with hand-written codecs
  instead (deviation 1).

Two private helpers were re-implemented rather than shared across a fence, both
~15 lines: a canonical-JSON sorter (`llm.rs::canonical_json_bytes` is private and
`llm.rs` is a non-claim) and the snake_case `EdgeKind` name table
(`facade.rs::edge_kind_from_str` is private and `facade.rs` is a non-claim).

## Packet

`git diff --name-only` vs base is exactly the four claimed paths:

```
crates/oneiron/src/campaign.rs      MODIFY
crates/oneiron/src/lib.rs           MODIFY
crates/oneiron/src/saved_query.rs   CREATE
crates/oneiron/src/saved_query/tests.rs   CREATE (child of the claimed module,
                                          blueprint-sanctioned unit-test home)
crates/oneiron/tests/saved_query_oracle.rs  CREATE
```

`campaign/claims.rs` is untouched (explicit NON-CLAIM — imported only).
`registry.rs`, `store.rs`, `vault.rs`, `claim.rs`, `extraction_eval.rs`,
`llm.rs`, `graph_fs.rs`, `gate.rs`, `Cargo.toml`, `Cargo.lock` — all untouched.
No dependency added. No `Cargo.lock` change.

## K3 simplify pass (post-impl, deletion-biased)

Net −35 lines in `crates/oneiron/src/saved_query.rs` (28 insertions, 63
deletions); zero behavior, public-API, or test changes.

- **Single-row `vault_meta` doors collapsed.** The read pattern (open rtxn →
  get → own the bytes) appeared 3x (`load_record`, `verdict_memo`,
  `load_migration_map`) and the write pattern (encode → `with_write_txn` →
  put) 5x; both are now one-line `meta_row` / `put_meta_row` helpers.
  `create_saved_query` had inlined its own copy of the write — it now calls
  `store_record` like every other mutation. The multi-row membership commit
  keeps its own transaction, as it must.
- **`read_watermark_in_txn` deleted** — a one-line wrapper with exactly one
  call site; the commit txn calls `read_watermark` directly (`RwTxn` derefs to
  `RoTxn`).
- **Loop-invariant hoist in `semantic_fingerprints`** — the subject vector was
  re-read once per exemplar; it is read once, so every pairwise fingerprint in
  one collection derives from a single consistent snapshot.
- Pointer for ONE-1774: `Store::vault_meta_{get,put}_in_txn` look like the
  shared doors for this pattern but are `SessionStoreView` methods (off-record
  overlay), not `Store` methods — `meta_row`/`put_meta_row` wrap the raw
  `vault.store.vault_meta` access instead.
- Considered and kept: local `hex_lower` (`receipt.rs` and `deletion.rs` each
  carry their own `pub(crate)` copy — per-module copies are the de facto house
  pattern, and `receipt.rs` is a hot cross-lane seam); local
  `canonical_json_bytes` and `edge_kind_from_name` (impl-leg ruling stands:
  the source modules are non-claims and their copies are private).
  `EvalMode::as_str`/`parse` are dead pub API (the serde derive covers the
  wire form) — flagged here, not removed: public API is out of scope for a
  simplify pass.

Gates after the pass: `cargo fmt -p oneiron --check` clean; `cargo clippy -p
oneiron --all-features --all-targets` zero warnings; `cargo test -p oneiron
--all-features` green (15 saved_query unit + 18 oracle + full suite). One
pre-existing flake observed once under full parallel load:
`embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`
(passed in isolation and on a full-suite re-run; `embed.rs` is untouched by
this lane) — same class as the batch flake above, charged to no lane.

## Notes for later lanes / postmortem

- **Engine gap (candidate ticket):** dynamic structural-kind registrations are
  invisible to `validate_entity_type`, so no runtime-registered kind can hold
  entities. CAMPAIGN (CA-00) and SAVED_QUERY (CA-02) both register bytes that
  nothing can currently write against. Either the write path should consult
  `Store::kind_registry`, or the byte-space-v3 story needs an explicit "namespace
  only, not yet writable" posture in canon.
- **ONE-1774** consumes `MembershipEvent`, `MembershipWritePlan`,
  `next_membership_epoch`, `derived_member_value`, and `commit_membership_plan`.
  Home-node election, attempt-queue claiming, and outbound firing are NOT here.
- **ONE-1778** delegates its SavedQuery surfaces to the create/read/update/archive
  API and supplies the authenticated principal; it must also supply
  `owner_grants` from its actor-bound facade.
- **OF-241** is not a dependency. `EvidenceDependencies` is the subscription-wiring
  surface when it lands; no live-sub runtime or registry was minted.

## VERDICT-FIX round (finder + verdict legs, 11 REAL findings)

Adjudicated verdict: `FIX-REQUIRED` — 4 REAL P1 + 7 REAL P2 + one half-real P3.
Every fix below is mutation-verified: the fix was reverted, the named test was
run, and it went RED; the revert was then undone. 18 mutations, 18 caught.

### P1-1 `effective-scope-not-applied-to-candidate` (saved_query.rs)

The scope intersection failed closed only in the degenerate EMPTY-intersection
case; nothing ever asked whether the CANDIDATE was inside the effective scope.
A world-A query matched a world-B person, or an unscoped one.

The blueprint was genuinely underdefined on the mechanism (its named oracle
enshrined the weak reading), so the fix PINS it:

- `QueryScope::admits(&membership)` — a restricted axis demands a witness ON
  that axis. An entity with no world membership is OUTSIDE a world-scoped
  query, not universally inside it.
- `SavedQueryEvaluator::scope_membership` reads the entity's own `in_world` /
  `has_facet` edges, narrowed to the effective scope. A facet is spelled as its
  FACET entity's canonical hex — the spelling `gate.rs` already uses for a facet
  ref in a scoped-read grant.
- `RelevantEvidence.scope_membership` is a new EVIDENCE field, hashed. Moving
  between worlds therefore moves the evidence hash and invalidates the memo;
  nothing else carried that movement.
- Claim evidence is admitted by world too (`claim_in_scope`): a claim scoped to
  an unreachable world is not evidence this query may read. A world-less claim
  is base reality and reads everywhere — `gate.rs`'s
  `scoped_read_world_matches_claim` rule, mirrored rather than re-invented.

The stage-0 gate runs after the memo lookup and before stage 1, so an
out-of-scope candidate never spends a judge call.

Tests: `declared_scope_is_applied_to_the_candidate_entity`,
`out_of_scope_claim_evidence_does_not_satisfy_the_filter` (oracle);
`scope_admits_only_entities_holding_the_restricted_axis`,
`claim_world_scope_admission_mirrors_the_gate_rule` (unit). The oracle's
`owner_actor_is_the_only_evaluation_principal` now places its person in the
declared world — the weak reading it used to enshrine is gone.

### P1-2 `saved-query-authority-stored-in-unsynced-vault-meta` (saved_query.rs)

The module header's rationale was FALSE on this base: `Store::validate_entity_type`
accepts runtime registrations, and `registered_structural_kind_unblocks_writes_and_short_ids`
(src/tests.rs) proves a dynamic kind is writable with short ids. `vault_meta`
never replicates, so the whole authority of a saved query was node-local.

Split by AUTHORITY, not convenience:

- **The definition is a real entity** of the registered SAVED_QUERY kind,
  written through the batch put chokepoint (`store_record_in_txn` →
  `apply_ops`/`BatchOp::Put`) and read back with a header type check. The byte
  is resolved per-vault from the structural-kind registry
  (`saved_query_type_byte`) — still no constant anywhere. A vault with no CRM
  pack now errors instead of silently sidecar-ing.
- **The epoch watermark is replica-convergent.** `current_watermark` takes the
  max of the local `vault_meta` row and `replicated_epoch_floor` — the highest
  epoch any replicated `campaign.member` claim carries for this
  `(query, entity)` pair, across every lifecycle. A promoted home node
  continues the sequence instead of restarting at 1. A watermark recovered from
  the claim chain carries no content digest, so a same-epoch replay it cannot
  PROVE it applied is `RejectedStaleEpoch`, never `AlreadyApplied`.
- Memos, event rows, repair receipts, and migration maps stay node-local, and
  the header now says so honestly: a memo is a derivation cache, event rows are
  a local audit projection of transitions whose authoritative record is the
  replicated claim chain.

The "engine gap" note in the previous section was wrong and is superseded by
this entry.

Tests: `saved_query_crud_round_trips_and_archives_without_delete` (asserts the
record's entity type is the registered byte),
`membership_epoch_floor_survives_a_promoted_node_with_no_local_watermark`.

### P1-3 `membership-transitions-leave-competing-active-heads` (saved_query.rs)

`commit_membership_plan` minted a fresh claim per transition and never closed
the prior head, so `Entered(1) → Exited(2) → Entered(3)` left three Active
`campaign.member` claims with mutually incompatible states, all of them visible
to `claims_for_subject` as current truth.

The commit now reads the live heads for this `(query, campaign, entity)`
BEFORE writing the replacement (so the replacement is never its own
competition) and supersedes each one in the same transaction — the CA-01
`supersede_crm_stage_in_txn` pattern the blueprint names as the mirror. A
rejected supersession rolls the replacement back with it. Event history is
untouched: closing a claim head is not erasing a transition.

Test: `membership_transitions_leave_exactly_one_live_head`.

### P1-4 `non-effective-claims-count-as-live-evidence` (saved_query.rs)

`live_claim_body` accepted any `lifecycle == Active` claim — an unapproved
`Proposed` claim, a `stale` derived claim, or a claim outside its valid-time
window all entered the evidence and could satisfy the filter. The harm chain
ends at consent-gated outbound.

`effective_claim_body` now applies `claim_effective_at` = `claim_surfaceable`
(the engine's canonical read-admission predicate: `Auto|Approved` ∧ `Active` ∧
`!stale`) plus the `comm.rs` valid-time window, and `EvaluationRequest.valid_at`
is threaded into evidence collection.

Tests: `only_effective_claims_satisfy_the_stage_one_filter` (oracle, four
arms), `only_effective_claims_count_as_evidence` (unit).

### P2-5 `definition-version-cas-is-not-atomic` (saved_query.rs)

`update`/`archive` compared `expected_definition_version` in a read txn and
then opened a separate write txn. LMDB's single-writer rule serializes the
WRITES, not a compare performed outside them, so two writers both reading v1
both stored "v2" and the first update vanished silently.

Both doors now run load → compare → validate → store inside ONE
`with_write_txn` (`owned_record_in_txn` / `store_record_in_txn`). The module
already did this correctly for the epoch watermark; the pattern was available.

Test: `concurrent_updates_cannot_both_win_the_version_cas` — two threads, both
believing v1, exactly one winner and the loser gets `ConcurrentWrite`.

### P2-6 `pack-repair-bypasses-definition-write-door` (saved_query.rs)

`apply_pack_migration` built its replacement from the CALLER's snapshot, forced
lifecycle `Active`, and never validated. Three defects, one chokepoint:

- The replacement is built from the STORED record, and a `definition_version`
  that moved since the repair was planned returns `ConcurrentWrite` instead of
  reverting the owner's update.
- An `Archived` query is not reopened — repair returns `InvalidConfig`.
- The migrated definition goes through `validate_definition`; a rewrite target
  like `""` or `"top_k"` PAUSES the query (the ladder's own "no viable rewrite"
  rung) rather than being persisted as an active definition nobody authored.

Test: `pack_repair_respects_the_definition_write_door` (all three arms).

### P2-7 `pack-drift-result-depends-on-predicate-order` (saved_query.rs)

`repair_pack_drift` returned on the FIRST semantics-changing or unmapped
predicate, so `[SemanticsChanging, unmapped]` returned `ProposalRequired` and
left a broken query Active while the reverse order returned `Paused`. The whole
affected set is now classified before a rung is chosen, and the rungs are
applied worst-case-first — the contract the docstring already claimed.

Test: `pack_drift_rung_does_not_depend_on_predicate_order` (both orders).

### P2-8 `semantic-verdict-hash-uses-different-snapshots` (saved_query.rs)

`semantic_fingerprints` read the vectors, then `semantic_decision` re-read both
through `Vault::get_vector` — each its own read transaction. A write landing
between them stored a verdict derived from new vectors under the old vectors'
hash, and a later revert produced a false memo hit.

`collect_evidence` now returns `CollectedEvidence`, carrying the vectors the
fingerprints were taken from. `semantic_decision` is a free function that takes
NO vault, so a re-read cannot creep back in — the signature is the enforcement.

Tests: `semantic_matcher_scores_the_fingerprinted_snapshot` (oracle),
`semantic_decision_scores_the_fingerprinted_vectors` (unit).

### P2-9 `relevant-evidence-projection-is-lossy` (saved_query.rs)

Both halves:

- `evidence_to_json` inserted `Vec<(String, Value)>` into a predicate-keyed
  object, so two live values for one predicate showed the judge only the last
  while the hash covered both. Claims are now PAIRS, like edges.
- `rmpv_to_json` mapped `Binary` to an untagged hex string, so `Binary([0x61])`
  and the literal `"61"` produced identical JSON. `Binary` and `Ext` now carry
  `$`-tagged wrappers, a real map key starting with `$` is escaped by doubling,
  a non-UTF-8 MessagePack string is tagged as bytes instead of collapsing to
  null, and a map with non-string keys becomes `{"$map": [[k, v], …]}` instead
  of having those entries silently dropped. The projection is injective, which
  is what the memo key needs it to be.

Tests: `judge_evidence_preserves_every_live_claim_value`,
`rmpv_projection_is_injective_across_types` (unit).

### P2-10 `zero-wake-bounds-are-not-enforced` (saved_query.rs)

`validate_definition` now rejects a zero `max_entities_per_wake` or
`max_judges_per_wake`: a zero-judge wake still spent the first judge before the
post-increment check stopped it, and a zero-entity wake reported
`evaluated = 0` with `resume_after = None` — documented to mean "exhausted".
Separately, `resume_after` now tracks the last entity actually VISITED instead
of `index.wrapping_sub(1)`, which reported `None` at index 0.

Tests: `zero_wake_bounds_never_reach_a_stored_definition` (oracle),
`zero_wake_bounds_are_rejected_at_the_write_door` (unit).

### P2-11 `crm-pack-registration-can-commit-half-a-pack` (campaign.rs)

`register_structural_kind` commits per call and is non-idempotent, so a bad
SAVED_QUERY byte left CAMPAIGN durable and made whole-pack retry fail on the
campaign collision — the docstring's "cannot install half a pack" contradicted
its own next sentence. Since the registrar cannot be composed into one
transaction from here, two properties make the guarantee real:

- **Both slots are vetted before either is written** (`vet_pack_slot`: CRM band
  + byte already held by something that is not this slot; two equal bytes are a
  collision). The ordinary misconfiguration never half-installs anything.
- **The call is resumable** (`register_pack_slot`): a slot already registered to
  exactly this pack's kind is reused, so re-running the one entry point after
  any partial failure converges instead of colliding with itself.

Test: `crm_pack_registration_never_leaves_half_a_pack`.

### P3-12 `packet-claims-violation` — PACKET_AMEND, folded

`WORKLOG-ONE-1773.md` was REJECTED as a violation (wave convention — main
carries `WORKLOG-ONE-*.md` from every merged lane). The real half was
`crates/oneiron/src/saved_query/tests.rs`, an unclaimed new source file. The
blueprint permits private tests "under `#[cfg(test)]` in `saved_query.rs`", so
the module was folded inline and the file deleted — no amendment needed, no
work burned. `git diff --name-only origin/main...HEAD` is now exactly the four
manifest paths plus the worklog.

### Gates

`cargo fmt -p oneiron --check` clean · `cargo clippy -p oneiron --all-features
--all-targets` zero warnings · `cargo test -p oneiron --all-features` green
(22 saved_query unit + 29 oracle + full suite). No `Cargo.toml` / `Cargo.lock`
change; `campaign/claims.rs`, `registry.rs`, `store.rs`, `vault.rs`, `claim.rs`
and `gate.rs` remain untouched non-claims.

Base-red note: the lib suite on this branch base flakes ONE test per full
parallel run under `-j 6 --test-threads` default — observed
`batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`
(clock-second boundary) with this lane's changes and
`embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`
on the pre-fix tree with the changes stashed. Both pass in isolation, both live
in files this lane never touches, and the suite is green at
`--test-threads=6`. Charged to no lane.
