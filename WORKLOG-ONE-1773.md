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
