# WORKLOG — ONE-1772 [CA-01] crm claim families + ClaimClassDescriptor rows

Lane: CA · Chain CA-A, layer L2 of 4 (`1771 → 1772 → 1773 → 1774`).
Worktree: `/Volumes/Cinema/w5-lt/ca` · Branch: `ONE-1772`.
Base: `59a4301` (current `origin/main` at cut time).

## Base selection

Brief said "cut off the CURRENT tip (parent CA-1771 already merged at 6b07ced)".
Cut from `origin/main` @ `59a4301` rather than `6b07ced`, because both blocking
writer-order predecessors are ancestors of the current tip and NOT of `6b07ced`:

- `8fb98e6` ONE-1782 [CAL] — `claim.rs` writer order **1782 → 1772**.
- `7978e74` ONE-1728 [L1-STORAGE-SPINE] — `gate.rs` order **1772 → 1777 → 1868**,
  never before 1728 merges.

`6b07ced` (ONE-1771, PR #571) is an ancestor of `59a4301`, so the parent layer is
present. Cutting from `6b07ced` would have taken `gate.rs` at a pre-1728 shape.

## What landed

### `crates/oneiron/src/campaign/claims.rs` (CREATE)

Single home for the CRM pack's six exact predicates. `comm.do_not_contact`,
`comm.bounce`, and `comm.jurisdiction` live here — not in `comm.rs` — per the
comm-residence seam; `comm.rs` is untouched (file oracle below).

- Constants + `CAMPAIGN_PACK_CLAIM_PREDICATES` (exact table, never a prefix).
- Typed values: `CampaignMemberValue` / `CampaignMemberState` /
  `CampaignMemberChannel` / `CampaignMemberDerivation`, `CrmFitValue`,
  `CrmStageValue` (+ `StageKey`, `StageEvidenceClass`, `EvidenceBasis`),
  `CommDoNotContactValue`, `CommBounceValue`, `CommJurisdictionValue`.
- `validate_campaign_pack_claim_structure` — exact key sets, no extras, no
  back-compat defaults (greenfield families have no legacy shape to admit).
- `claim_class_descriptors()` — six pure-data rows, spelled out; no runtime, no
  registry, no persistence side effect.
- `resolve_crm_fit` — restrictive fold, `NotFit` wins.
- `supersede_crm_stage` — predicate + subject + campaign-scope + current-head
  check and the swap in ONE write txn; every rejection precedes the first write.
- `do_not_contact_applies` + `matching_do_not_contact_in_txn` +
  `counterparty_do_not_contact_in_txn` — the gate's enforcement read.

### `crates/oneiron/src/claim.rs` (MODIFY)

Family branch inserted ahead of `crate::comm::is_comm_claim_predicate`, exact
match only. No `campaign.` / `crm.` / `comm.` catch-all.

### `crates/oneiron/src/gate.rs` (MODIFY)

`hydrate_external_effect_contact` now folds `comm.do_not_contact` into
`counterparty_opted_out` with `|=`, AFTER the existing type-132 contact-record
read. Two shape notes:

1. The early return was narrowed from `(channel_identity_ref, counterparty)` to
   `counterparty` alone. The contact-record block still requires both, so its
   behaviour is unchanged; the DNC leg additionally runs for counterparties with
   no channel identity — which is exactly where the type-132 read contributes
   nothing. `comm.do_not_contact` is campaign- AND identity-independent by
   construction (no campaign field in the value), so scoping it to
   identity-bearing effects would have been a hole.
2. `|=` is load-bearing: the leg can only ADD suppression. Proven both ways in
   `do_not_contact_matching_claim_denies_external_effect`.

Channel = `effect.channel`, scope = `effect.verb`.

### Tests

- `src/campaign/claims/tests.rs` (CREATE) — 11 tests, one per done-means plus a
  serde/rmpv token drift guard.
- `tests/campaign_claim_gate_oracle.rs` (CREATE) — 3 tests proving the same
  suppression through the PUBLIC shipping path only
  (`Vault::dispatch_outbound_intent`), so a refactor that keeps the internal
  helper honest while detaching it from the send pipeline still fails.

## Blueprint deviations (3)

1. **`CrmStageValue` does not derive `Serialize`/`Deserialize`.**
   Not buildable: `EntityId` has no serde impl, and `entity_id.rs` is a CA
   non-claim, so the derive cannot be satisfied without a foreign-file edit.
   The three token types it composes (`StageKey`, `StageEvidenceClass`,
   `EvidenceBasis`) DO derive serde, so ONE-1775/ONE-1778 still get the tokens
   without re-spelling them. `crm_stage_wire_tokens_match_serde` pins the rmpv
   tokens equal to the serde representation so the two can never drift.

2. **`resolve_crm_fit` takes `icp_scope` as a parameter.**
   Blueprint signature was `resolve_crm_fit(claims) -> Option<CrmFitVerdict>`
   with scope isolation left to the caller. That makes the done-means
   "unrelated ICP scopes do not contaminate each other" untestable against the
   function — the test would only be testing its own filter. Scope is now a
   property of the chokepoint. Signature:
   `resolve_crm_fit(icp_scope: &EntityId, claims: &[CrmFitValue])`.
   (The slice, rather than `impl IntoIterator<Item = &'a CrmFitValue>`, is
   forced by the workspace `-D single-use-lifetimes` lint colliding with
   unstable anonymous lifetimes in `impl Trait`.)

3. **`resolve_do_not_contact_subject_in_txn` reads SPINE-COMM's node-local
   party shortcut.** The blueprint says to resolve the PERSON from
   `effect.counterparty` but no engine call does this, and `comm.rs` is a hard
   CA non-claim so the private `resolve_party` could not be reused. The read
   mirrors the `comm.party.v1:` vault_meta key and then RE-VALIDATES the hit
   against synced truth (row must still be a PERSON carrying exactly that
   `party_key`), so a stale shortcut resolves to NOTHING rather than to the
   wrong person. A miss returns `Ok(None)` → the leg contributes nothing and
   never clears. Explicitly the interim posture: **ONE-1868 owns the complete
   resolution** (all matching contacts by `(party_ref, channel_class)`, index
   repair, full-scan fallback, no false-negative "no"). Known gap handed to
   1868: a merged-away PERSON twin still carrying the `party_key` is not
   followed to its survivor — `entity_lifecycle_state_in_txn` is a `Vault`
   method and the gate hydration has only `&Store`.

## Main-repair carried in this diff (needs owner note)

`claim.rs` was missing the `calendar.*` family branch. **ONE-1782's validator
wiring was dropped when that PR was redone** (`8fb98e6`, redo of sandbagged
#561): `calendar/claims.rs` landed complete but nothing ever called
`validate_calendar_claim_structure`.

Live consequences on `59a4301`, all verified before touching anything:

- `calendar.*` claims reached storage **completely unvalidated**.
- 3 tests RED on main: `calendar::claims::tests::calendar_claims_require_event_subjects`,
  `calendar::claims::tests::calendar_claim_validator_rejects_malformed_shapes`,
  `claim::tests::write_door_validates_calendar_claim_structure`.
- ~40 `-D dead-code` clippy errors (the whole module's private helper chain).

Fixed by restoring the two-line branch. Justification for doing it here rather
than deferring: `claim.rs` is a ONE-1772 MODIFY claim and the writer order names
this ticket the next writer after 1782, so the repair is packet-internal; and
the lane's own cheap gate (`clippy -D warnings`, full suite) is otherwise
unreachable. Flagging for the deviation board because it restores another
ticket's done-means.

## Cheap gate

| Gate | Result |
|---|---|
| `cargo fmt --all --check` | clean for every file in this diff |
| `cargo clippy -p oneiron --all-targets --all-features -- -D warnings` | clean for every file in this diff |
| `cargo test -p oneiron --all-features --lib campaign` | 16 passed / 0 failed |
| `cargo test -p oneiron --all-features --lib calendar` | 18 passed / 0 failed |
| `cargo test -p oneiron --all-features --lib comm::` | 47 passed / 0 failed |
| `cargo test -p oneiron --all-features --lib claim::` | 34 passed / 0 failed |
| `cargo test -p oneiron --all-features --test campaign_claim_gate_oracle` | 3 passed / 0 failed |
| `cargo test -p oneiron --all-features` (full) | lib **3388 passed / 0 failed** / 17 ignored; every integration binary green |

### Pre-existing base defects NOT fixed here (charged to no lane)

1. `crates/oneiron/src/lib.rs` is rustfmt-dirty at `59a4301` (a `receipt`
   re-export block, unrelated to this ticket). Verified by stashing this branch
   and re-running `cargo fmt --all --check` on the bare base. `lib.rs` is a
   ONE-1771/ONE-1773 claim, not this ticket's, so the fix is left alone and the
   repo-wide `--check` still reports that one file.
2. `crates/oneiron/src/secret_custody.rs:625 reject_secret_custody_byte` is dead
   code → one `-D dead-code` clippy error. Present at `59a4301`,
   `secret_custody.rs` is a CA non-claim (L1-SECRET). Left alone.

### Flake observed once

First full-suite run had
`attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`
fail with `cleanup span records=[]` (global tracing-subscriber contention under
full parallelism). Passes in isolation and passed on the clean full re-run.
Nothing in this diff touches `attempt_queue` or tracing.

## Packet check

`git diff --name-only` against the base is exactly:

```
crates/oneiron/src/campaign.rs           MODIFY (claimed)
crates/oneiron/src/campaign/claims.rs    CREATE (claimed)
crates/oneiron/src/campaign/claims/tests.rs CREATE (claimed)
crates/oneiron/src/claim.rs              MODIFY (claimed)
crates/oneiron/src/gate.rs               MODIFY (claimed)
crates/oneiron/tests/campaign_claim_gate_oracle.rs CREATE (claimed)
```

File oracle satisfied: the diff for `crates/oneiron/src/comm.rs` and
`crates/oneiron/src/registry.rs` is **empty**. `Cargo.lock` not committed. No
entity/type byte, no `EdgeKind`, no registry row, no descriptor runtime, no
second deny reason (`GateReasonCode::DenyCounterpartyOptOut` reused as-is), no
docs edits. No push, no merge.
