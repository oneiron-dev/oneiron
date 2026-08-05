# WORKLOG — Cluster A fix-forward on ONE-1728-ca-fix

Branch `ONE-1728-ca-fix` cut from worktree root `42cb5e6` (carries #566 ancestry through the redo lineage).
Worktree: `/Volumes/Cinema/w5-lt/spine-1728-ca`. Workers never push; orchestrator publishes above main tip `59a430183` after CY.

Union verdict fix-orders on this branch: CAL restore · ROUTE/lock/shell · SESSION-DOORS.

## FIX-CAL — calendar.* structural validation dispatch arm restored (seat Opus) — DONE

Finding: Qodo-4 + Codex-1 deduped. `validate_claim_body_and_decode` in
`/Volumes/Cinema/w5-lt/spine-1728-ca/crates/oneiron/src/claim.rs` chained thirteen predicate-aware
structural arms (edge.provenance … delivery_window) with **no calendar arm**, while
`crates/oneiron/src/calendar/claims.rs:10-13` documents `validate_calendar_claim_structure` as
"wired into the write-only validator chain in `crate::claim`". The wire was dropped in the
extraction redo.

### Ground truth (own the grep)

- Arm existed at `8fb98e642` (ONE-1782 [CAL], #573) as the **last** arm of the chain, after `delivery_window`.
- Removed at `42cb5e62b`; the squash-merge `7978e74c9` (#578) also lacks it → **the regression is live on main**, not branch-local.

### Red baseline (before fix), `cargo test -p oneiron --lib calendar`

    calendar::claims::tests::calendar_claims_require_event_subjects          FAILED
    calendar::claims::tests::calendar_claim_validator_rejects_malformed_shapes FAILED
    claim::tests::write_door_validates_calendar_claim_structure              FAILED
    13 passed; 3 failed

Every failure is `left: Ok(())` where a rejection was required — malformed calendar claims were
storing through the public write door.

### Fix

Restored the arm at its exact pre-removal position (last, after `delivery_window`):

    } else if crate::calendar::claims::is_calendar_claim_predicate(&body.predicate) {
        crate::calendar::claims::validate_calendar_claim_structure(&body)?;
    }

`validate_claim_body_and_decode` (doc comment + body) now diffs **byte-identical** to the
pre-removal `8fb98e642` version. Two added lines; no other file touched.

### Mutation verification

1. **Arm absent** (the red baseline above) → the 3 tests fail. Guard+call are load-bearing.
2. **Mutant A** — validator body stubbed to `if true { return Ok(()); }` with the arm present →
   the same 3 tests fail. Proves the *call* is load-bearing, not merely the `else if` guard
   (an arm that matched but no-op'd would not be caught by (1) alone).
3. **Arm-order safety** — the arm is last, so an earlier matcher intercepting a `calendar.*`
   predicate would leave it dead. Verified none can: every earlier matcher is exact-table
   `.contains()` or exact `==` (no prefix matching anywhere in the chain), and
   `rg '"calendar\.' crates/oneiron/src/ --glob '!calendar/**'` returns nothing — no foreign
   family table holds a calendar string. All 12 predicates reach the arm.

### Gates

- `cargo test -p oneiron --lib calendar` → 16 passed, 0 failed (3 previously-red now green).
- `cargo fmt --all -- --check` → clean.
- `cargo test -p oneiron` (full package) → **2984 passed, 0 failed**.
- `cargo clippy -p oneiron --all-targets --all-features` → 2 errors, both in
  `crates/oneiron/src/secret_custody/tests.rs` (`field-reassign-with-default`,
  `items-after-statements`). **BASE-RED**: reproduced identically on the clean base with my diff
  stashed. Outside this diff (my diff is `claim.rs` only), charged to no lane, quarantined per the
  base-red rule. Belongs to the L1-SECRET packet.

NEXT: FIX-ROUTE/lock/shell and FIX-SESSION-DOORS orders on this same branch (other seats).
