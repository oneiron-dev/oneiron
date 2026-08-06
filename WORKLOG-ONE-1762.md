# WORKLOG — ONE-1762 [ED-06] escalation rulings + standing policy

Branch `ONE-1762`, cut from `origin/main` @ `b3c1fd756` (ED-05 #609 merged).
Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1762.md`.

## What landed

| file | change |
|---|---|
| `crates/oneiron/src/edit_distance/escalation.rs` | NEW — the whole ticket |
| `crates/oneiron/src/edit_distance/escalation/tests.rs` | NEW — 20 unit tests |
| `crates/oneiron/src/edit_distance.rs` | `pub mod escalation;` |
| `crates/oneiron/src/receipt.rs` | 8 escalation field-key consts + ONE projector registration line |
| `crates/oneiron/src/lib.rs` | re-export block |

`policy_model.rs` NOT touched — see deviation D1.
`tests/effect_spine_oracle.rs` NOT touched (SPINE-COMM-owned). `settings.rs` NOT
touched. `Cargo.toml` / `Cargo.lock` NOT touched (`Cargo.lock` was already dirty
in the worktree at cut time and was deliberately left unstaged).

## Shape as built

Three surfaces, all in `escalation.rs`:

1. **Ledger** — `record_escalation(vault, EscalationReceipt) -> Result<EntityId>`.
   Rows in `vault_meta` under `edit_distance/escalation/v1\0 ‖ scope_key(16) ‖
   row_id(16)`: scope-major (one scope's history is a contiguous range), row id
   is a UUIDv7 so key order is WRITE order and a caller-supplied `at` never
   reorders "the newest N".
2. **Aggregation** — `escalation_stats(vault, scope, trigger)`; counts plus the
   newest `ESCALATION_LAST_RULINGS_BOUND = 8` rulings returned oldest-to-newest.
3. **Standing policy** — `maybe_propose_standing_policy` /
   `standing_policy_for` / `accept_standing_policy`, keyed
   `edit_distance/escalation_policy/v1\0 ‖ scope_key(16) ‖ trigger_byte(1)`.

Receipts are PROJECTIONS of those rows (the house law from `delta.rs`:
"receipts are projections, not stored rows"), in the existing `ReceiptKind::Gate`
family — no new kind. Two receipt-id prefixes discriminate inside the kind:
`escalation:` (a ruling) and `escalation_policy:<hex>.{proposed,accepted}`.

Amend rulings store exactly the bytes `AmendmentDelta::encode()` produced and
read back through `AmendmentDelta::decode` — same bytes, same decode — and
project into ED-01's own `FIELD_AMENDMENT_DELTA` slot in the same hex spelling
`delta::attach_amendment_deltas` writes. One delta language, down to the field
key. (No collision with that pass: it filters `outcome == "approved_amended"`,
which no escalation receipt carries.)

## Blueprint deviations (declared, not absorbed)

**D1 — `policy_model.rs` left untouched. REASONED REJECT of the packet's
optional allowance.**
The blueprint says the standing row "rides `policy_model.rs` row shapes (prior
art: policy classify/help routing rows)". Ground check: `policy_model.rs` is
OF-333 content classification. Its `PolicyRubricRow` is assembled at call time
from `PolicyManifestResolution` (`rubric_rows` / `rubric_rows_floor_only`,
policy_model.rs:1762-1808) — there is no persistence layer, no key, no
`(scope, trigger)` axis, and nothing an escalation standing row could reuse but
the words `row_ref`. Adding an escalation row type to a 2308-line
content-policy module for zero reuse would put ED's storage schema in the wrong
module and add a fan-in edge that buys nothing.
What the citation actually asks for IS honored: `StandingPolicy` carries a
`row_ref` handle plus a typed ruling, exactly the `PolicyRubricRow` /
`PolicyRewordFeedback` shape. Storage rides the same-lane prior art instead —
`edit_distance/graduation.rs`'s `vault_meta` prefix + `rmp_serde::to_vec_named`
+ `ROW_VERSION` idiom (ED-05, ONE-1761), which is closer in every dimension.
PACKET_AMEND candidate: strike `policy_model.rs` from ED-06's claim slice. It is
an allowance not exercised, so no other lane is affected either way.

**D2 — one line in `receipt.rs` beyond "field-key consts".**
The blueprint's persistence claim ("escalations persist as `ReceiptKind::Gate`
receipts") is only TRUE through the public `vault.receipts()` door if the
projector is registered. So `collect_receipt_records`'s Gate arm gains one
`records.extend(...)` call (+ a 4-line comment), beside the gate-decision and
ramp projectors it now sits with. Purely additive, no signature or behavior
change to anything existing — but it is past the literal packet wording, so it
is declared here rather than absorbed.

**D3 — the budget band rides the row's CEILING, not the row KEY.**
Blueprint §3: "for the `budget` trigger, the stable-pattern key includes a
magnitude band". The ratified read signature (`standing_policy_for(scope,
trigger)`, SPINE-COMM-R2-A 2026-08-01) has no band axis, so a band-partitioned
key family could not be read through it. Built instead as: ONE row per
`(scope, trigger)`, carrying `budget_band_ceiling`. The invariant the blueprint
was protecting is preserved exactly and is tested — "N identical approvals of
small asks never mint a policy covering a larger band" — because the ceiling is
the **minimum** band across the N citing rulings, i.e. the largest band EVERY
one of them covered. A window of `[10, 10, 1000]` mints a ceiling of 10, not
1000: one approval at a magnitude is not N approvals at it.
Coverage is decided in one place, `StandingPolicy::covers_ask(ask_band)`, so
ES-07 consults a decision rather than re-deriving the comparison.

**D4 — additions to the blueprint's skeleton.** All additive, none replacing a
specified item:
- `StandingPolicy.scope` / `.trigger` / `.cited_receipts` — the row must be
  self-describing for `covers_ask` to be decidable and for "the row cites its
  source receipts" (blueprint §3) to be real rather than narrative.
- `StandingPolicy::covers_ask` — the band chokepoint (see D3).
- `escalation_standing_n` / `set_escalation_standing_n` +
  `ESCALATION_STANDING_N_KEY` + `DEFAULT_ESCALATION_STANDING_N = 3` — the
  blueprint's "N settings-backed" dial, as a per-feature key const over
  `vault_meta` per the relay's `settings.rs`-NEVER rule.
- `is_escalation_receipt` / `is_standing_policy_receipt` — the `Gate`-family
  discriminators, matching ED-05's `is_graduation_answer_receipt`.
- `EscalationTrigger::{ALL, from_token}`, `EscalationRuling::{as_str, delta}`,
  `StandingPolicyStatus::as_str` — pinned tokens and the closed-enum iterator.

## Judgment calls worth a screener's attention

- **`budget_band` on a non-budget trigger is a typed REJECT**, not a silently
  ignored field. An aggregation that ignored it would let a meaningless number
  look like evidence.
- **`StandingPolicyStatus` is derived from `accepted_at`, never stored.** Two
  spellings of one fact are two things that can disagree.
- **Acceptance projects a SECOND receipt** rather than rewriting the proposal
  receipt: the offer and the acceptance are separate acts. Re-accepting is an
  idempotent no-op that keeps the original acceptance time.
- **`standing_policy_for`'s `Err` arm is load-bearing** — an undecodable row is
  UNCERTAINTY, not absence; ES-07 maps it to escalate. Tested by corrupting a
  live row.
- **Agreement includes the Δ**: two amendments that changed different things are
  two answers, not a pattern.
- **`escalation_stats` scans a scope's whole range uncapped** — counts are not
  derivable from a prefix, and the range walked is one scope's rows, not the
  family's. The receipt PROJECTORS are capped at `MAX_RECEIPT_QUERY_SCAN` and
  walk newest-first, for ED-05's reason: neither family drains, so an
  oldest-first cap would permanently hide recent decisions.
- **`needs_input` / OF-390 untouched** — ED-06 stores what came back; no
  ask-routing was built.
- **ES-07 (ONE-1720) has NOT landed**: `effect_spine_oracle.rs`'s
  `classify_fan_out_ask` / `apply_escalation_ruling` /
  `count_pending_escalations` are still `unimplemented!()`. So there was no
  inline shape to migrate — this is the greenfield schema 1720 will consume.
  The oracle file was not touched.

## Gates

- `cargo fmt -p oneiron` — clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` — clean.
- `cargo test -p oneiron --all-features` — **exit 0**; lib `3717 passed; 0
  failed; 17 ignored`, every integration target and both doctests green.
- 20 new unit tests in `edit_distance::escalation::tests`, all green.

### Flake note (charged to no lane)

The FIRST full run showed one unrelated red:
`bm25::tests::bm25_diagnostics_increment_for_targeted_search_corruption`.
Pre-existing test-isolation defect: it reads a PROCESS-GLOBAL counter
(`bm25_diagnostics_snapshot()`) and asserts `before_malformed + 1`
(`crates/oneiron/src/bm25/tests.rs:1889-1920`), so any concurrent test
incrementing `MalformedPostingAlignment` between the two reads flips it.
Nothing in this packet can touch a bm25 diagnostic; adding 20 tests only
perturbed the harness schedule. Passed in isolation, and passed on the re-run
per the flake guard. Not fixed here — it is another packet's file.
