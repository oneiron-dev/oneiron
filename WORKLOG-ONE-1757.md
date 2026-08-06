# WORKLOG — ONE-1757 [ED-01] amendment-delta capture + approve-with-edit

Branch `ONE-1757` off `origin/main` @ `e356021e0` (1756 #599 + 1747 #569 + 1789 #602 merged).
Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1757.md` · Claims: `ED/CLAIMS.md`.

## What landed

| file | what |
|---|---|
| `crates/oneiron/src/edit_distance/delta.rs` **(new)** | Δ schema (six ARCH-0056 §2 fields), both capture lanes, the r2 chooser, the Δ side-ledger + receipt attachment, and the identity-topology projection pass |
| `crates/oneiron/src/edit_distance/delta/tests.rs` **(new)** | 16 unit tests |
| `crates/oneiron/src/edit_distance.rs` | `pub mod delta;` |
| `crates/oneiron/src/inbox.rs` | `accept_member_with_amendment_in_txn` + public `Vault::approve_inbox_member_with_edit(_at)` + `InboxAmendedApproval` |
| `crates/oneiron/src/inbox/tests.rs` | 7 door tests |
| `crates/oneiron/src/receipt.rs` | `FIELD_AMENDMENT_DELTA` → `pub(crate)`; ONE additive attach call in `collect_receipt_records` |
| `crates/oneiron/src/llm.rs` | `canonical_json_bytes` → `pub(crate)` (one word, no logic) |
| `crates/oneiron/src/error.rs` | additive `DeltaCaptureUnavailable(&'static str)` + `ErrorKind` arm — **PACKET_AMEND candidate, see below** |
| `crates/oneiron/tests/merge_split_oracle.rs` | ms05 NEG polarity flip (declared seam) + 3 new seam fns + header arming note |

`lib.rs` NOT touched: ED-00 chose not to flat-export `edit_distance`, so consumers reach
`oneiron::edit_distance::delta::…` through the existing `pub mod`. One fewer high-fan-in file
in the packet; the blueprint's "lib.rs re-exports" line was not needed.

## Design decisions worth a reviewer's attention

**Where a Δ lives.** Receipts are PROJECTIONS, not stored rows, so a Δ cannot be stamped onto
one after the fact — and `gate_decision_receipt` / `proposal_outcome_receipt` are pure
projectors whose signatures 1747 explicitly reverted a change to (its FIX2). So the Δ gets its
own `vault_meta` row keyed by RECEIPT ID, and ONE additive pass at the single convergence point
(`collect_receipt_records`) folds it into the reserved slot for receipts whose outcome is
`approved_amended`. Consequences: zero projector-signature churn, both amendment doors served by
one hook, and the common query pays no lookups (the outcome filter gates them).

**No MS-file edits.** `project_identity_amendment_deltas(vault)` reads back through PUBLIC
receipt surfaces only — `vault.receipts()`, `proposal_outcome_amended_body`, `trigger_ref` — then
re-encodes the proposal's op through the same `encode_identity_op_amendment` door the amended
body rode, so both sides of the diff are comparable shapes. `identity_topology.rs` is untouched.

**Amendment scope at the inbox door.** The amended body must keep the reviewed claim's
**predicate and subject**. That pair is not decoration: `classify_member` derives the exception
classes from it (manifest-critical, supersedes-user_stated) and `claim_consent_binding_parts`
binds consent to it, so an amendment that moved either would land a claim under a classification
that never described it. Everything else (value, confidence, validity, scope) is what an edit is
for. Approval is forced to `Approved` by the engine — a submitted body asserting its own
approval decides nothing. Reserved predicates cannot be smuggled in: the predicate must equal the
reviewed one, and a reserved predicate could never have been the public proposal's.

**Consent binding is checked against the REVIEWED body**, then the amended body replaces it.
Consent was given on that content; the edit is the decider's own. The stale-binding check is
inherited unchanged from `accept_member_in_txn` — which is now a one-line wrapper over the
amendment variant, so there is ONE implementation of the redemption path, not two.

**Δ normalization is measured on approval-normalized bodies** (both sides forced to `Approved`
before encoding), so the door's own approval flip is not counted as the decider's edit.

**Both lanes' numbers are comparable.** `d_norm = clamp(edit_mass / (len_before + len_after), 0, 1)`
with `edit_mass = ins + del`; `moved` is the pinned discount channel — a producer that DETECTS a
move records the run length there and leaves it out of ins/del, so "moves discounted" is
structural rather than an arithmetic correction. No lane here detects moves (`moved == 0`);
ED-02's Myers pass is the first producer that can fill it.

## Blueprint deviations (declared, none silently absorbed)

1. **`AmendmentDelta::encode` returns `Result<Vec<u8>>`, not `Vec<u8>`.** The blueprint skeleton
   pins the bare return. Serialization of a hand-built Δ whose `d_norm` is non-finite genuinely
   fails (JSON has no NaN) and the struct's fields are `pub`. House pattern is `encode_*() ->
   Result<Vec<u8>>` (cf. `encode_claim_body`); the alternative was a panic or a silent zero.

2. **The inbox lane's receipt is a GATE receipt, not a "proposal-outcome receipt".** Blueprint §3
   says the door "emits the proposal-outcome receipt with `outcome=approved_amended`". In the
   landed engine a proposal-outcome receipt is projected exclusively from an identity-topology
   type-76 resolution event (MS-owned); an inbox claim approval produces a `GateDecisionRecord`.
   Implemented on the gate receipt with `outcome = "approved_amended"` and reason
   `gate.consent.amend_accept`, so the Δ attach pass and every outcome filter treat both doors
   alike. No MS file was edited to force the other shape.

3. **Blueprint's "capture-error field" is a receipt REASON, not a new receipt field.**
   `receipt_reasons` already projects to `fields["receipt_reason"]` + `policy_trace`, so
   `gate.consent.amend.delta_uncaptured` needed no receipt.rs surface at all.

4. **Done-means "test with a corrupt `proposed_ref`" adjusted.** At the inbox door the corrupt
   case is UNREACHABLE: both bodies are `encode_claim_body` output of door-validated
   `ClaimBody`s, so `delta_from_field_diff` cannot fail there. Rather than fake an injection, the
   non-fatal contract is tested at its chokepoint — `captured_amendment_delta(b"\x91", b"\x91")`
   returns `(None, [marker])` — plus `delta_from_field_diff` rejecting truncated and
   trailing-byte bodies directly. The posture is stronger than the blueprint assumed, not weaker.

5. **NEG-test flip renamed.** `ms05_delta_field_is_reserved_opaque_not_built` →
   `ms05_amendment_body_stays_opaque_while_ed01_fills_the_reserved_delta_slot`: the old name
   asserts the opposite of what the ticket builds. Every inherited assert carried over
   unweakened (byte-exact opaque `amended_body` round-trip), and the flip is recorded in the
   oracle module header per arming discipline. A second test
   (`ms05_unamended_outcomes_carry_no_delta_after_the_projection_pass`) pins that untouched and
   rejected outcomes still carry no Δ after the pass runs — the contract
   `ms05_amended_receipt_carries_delta_others_do_not` protects, now extended to the reserved slot.
   The flipped test also proves the two-slot contract holds: the producer artifact is byte-exact
   AFTER the projection wrote the reserved slot.

## PACKET_AMEND candidates

1. **`crates/oneiron/src/error.rs`** — not in the declared packet. Added ONE variant
   `DeltaCaptureUnavailable(&'static str)` + its `ErrorKind` arm (2 additive insertions, no
   existing line changed). The blueprint requires the reconstructed arm to return "a typed
   NotAvailable"; the alternatives were misusing `IdentityTopologyUnarmed` (wrong domain, and
   `ErrorKind` is public API others match on) or string-sniffing. error.rs is already
   multi-lane-additive this wave (1919's `InvalidSecretCustodyBody` et al.), variants append at
   the end of their block → merge-tolerant. **No collision expected; requesting ratification.**

2. **`crates/oneiron/src/receipt.rs`** — declared as "field-key consts ONLY". Landed: the const
   visibility lift (in scope) PLUS one additive call line + comment in `collect_receipt_records`.
   No signature changed, no projector refactored, no existing line rewritten. Without it the Δ
   cannot reach the receipt at all and done-means #1 is unmeetable. **Requesting ratification of
   the one-line widening.** 1748 is also in flight on receipt.rs; both touches are in distinct
   additive regions (its projector block vs. the const table + the tail of
   `collect_receipt_records`) — merge-in tolerant.

## Done-means

- [x] Amended inbox approval persists the amended body (read-back differs from proposed, matches
      the amendment) and emits an `approved_amended` receipt whose Δ decodes with all six fields —
      `approve_with_edit_persists_the_amended_body_and_receipts_the_delta`.
- [x] Untouched approval: no Δ — `an_untouched_approval_carries_no_delta`;
      `ms05_amended_receipt_carries_delta_others_do_not` still green.
- [x] `recorded_ops` lane: two-change window, `ops_summary` matches the known edit script
      (ins 10 / del 4 / kept 11), `d_norm` = 0.5 ∈ [0,1], `source=recorded_ops`.
- [x] `field_diff` lane: changed-leaf counts in `ops_summary`, `source=field_diff`, full [0,1]
      range pinned at both ends.
- [x] Oracle NEG test flipped; six Δ names projected; header arming note recorded.
- [x] Δ-capture failure path: non-fatal, marker recorded — see deviation 4 for the honest shape.
- [x] No `ClaimApprovalStatus` variant added; `claim.rs` untouched.
- [x] Gates: `cargo fmt` · `cargo clippy -p oneiron --all-features --all-targets` clean ·
      `cargo test -p oneiron --all-features` **3586 passed / 0 failed / 17 ignored**.

## Flake note (charged to no lane)

Seven suite runs: **4 fully green (3586 passed / 0 failed / 17 ignored)**, 3 with exactly ONE red
— a DIFFERENT test each time, each in a module this packet never touches:

- `embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`
- `bm25::tests::bm25_diagnostics_increment_for_targeted_search_corruption`
- `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`

All three pass in isolation, and all three assert on process-global counters/sidecar state — the
known parallel-contention shape, aggravated here by nine lanes sharing the box. A deterministic
regression from this diff would fail the SAME test every run. Pre-existing flake, not a lane
regression; the last two consecutive full runs were green.

## Notes for downstream ED tickets

- `capture_delta_best` is the ONLY call site production rides; ED-02 (1758) fills the
  `Reconstructed` arm and rewires nothing.
- `delta_from_recorded_ops` uses a prefix/suffix span per recorded change. That is a lower bound
  on scattered edits (it under-counts `kept`, never under-counts ins/del). ED-02's Myers pass is
  what resolves them exactly, and is also the first producer that can populate `moved`.
- `MAX_FIELD_DIFF_DEPTH` bottoms out deep nesting as one opaque leaf: the number degrades, the
  process does not. `delta_from_field_diff` is `pub` and takes raw bytes, so it must survive
  nesting the caller did not choose.
- ED-08's outbound-draft lane rides the same `capture_*` fns: nothing in this module knows about
  claims or identity topology.
