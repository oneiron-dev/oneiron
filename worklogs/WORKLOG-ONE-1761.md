# ONE-1761 [ED-05] — graduation thresholds + trust-table surface

Branch `ONE-1761` off `origin/main` @ `48ebcbc34` (ONE-1748 #603 merged — the
`consent_graduation.rs` handoff is cleared).

Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1761.md`
Claims: `/Users/olety/.claude-wave5/blueprints/ED/CLAIMS.md`

## Files touched

| file | disposition |
|---|---|
| `crates/oneiron/src/edit_distance/graduation.rs` | **NEW** — the whole ticket |
| `crates/oneiron/src/edit_distance/graduation/tests.rs` | **NEW** — 24 unit tests |
| `crates/oneiron/src/consent_graduation.rs` | policy-fn swap + snooze consult (declared handoff) |
| `crates/oneiron/src/edit_distance.rs` | `pub mod graduation;` |
| `crates/oneiron/src/lib.rs` | re-export block |

`settings.rs` untouched (key consts live in `graduation.rs` over `vault_meta`,
per the house `INBOX_REVIEW_DIAL_KEY` pattern). `receipt.rs` untouched.
`oneiron-server/src/projection.rs` skipped — see DEVIATION 5.

## Shape as built

Three surfaces, as specced:

1. **Threshold rows.** `ThresholdRow { scope_pattern, required_streak,
   posterior_guard }`, resolved for a scope by `graduation_policy_for`. Three
   sources feed ONE ranking (most literal axes first; on a tie, an
   owner-written row beats an engine-written one; remaining ties on the pattern
   string so the winner never depends on scan order):
   - runtime rows the owner writes (`set_graduation_policy` / `clear_…` /
     `graduation_policy_rows`),
   - MS-06's per-scope streak dial, entering as an exact-scope row (below),
   - the compiled table — exactly ONE catch-all row,
     `("*/*/*", DEFAULT_GRADUATION_STREAK_FLOOR = 12, DEFAULT_POSTERIOR_GUARD = 0.8)`.
2. **Posterior guard.** `posterior_lower_bound(wins, losses)` — Beta(1,1) prior,
   `mean − 1.645·σ` clamped to [0,1], σ = `sqrt(αβ/((α+β)²(α+β+1)))`. Local, ~8
   lines, no `critic.rs` import, no shared dep — bit-for-bit the formula SK-05
   (`skill_reliability.rs:241`) pins, so the two cannot disagree. Evidence is
   `(untouched_streak, amended + rejected)`: the current clean run against every
   correction the scope ever drew.
3. **Offer answer.** `answer_graduation_offer` (GoAuto | NotNow) → snooze ladder
   `7d → 30d → ManualPinned`, `unpin_scope` the only way out. State is REPLAYED
   from an append-only answer log — no stored projection, so no rebuild door and
   nothing that can drift. The same log is the receipt family.

Plus `trust_table(vault) -> Vec<TrustTableRow>` — scope, ramp state, MS-06
stats, effective threshold, snooze state, grant ref, `offer_is_earned`.

## Design rulings taken inside the blueprint

**Ramp state and snooze are ORTHOGONAL, not nested.** MS-06 marked `RampState`
`#[non_exhaustive]` anticipating that ED-05 would "add snooze / manual-pin
states". I did not add them, and the blueprint agrees with the decision it
implies: its `TrustTableRow` lists `ramp_state` and `snooze_state` as SEPARATE
columns. `RampState` answers *what authority is live*; snooze answers *are we
asking about it*. Consequences, all of them good:

- `Vault::graduation_offers()` (the "what should I surface" query) is the ONLY
  place suppression applies — one consult, one line.
- `accept_graduation_offer` needed no change: a snoozed or pinned offer is still
  `Offered` and still acceptable. Had snooze been a `RampState` variant, a
  snooze would have silently blocked the owner from saying yes — a wall I would
  have then had to special-case back out.
- `RampState` is untouched, so nothing downstream of MS-06 shifts.

**A dialed streak carries its own guard.** `set_ramp_streak_floor(scope, 2)`
composed against the catch-all guard of 0.8 would never fire — the owner's dial
would be a silent lie (and MS-06's own `a_per_scope_floor_overrides_the_compiled_default`
would have gone red). It enters resolution as
`ThresholdRow::for_dialed_streak` = `(exact_pattern, streak, lower_bound(streak, 0))`:
a spotless run of exactly the dialed length clears it, the same length with
corrections behind it does not. A dialed 0 becomes 1 (never a zero threshold),
and the trust table shows the row it became.

I built and then REMOVED a general "clamp every guard to reachability at its own
streak" rule. It is wrong: it makes the blueprint's own fixture inexpressible
(a row of `(streak 2, guard 0.6)` blocking 2/2 and passing 9/10 is exactly the
specced behaviour). A guard binding above its row's streak is the POINT — the
streak floors repetition, the guard floors evidence, either may be the one that
holds. Rows are now returned as written.

**Answer-log key order is WRITE order, not caller-clock order.** First cut keyed
answers by `at`; a test caught an `unpin` stamped earlier than the declines it
undid replaying before them and undoing nothing. Now keyed
`prefix ‖ scope.key() ‖ uuidv7`, which is MS-06's own law ("caller-supplied wall
time is DATA, never order") applied here. Pinned by
`unpinning_from_settings_restores_eligibility_and_resets_the_ladder`, whose
fixture declines across a synthetic future and unpins at the real clock.

**Fail-closed on unreadable policy.** A corrupt/illegal stored threshold row is
`Error::CorruptedIndex`, propagated up through `ramp_scope_state` and
`graduation_offers`. Read of the done-means "malformed row → typed error +
compiled fallback": the write door rejects malformed input with a typed error so
the compiled row STAYS in force (the primary reading, fully satisfied), and a
row that is already corrupt on disk errors rather than resolving to a threshold
nobody wrote. "Compiled fallback" applies to ABSENCE, never to corruption —
substituting a guess for an unreadable policy is how a zero threshold gets
surfaced silently.

## DEVIATIONS from the blueprint — all declared, none absorbed

1. **`OfferAnswer::GoAuto` carries `&AuthenticatedOwner`.** Blueprint sketch:
   `pub enum OfferAnswer { GoAuto, NotNow }` and
   `answer_graduation_offer(vault, scope, answer) -> Result<()>`. GoAuto mints a
   standing grant, which MS-06 (correctly, DEC-0006 invariant 5) will not do
   without an `AuthenticatedOwner`. Putting it in the VARIANT rather than in the
   signature keeps declining authority-free — requiring owner auth to say "not
   now" would be a wall — and makes invariant 5 type-enforced at this door too,
   which is the stated philosophy of the module family.
2. **Returns `OfferAnswerOutcome`, not `()`.** GoAuto produces a `ConsentReceipt`
   the MS-06 door already minted; dropping it on the floor would mean the caller
   cannot show the grant it just made. NotNow returns the new `SnoozeState`, so
   a settings screen can say "one more and I'll stop asking" without a second
   read. Two variants, no storage.
3. **`consent_graduation.rs` edits slightly exceed "policy-fn swap".**
   PACKET_AMEND candidates, itemised:
   - `ramp_receipts` gains ONE delegation line to
     `graduation::answer_receipts_in_txn` (on the caller's read txn, so no
     nested transaction). The alternative was registering a third projector in
     `receipt.rs` — NOT in my packet, high fan-in, and it would put ED-05
     keyspace knowledge in MS-06's module.
   - `accept_graduation_offer`'s body moved to a `pub(crate)`
     `accept_graduation_offer_in_txn`; the public method is now that function
     plus a transaction, behaviour byte-identical. ED-05 needs it so the owner's
     ANSWER and the grant land in ONE write txn — otherwise a torn write leaves
     a grant with no answer receipt.
   - three new `pub(crate)` seams: `ramp_floor_override_in_txn` (the old private
     `read_floor_in_txn`, now returning `Option` so ED-05 can tell an override
     from a default), `offer_is_standing_in_txn`, `ramp_stats_in_txn`.
     `active_grant_ref_in_txn` widened to `pub(crate)`.
   - `graduation_offers` rewritten in terms of `ramp_stats_in_txn` — a net
     simplification (one all-scopes scan, one place to get it wrong).
   No public MS-06 API changed shape; no MS-06 test was edited.
4. **`ramp_streak_floor` now reads the EFFECTIVE policy** rather than only the
   override keyspace. Left alone it would answer "12" while a pattern row was
   the thing actually deciding — a public reader lying about its own subject.
5. **`oneiron-server/src/projection.rs` skipped**, per the blueprint's own "only
   if trivial read-through". It is not trivial: `TrustTableRow` cannot derive
   `Serialize` without `RampScope`/`RampState`/`ScopeOutcomeStats` (MS-06 types,
   not mine) deriving it too. The engine fn is the deliverable; wiring it is a
   server-lane ticket.

## Known holes / banked

- **No `pin_scope` door.** A scope can only be pinned by declining three
  standing offers; the owner cannot pre-suppress a scope that has never asked.
  The blueprint's state machine is offer-triggered, and inventing the door
  would be scope I was not given. Banked, not silently added.
- **Sub-millisecond answer ordering** rests on UUIDv7 monotonicity, as MS-06's
  row ids already do. Answers are owner taps seconds-to-days apart; a clock that
  steps backwards between two of them could misorder. Same exposure MS-06
  accepted, documented in the `ANSWER_KEY_PREFIX` doc.
- **`graduation_policy_for` scans the runtime row table per call**, so
  `graduation_offers`/`trust_table` are O(scopes × rows). Rows are
  owner-authored policy (a handful); documented rather than indexed.

## Pre-existing defect found (charged to no lane)

`cargo clippy --workspace --all-targets --all-features -- -D warnings` fails on
**`crates/oneiron-seal/src/native/verify.rs:1280`** — deprecated
`GenericArray::as_slice` under `-D deprecated`. Not in this packet, not in this
diff (`git diff --name-only HEAD` has no `oneiron-seal` path); present on
`48ebcbc34`. Recipe-defect class: it will red the fmt-clippy verify leg for
every lane until someone fixes it. `cargo clippy -p oneiron --all-targets
--all-features -- -D warnings` is clean.

## Gates

- `cargo fmt --all` — clean
- `cargo clippy -p oneiron --all-targets --all-features -- -D warnings` — clean
- `cargo test -p oneiron --all-features` — **3967 passed, 0 failed**
  (lib: 3605 passed / 0 failed / 17 ignored)
- MS-06 regression: 18/18 `consent_graduation` unit tests + 5/5 `ms06_*` oracle
  tests green, unedited.
- 24 new tests in `edit_distance::graduation::tests`.

## Done-means

- [x] Streak meets row, guard fails (2/2) → no offer; 9/10-style history passes →
      offer — `a_streak_that_meets_the_row_but_not_the_guard_surfaces_no_offer`
- [x] go-auto → grant via MS-06's door — `go_auto_mints_the_grant_through_ms06s_own_door`
- [x] not-now ×1..2 backoff respected; ×3 → manual_pinned; no further offers;
      unpin restores — `not_now_holds_the_offer_for_the_backoff_and_the_third_one_pins_the_scope`,
      `a_pin_never_expires_and_never_lets_the_engine_ask_again`,
      `unpinning_from_settings_restores_eligibility_and_resets_the_ladder`
- [x] All transitions receipted — asserted in each of the three above
- [x] Settings override beats compiled default —
      `the_most_specific_row_wins_and_clearing_it_falls_back`,
      `an_exact_row_the_owner_wrote_outranks_the_dial_the_engine_derived`
- [x] Malformed row → typed error, never a silent zero threshold —
      `a_malformed_stored_row_is_a_typed_error_never_a_waived_threshold`,
      `a_row_must_name_three_axes_a_real_streak_and_a_probability`
- [x] `trust_table` covers every scope with history, consistent with MS-06 over a
      scripted sequence — `the_trust_table_agrees_with_ms06_over_a_scripted_outcome_sequence`
- [x] MS-06's oracle tests still green after the policy-fn swap

## SIMPLIFY pass (K3, on cf9c04eef)

Deletion-biased, confined to `edit_distance/graduation.rs` internals — no
public API, no test assertions or fixtures touched:

- Deleted the one-call-site `narrow()` wrapper: the `cast_possible_truncation`
  `#[expect]` moved onto `posterior_lower_bound` itself, cast inlined, the
  width rationale kept as a comment. One private fn gone.
- `trust_table`: hoisted `offer_is_earned` ahead of the struct literal, which
  let `threshold` move instead of `clone()`. One allocation per row gone.
- `answer_receipt_record`: the three-insert `BTreeMap::new()` became
  `BTreeMap::from([...; 3])`.
- `encode_row` call sites now pass the existing `THRESHOLD_ROW_LABEL` /
  `ANSWER_ROW_LABEL` consts instead of divergent one-off strings.

Deliberately left alone: the `StoredAnswer` decode/version-check duplication
between `snooze_state_in_txn` and `answer_receipts_in_txn` (factoring it would
ADD a helper to save four lines — structure, not deletion), and the extensive
doc comments (house craft standard, not a layer).

Gates after the pass: `cargo fmt --all` clean · `cargo clippy -p oneiron
--all-targets --all-features -j 6 -- -D warnings` clean · `cargo test -p
oneiron --all-features --lib -j 6 graduation` 42/42 (24 new + 18 MS-06,
unedited).

## VERDICT-FIX round (Opus, on 2978dc497)

Four findings, all ruled REAL with verified traces by the verdict leg; nothing
banked, nothing relitigated. Each fixed at its chokepoint and mutation-verified
(red-before / green-after).

### F1 — P1 `input-validation`: `set_graduation_policy` trusted its argument

`ThresholdRow`'s fields are `pub` by the keystone skeleton, so `ThresholdRow::new`
is a door and not a gate: a struct literal reaches `set_graduation_policy`
unvalidated. Because every read re-parses the stored row through
`threshold_row_parts` and fails CLOSED on one it cannot rebuild, a single bad
write did not corrupt one scope's policy — it took `graduation_policy_for`,
`ramp_streak_floor`, `ramp_scope_state`, `graduation_offers`, `scope_stats`,
`trust_table` and `record_proposal_outcome_for_ramp`'s post-write derive down
vault-wide, contradicting the done-mean "malformed row → typed error + compiled
fallback".

Fix: `set_graduation_policy` re-runs `ThresholdRow::new` on the row it was handed
and returns the typed `InvalidConsentBound` at the write door. Public field shape
unchanged.

Red-before: `the_write_door_re_validates_a_row_the_caller_assembled_by_hand`
panicked on `expect_err` (three hand-assembled illegal rows all persisted).

### F2 — P1 `state-machine-bypass`: two acceptance doors, two state machines

`Vault::accept_graduation_offer` called `accept_graduation_offer_in_txn`
directly and appended no answer row, while `answer_graduation_offer(.., GoAuto)`
appended one first. `replay_snooze` treats `go_auto` as ladder-clearing, so the
old door minted the grant while leaving `ManualPinned` standing: once a later
correction demoted the grant and the scope re-earned its threshold,
`graduation_offers` suppressed it indefinitely with only `unpin_scope` as the way
out. The old door is live — MS-06's tests and `merge_split_oracle` both call it.

Fix at the shared chokepoint: `accept_graduation_offer_in_txn` — the only path
both public doors traverse — now appends the `go_auto` row itself, through a new
`pub(crate) record_go_auto_answer_in_txn` in `graduation.rs`, inside the same
write transaction that mints the grant. `answer_graduation_offer_at` dropped its
own append; the acceptance clock is passed in so the caller's `at` still governs.
No fixture sync was needed: every MS-06 and oracle receipt count filters on
`is_ramp_demotion_receipt` / `is_ramp_outcome_receipt`.

Red-before: `ms06s_own_acceptance_door_answers_the_offer_exactly_as_this_ones_does`
saw 3 answer receipts instead of 4.

### F3 — P2 `scope-encoding`: `exact_pattern` was not exact

`RampScope` fields are arbitrary text (trim, non-empty, length cap), so
`op_kind = "send/email"` and `target_class = "*"` are valid MS-06 tuples. The
pattern grammar reserved `/` and `*` without a way to spell them, so
`exact_pattern` produced a four-axis string for the first (making
`for_dialed_streak` unbuildable — any `set_ramp_streak_floor` on such a scope
poisoned every later policy read) and a wildcard for the second (a "exact" row
governing every scope on that axis). Both are regressions against a landed MS-06
dial.

Fix at the encoding chokepoint rather than at one write door: `\` now escapes a
reserved character inside an axis. `pattern_axes` splits on UNESCAPED separators
and rejects a dangling escape or an escape of an unreserved character — so one
axis has exactly one spelling, one pattern exactly one `pattern_key`, and no two
rows can mean the same thing under two keys. `axis_matches` compares against the
unescaped axis without materializing it; `exact_pattern` escapes as it builds.
A lone `*` axis is still the wildcard, `\*` is a literal star, and `specificity`
counts an escaped literal as a literal. Rejecting `/` in `RampScope` itself stayed
out of scope — that would change MS-06's scope domain.

Red-before: `a_scope_field_carrying_a_reserved_character_still_names_exactly_itself`
failed at `ThresholdRow::new(exact_pattern(&slashed), ..)`; the extended
`a_row_must_name_three_axes_a_real_streak_and_a_probability` failed on the
well-formed escaped pattern.

### F4 — P2 `receipt-pagination`: an oldest-first cap hid recent decisions

`answer_receipts_in_txn` walked `prefix_iter` ascending under
`MAX_RECEIPT_QUERY_SCAN` with no cap-fired signal. The answer log persists for the
life of the vault and `unpin_scope` appends unconditionally, so growth is bounded
by nothing: past the cap the newest transitions became permanently unprojectable
and a time-bounded query for the latest one could return empty — the exact shape
`receipt.rs:736-747` documents and rejects for `attempt_pack_receipts`.

Fix mirrors that house pattern: an explicit half-open range over the family
(`OverlayDb` has no reverse prefix iterator), a `rev_range` walk capped at
`MAX_RECEIPT_QUERY_SCAN` with one row past the cap reached and never decoded, and
`note_answer_scan_capped` warning when the cap fires. The key is scope-major and
time-minor, so the doc says plainly that this is newest-first WITHIN each scope
rather than globally.

Mutation-verified: with the walk flipped back to `range` (forward),
`a_capped_answer_scan_keeps_the_newest_transitions_not_the_oldest` fails on
"the cap keeps the newest transition"; restored, it passes.

### Gates

`cargo fmt --all -- --check` clean · `cargo clippy -p oneiron --all-features
--all-targets -j 6 -- -D warnings` clean · `cargo test -p oneiron --all-features
-j 6` exit 0, 3609 lib tests + every integration suite green, zero failures.

Diff against the pre-fix tip is exactly `edit_distance/graduation.rs`,
`edit_distance/graduation/tests.rs` and the declared `consent_graduation.rs`
handoff. No `Cargo.toml`, no `Cargo.lock`, `settings.rs` untouched.
