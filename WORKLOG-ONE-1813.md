# WORKLOG — ONE-1813 [BK-02] booking lifecycle verbs

Branch `ONE-1813`, cut off `origin/main` 56f0940e0 (ONE-1784 #625 CAL-02 passport
index/supersede live; ONE-1823 #614 solver + `SlotOracle` live).
Blueprint: `/Users/olety/.claude-wave5/blueprints/BK/ONE-1813.md`.

## Packet

Exactly the claimed files, verified by `git diff --name-only origin/main...HEAD`:

- CREATE `/Volumes/Cinema/w5-lt/bk/crates/oneiron/src/booking/lifecycle.rs`
- CREATE `/Volumes/Cinema/w5-lt/bk/crates/oneiron/tests/booking_lifecycle.rs`
- MODIFY `/Volumes/Cinema/w5-lt/bk/crates/oneiron/src/booking/mod.rs` (declarations + re-exports only)
- MODIFY `/Volumes/Cinema/w5-lt/bk/crates/oneiron/src/lib.rs` (append re-exports only)
- plus this worklog at the repo root, the house convention (ONE-1784's worklog is
  committed on `main`).

No `claim.rs`, `config.rs`, `solver.rs`, `constraint.rs`, `registry.rs`,
`attempt_queue.rs`, `dreamer_runner.rs`, `calendar/*`, `Cargo.toml`, or
`Cargo.lock` edit. `Cargo.lock` was already dirty in the worktree on arrival and
was never staged.

## Gates

- `cargo fmt -p oneiron -- --check` clean.
- `cargo clippy -p oneiron --all-features --all-targets` clean (0 warnings).
- `cargo check --workspace --all-features` clean (one pre-existing
  `oneiron-seal` deprecation warning, not this lane).
- `cargo test -p oneiron --all-features` — 51 test binaries, all `ok`, 0 failed.
- `cargo test -p oneiron --all-features --test booking_lifecycle` — 18/18.

## Blueprint deviations — declared, none absorbed silently

**D1 — `enqueue_booking_verb` returns `AttemptId`, not `EntityId`.**
The skeleton pins `Result<EntityId, BookingError>`, but what is enqueued is an
attempt-queue row, not an entity. An `EntityId` built from the attempt id's 16
bytes would be a pun the caller cannot use: `AttemptQueue::get` takes an
`AttemptId`. Proposed amendment: the skeleton returns `AttemptId`.

**D2 — `VaultActiveHoldSource` carries `exclude_session_key: Option<SessionKey>`.**
The skeleton has only `{ vault }`. Grounding: `booking/solver.rs:265` calls
`self.holds.active_holds(page_ref, window, now_utc, None)` — the solver hardcodes
`None` for the trait's own exclusion argument on every solve. A source holding
only `vault` therefore can never hide the confirming session's own hold, and every
confirm would be blocked by the hold it is redeeming. `solver.rs` is a NON-CLAIM,
so the exclusion is bound into the source the caller builds; both the bound
exclusion and the trait argument are honored, so either door works.

**D3 — `outbound_passport_value` sets `presence: CalendarPassportPresence::Live`.**
Forced by the landed CAL-00 type: `CalendarPassportValue` has seven fields, and
the blueprint's verbatim constructor listed six (it predates `presence`).

**D4 — confirm's re-solve window is the held slot padded by 24h
(`CONFIRM_ALTERNATIVES_PAD_SECS`), not the slot alone.**
The ratified done-means requires `SlotTaken` to carry "nearest alternatives from
the same solver"; a window equal to the held slot can only ever return that slot
or nothing, so the alternatives would always be empty. The solver still clips
every solve to the page's own booking horizon, so this widens the ANSWER and not
the work bound. `offers_slot` remains exact equality against the held slot.

**D5 — a confirm retry re-issues fresh reschedule/cancel bearer tokens.**
Two ratified rules collide: "retries return the already-recorded lifecycle
receipt" and "tokens are opaque bearer values returned once … vault-meta stores
only their digest and scope". The digest-only rule is the stronger one — it is
also a named done-means oracle — so a retry cannot replay the original bearer
strings. Resolution: the durable receipt pins `{event_ref, uid, sequence}` (no
re-mint, no second EVENT, no increment) and the retry receives fresh credentials
for the SAME booking. `confirm_retry_returns_same_event_uid_and_sequence` asserts
exactly the ratified property.

**D6 — the family door lives in `lifecycle.rs`, re-exported from `mod.rs`.**
The blueprint says "extend the booking-family exact validator and local pure-data
descriptor table in `booking/mod.rs`", but ONE-1816's landed test
`booking::tests::booking_constraint_seam_compiles_from_constraint_home` asserts
mechanically that `booking/mod.rs` contains no `fn `/`struct `/`impl `/`trait `/
`enum `/`type `. Defining them in `mod.rs` turned that test red. `mod.rs` stays
declarations + re-exports; `is_booking_family_claim_predicate`,
`validate_booking_family_claim`, and `booking_claim_class_descriptors` live in
`lifecycle.rs` and are exposed from `crate::booking` exactly as intended.

**D7 — digest fields serialize as lowercase hex.**
Field types are blueprint-verbatim `[u8; 32]`; only the `serde(with = …)` adapter
differs. `rmp_serde` encodes `[u8; 32]` as a 32-element integer array (up to 64
non-contiguous bytes), which is both wasteful and made the byte-level
"no raw token at rest" oracle unable to distinguish a present digest from an
absent one. Hex mirrors the module's existing `EntityId`-at-rest convention.

**D8 — cancel also supersedes `calendar.status` to `Cancelled`, basis
`CalendarStatusBasis::Booking`.**
Not in the blueprint's cancel bullet. Derivation, not preference: an EVENT
carrying a live `calendar.passport` claim IS a calendar-family member
(`calendar/query.rs::event_facts`), and `CalendarEventFacts::blocks_time()`
defaults an absent `calendar.time_kind` to busy. Without the status write a
cancelled booking would occupy the host's availability forever and the freed slot
could never be rebooked. CAL-00 minted `CalendarStatusBasis::Booking` — "A booking
flow recorded it" — for precisely this writer, which is the strongest available
evidence that the ratified design expects it. Asserted by
`cancel_keeps_uid_and_increments_sequence_once`.

**D9 — `issue_checkout_lease` is a new public server-side door.**
Without a mint door, `HoldLeaseSpec::CheckoutExtension` is structurally
unreachable and untestable — dead code with an unverifiable law attached. The row
stores digest + session digest + expiry ONLY, clamps at
`MAX_CHECKOUT_HOLD_TTL_SECS`, and adds no payment provider, checkout API, or
payment state machine. Note for the grep oracle: its `requested_ttl_secs`
parameter is SERVER-side and clamped at mint; no public visitor spec
(`HoldSpec`/`ConfirmSpec`/`RescheduleSpec`/`CancelSpec`) carries a TTL or an
extension lifetime, which is what the oracle targets.

**D10 — the consumer surface is new.**
The blueprint specified no consumer signature. `run_booking_lifecycle_once` +
`BookingLifecycleConsumerInput` + `BookingLifecycleTurn` + `BookingOracleRequest`
are this layer's. The oracle arrives through a closure because the page and the
session to exclude are properties of the CLAIMED attempt, unknown before the
claim; a plain `&dyn SlotOracle` parameter cannot express that.

## PACKET_AMEND candidates — declared, NOT taken

**A1 — `claim.rs` + `booking/config.rs`: the family validator is not wired to the
shared write door.** `claim.rs:1588` still routes `booking.*` through
`config::is_booking_claim_predicate` → `validate_event_type_claim`, which matches
ONLY `booking.event_type`. The four lifecycle predicates therefore reach the write
door with no family validator attached. The parent packet forbids a second broad
hook in `claim.rs`, and both files are ONE-1823's, so nothing was touched. The
amendment is one line: point that arm at
`crate::booking::is_booking_family_claim_predicate` /
`validate_booking_family_claim`. See KNOWN HOLE H1.

**A2 — `booking/solver.rs::load_booking_counts` is still the empty STACK-SEAM
stub.** Its own doc says "Confirmed bookings live in the session-keyed lifecycle
rows ONE-1813 lands in BK-A layer 2 … layer 2 supplies `confirmed` here and
changes nothing else", and its `#[expect(clippy::unnecessary_wraps)]` says
"unfulfilling it is how ONE-1813 is told to delete this attribute". `solver.rs` is
a NON-CLAIM for this lane (CLAIMS.md: ONE-1823 only), so daily/weekly caps are not
yet charged against confirmed bookings. Not absorbed.

**A3 — `calendar/passport.rs` has no transaction-composable supersession.**
`supersede_calendar_passport` opens its OWN write transaction, so calling it from
inside the home-node writer would deadlock LMDB (one writer per environment).
BK-02 composes CAL-02's `live_passports_for_event` resolution with the engine's
`Vault::supersede_claim_in_txn` — the same transition, minus the nested
transaction. Amendment: CAL-02 should offer `supersede_calendar_passport_in_txn`.
The UID index (`index_passport_uid`, also its own write txn) is called AFTER the
commit, which is safe by CAL-02's own design: the index is node-local cache that
`resolve_event_by_uid` repairs from synced truth on any miss.

## Known holes

**H1** (= A1) An externally-authored `booking.status` / `booking.source_page` /
`booking.booker_contact` / `booking.event_type_ref` body would land unvalidated at
the shared write door. All four are engine-authored inside the writer today and
are validated at the write site; the family door is exercised directly by
`booking_lifecycle_validator_is_exact`.

**H2** Reschedule refuses a move that OVERLAPS the booking's own current interval
(plus buffers): the re-solve reads the last-committed snapshot, in which the EVENT
still occupies its old slot. Fail-closed — it never double-books — but a 15-minute
nudge is answered "no longer available". Fixing it needs either a CAL `freebusy`
`exclude_event` parameter (CAL-owned) or a two-phase cancel/rebook that gives up
atomicity. Not attempted.

**H3** Mid-write fault injection is not asserted byte-for-byte.
`confirm_writes_event_claims_passport_tokens_and_consumes_hold_atomically` proves
rollback for a failure raised after the hold read (no EVENT, no claim, no
passport; the hold survives and is still confirmable) and proves `SlotTaken`
writes nothing. A genuine mid-sequence fault would need a `test_hooks` entry,
which is out of packet.

**H4** `hold_token_is_opaque_and_only_digest_is_persisted` is split. The
behavioural half — opacity, nothing derivable from the credential, per-mint
randomness — is the integration test of that name. The byte-level half is
`raw_bearer_tokens_never_enter_vault_meta`, an in-file `#[cfg(test)]` unit test,
because `vault.store.vault_meta` is `pub(crate)` and no integration binary can
scan it. Two further crate-internal assertions live beside it:
`hold_rows_key_on_the_session_and_never_on_the_token` and
`booking_lifecycle_validator_is_exact_at_the_family_door`.

**H5 (tripwire note)** A confirmed booking occupies the host's calendar because
its `calendar.passport` claim makes the EVENT a calendar-family member and an
absent `calendar.time_kind` defaults to busy. BK-02 writes no
`calendar.time_kind`. That default is CAL-00's documented stance and the r9
oracle depends on it; if CAL ever flips it, booking EVENTs would silently stop
occupying availability.

## Design notes worth a screener's eye

- **The lock is the write transaction.** `booking_writer` mirrors
  `Vault::try_with_write_txn` (including `store::active_write_txn_guard`) but
  carries `BookingError`, which has no `From<crate::Error>`. Confirm's hold read,
  receipt lookup, re-solve, and every write share one transaction; a competing
  confirm either committed already (visible as busy) or has not yet acquired the
  writer (and will see our EVENT). `two_serialized_confirms_for_same_slot_only_one_commits`
  is the oracle; the loser carries a caller-supplied idempotency key precisely to
  show the key changes nothing.
- **Read transactions nested inside the writer** are used deliberately (the
  oracle's own `freebusy`/config reads, the passport read). LMDB readers never
  block on the writer, and the snapshot is the last-committed state, which is
  exactly the evidence r9 needs. LMDB gives a thread ONE read transaction at a
  time, though: `read_booking_facts` therefore reads the EVENT occurrence through
  the CALLER's transaction (`occurrence_in`) rather than via
  `Vault::read_entity_header`, which opens its own. That nesting was a real bug —
  it made `token_page_ref` silently return `None` and routed reschedule into the
  unresolved-page oracle — caught by `reschedule_uses_same_solver_rules_…`.
- **`BookingError` gains no variant.** Refusals ride `InvalidConstraint`, storage
  and calendar failures ride `SlotOracle` — the same stance `solver.rs` already
  takes on `freebusy` (`BookingError::SlotOracle(format!("freebusy: {error}"))`)
  and `config.rs` takes on storage. No `CalendarError` variant is matched or
  restated. A dedicated `Lifecycle`/`Calendar` variant would be nicer but
  `constraint.rs` is ONE-1816's; not taken, and not needed for correctness.
- **Receipt identity is never an advisory key.** Confirm keys on the hold token's
  digest; cancel on the token digest; reschedule on `(token digest, requested
  slot)`, because the same token legitimately moves a booking more than once and
  only a repeat of the SAME move is a retry.
- **UID shape** is `<event-hex>@oneiron.booking` — globally unique, carries no
  booker identity, and mints once at sequence 0.

## Downstream

- ONE-1814 (BK-03) consumes `ConfirmReceipt.calendar` / `RevisionReceipt.calendar`
  (`{event_ref, uid, sequence}`) for `calendar.invite`. This lane dispatches
  nothing and touches no outbound file.
- ONE-1817 (BK-01 abuse) gets the storage invariant it needs: one active hold row
  per derived session key. No IP/email/rate subsystem here.
- ONE-1821 may attach its soft-confirm hook to `lifecycle.rs`; ONE-1814 and
  ONE-1821 must not be in flight together on this file (CLAIMS.md).

## Simplify pass (K3, 2026-08-07) — NO EDIT WARRANTED

Deletion-biased review of the full lane diff (`lifecycle.rs` 2531 lines, `mod.rs`,
`lib.rs`) against the blueprint and the landed seam. Baseline re-verified before
the pass: `cargo fmt -p oneiron -- --check` clean, `cargo clippy -p oneiron
--all-features --all-targets` clean (0 warnings), `booking_lifecycle` 18/18,
`booking::lifecycle` unit tests 3/3.

Every deletion candidate examined and rejected with grounding:

- `attempt_failure_reason`'s 512-byte truncation + empty-substitution LOOKS like a
  defensive branch but is load-bearing: `attempt_queue.rs` rejects failure reasons
  over 2048 bytes or empty, so an unbounded `BookingError` display would make the
  `queue.fail` call itself error. Kept.
- Cross-module dedup of the serde adapters (`time_range_serde`,
  `entity_ref_serde`, digest adapters) and the `rmp_serde`/`rmpv` codec bridge is
  blocked by the packet: the identical adapters in `constraint.rs`/`config.rs` are
  private, and both files are NON-CLAIMs (ONE-1816/ONE-1823). Local copies are the
  house pattern (`deletion.rs`, `receipt.rs`, `saved_query.rs` each keep their own
  hex helper). Kept.
- `ConfirmOutcome` enum, `UnresolvedPageOracle` witness, `at()` point-range
  constructor: each carries intent at its call site; inlining saves single-digit
  lines at a legibility cost. Kept.
- `validate_lifecycle_claim`'s per-arm `claim_value::<T>().map(|_| ()).ok_or(..)`
  shape: a generic helper would ADD structure without net deletion. Kept.
- Public surface (`BookingVerb::parse`, `BookingVerbRequest::verb`,
  `requested_at`, `BookingOracleRequest`) and all test assertions/fixtures:
  off-limits by simplify law, untouched.
- The r9 writer serialization, mint-once UID law, digest-only token storage, and
  receipt-keyed retry idempotency were re-read line-by-line; nothing in this pass
  weakens or touches them.

Net diff of the pass: this worklog row only.
