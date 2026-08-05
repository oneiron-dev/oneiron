# WORKLOG — ONE-1747 (MS-05) proposal-outcome receipts + reserved delta

Lane: MS · flat, first out of the lane · branch `w5/ms/ONE-1747` off `w5/ms/main`
Worktree: `/Volumes/Cinema/w5-lt/ms`
Blueprint: `/Users/olety/.claude-wave5/blueprints/MS/ONE-1747.md`
Claims: `/Users/olety/.claude-wave5/blueprints/MS/CLAIMS.md`

## seg0 — read + recon + impl start

### Boot correction (per relay brief)
Worktree booted on `ONE-1744` (gh-stack layer). Cut a FLAT branch
`w5/ms/ONE-1747` from `w5/ms/main` (== `main` == `origin/main` == e9d9e9a) —
not riding the stack layer. Verified `git diff main w5/ms/main` empty.

### Ground truth found

`crates/oneiron/src/identity_topology.rs` (2601 lines, MS-01 landed):
- `StoredIdentityOpAction` = {Merge, Split, Undo}; `kind_str()` :814;
  `to_fold_action()` :826.
- `StoredIdentityOpEvent` :859 with `encode_value` :882 / `decode_value` :947;
  body codec `encode_identity_topology_event_body` :1034 /
  `decode_identity_topology_event_body` :1046 (canonical-round-trip assert
  + `validate_identity_topology_event_stateless` :1075).
- Apply door `apply_identity_topology_op_in_txn` :1978; undo door :2103;
  single write chokepoint `write_identity_event_in_txn` :2542.
- `IdentityOpOutcome` :1403 = {Applied, Parked, Noop}; `Proposed` parks via
  `write.is_effective()` false → `Parked { event }`.
- Fold `fold_identity_topology_log` :699 skips non-effective approvals.

Exhaustive `StoredIdentityOpAction` matches needing a new arm (blueprint
called :1588/:1847/:2124/receipt.rs:2160):
1. `identity_topology_shell_sources_for_store_in_txn` :1846
2. `undo_identity_topology_event_in_txn` :2118
3. `receipt.rs` `identity_topology_receipt` :2159
4. encode :921 / decode :983 arms
(:1588 + :2469 are `(action, state)` matches with a `_` catch-all → covered.)

`IdentityTopologyAction` (fold action, :654) is `{Apply, Undo}` and is matched
at :714, :1542, :1879 — a resolution event needs a third, effect-free arm.

`crates/oneiron/src/receipt.rs` (2698 lines):
- `ReceiptKind` :114 `#[non_exhaustive]` + `as_str` :137 + `parse` :150.
- `ReceiptRecord` :290 — `fields: BTreeMap<String,String>` ONLY, no blob
  column (confirmed; blueprint's "do not add a column" holds).
- `ReceiptQuery.outcome` :184 filters `receipt.outcome` (struct field, not
  the fields map) — so the outcome string must land on `ReceiptRecord.outcome`.
- `collect_receipt_records` :1809 gates `identity_topology_receipts` :2107
  behind `includes_kind(IdentityLifecycle)`.

No `base64` dependency in `crates/oneiron/Cargo.toml` (only transitively in
Cargo.lock). `receipt::hex_lower` :2687 exists; `deletion::hex_decode_lower`
is `#[cfg(feature = "sync")]`. → payload rides `fields` as LOWER HEX using a
local pair (hex_lower + a local decoder), NOT base64 — no new dep, no
reservation needed, byte-exact round-trip either way.

### Oracle arming plan (`tests/merge_split_oracle.rs`, MS-lane-exclusive)

Three ms05 tests un-ignore; seam stubs → real APIs. Handles `u64` → `EntityId`.
Per blueprint L62 BOTH payload asserts bind `amended_body` (the producer
artifact), not the reserved Δ slot.

**Fixture adaptation (NOT an assert weakening):** the oracle's amend payloads
(`b"narrow-to-work-claims"`, `[0x00,0xFF,0x13,0x37,0x00]`) are placeholder
bytes. The ratified amendment-scope pin (blueprint §Shape 1) requires the
amended body to DECODE to the same op kind with a subject subset — arbitrary
bytes are exactly what `AmendmentOutOfScope` must reject. So the fixtures
become real encoded amended-op bodies; every assert keeps its shape
(payload present iff `approved_amended`, byte-identical round-trip, no
ARCH-0056 Δ field names projected). Counts stay counts. The opaque-bytes
intent of `ms05_delta_field_is_reserved_opaque_not_built` is preserved by the
byte-exact round-trip assert; the reserved-Δ negative is untouched.

`ms06_streak_offers_standing_grant_never_auto_grants` is RE-ARMED as-is —
it stays `#[ignore = "armed by ONE-1748"]`; this ticket only keeps the file
compiling under the widened `ProposalOutcome`/`ProposalRuling` (the oracle's
local copies are replaced by the real `oneiron::` types, which ms06 also
names). No ms06 assert touched. GOV-1606's zone in this file is not crossed.

### Design (locked)

`identity_topology.rs` — additive, no refactor of the apply doors:
- `ProposalOutcome` {ApprovedUntouched, ApprovedAmended, Rejected} +
  `as_str`/`parse` (wire: `approved_untouched|approved_amended|rejected`).
- `ProposalRuling<'a>` {Approve, AmendThenApprove(&'a [u8]), Reject}.
- `ProposalScope { op_kind: &'static str, target_class: u8, actor: Option<EntityId> }`
  — the DEC-0006 tuple, STAMPED at resolve time from the proposal (blueprint
  §Shape 2: "cheap to stamp here where the op is in hand"). Stamping (vs.
  deref at projection) is what makes the receipt self-contained for MS-06 and
  records the scope AS RULED, not as later mutated. `actor` = the PROPOSAL's
  actor (the agent whose autonomy ramps), distinct from the resolution
  event's own actor (the ruler) which lands on `ReceiptRecord.actor`.
- `StoredIdentityOpAction::ProposalResolution { proposal, outcome, scope, amended_body }`
  + `EVENT_KIND_PROPOSAL_RESOLUTION = "proposal_resolution"` (wire string).
- `IdentityTopologyAction::ResolveProposal { proposal, outcome }` — effect-free
  fold arm (a resolution moves no lifecycle state; the applied op's own
  event does that).
- Amendment codec: extract the existing action encode/decode into shared
  `encode_action_entries` / `decode_action` so the amended body reuses ONE
  parser (`encode_identity_op_amendment` / `decode_identity_op_amendment`,
  merge/split only — undo + resolution are not amendable).
- Door `Vault::resolve_identity_proposal(&self, proposal, ruling, write, now)`.
  Signature completed with `write`+`now` per house style: the family never
  reads a wall clock (`at` is always caller-supplied) and every door carries
  `IdentityOpWrite`. Mechanical completion of the blueprint sketch, not a
  design change.
  Order: read proposal (must exist, must be `approval == Proposed`) → assert
  not already resolved → derive op → per ruling apply via the EXISTING
  `apply_identity_topology_op_in_txn` with `approval = Approved` → append the
  ProposalResolution event in the SAME txn. Exactly one outcome receipt.
- Amendment scope guard: decoded kind == proposal kind AND
  `amended.participants() ⊆ proposal.participants()` → else
  `Error::IdentityProposalAmendmentOutOfScope`. Nothing applied.

`receipt.rs` — additive:
- `ReceiptKind::ProposalOutcome` (`"proposal_outcome"`).
- Per-kind dispatch inside `identity_topology_receipts`: resolution events →
  the ProposalOutcome projector (gated on its own kind), all others → the
  existing `identity_topology_receipt`. `collect_receipt_records` guard
  widened to `IdentityLifecycle || ProposalOutcome`.
- Fields: `proposal_ref`, `outcome`, `op_kind`, `target_class`, `actor`,
  `amended_body` (hex, only on approved_amended). `amendment_delta` is the
  RESERVED slot — never written at this ticket.
- Accessors `proposal_outcome_amended_body` / `proposal_outcome_delta`.

`error.rs` — additive variants (already-resolved, not-a-proposal,
amendment-out-of-scope, bad amended body).

### Status
- [x] blueprint + CLAIMS read end to end
- [x] recon of identity_topology.rs / receipt.rs / error.rs / oracle
- [x] flat branch cut
- [ ] impl (in progress)

## seg0 (cont.) — impl complete, cheap gate GREEN

### Boot state found
Prior segment left ~818 uncommitted lines mid-impl (lib compiled clean; oracle
untouched). Committed as WIP `e31facd` FIRST to protect the work, then continued.

### Defects found + fixed in the inherited impl

1. **`source` field leak (REAL, oracle-caught).** The new `proposal_outcome`
   projector wrote `fields["source"]` — but `source` is one of the SIX
   ARCH-0056 Δ names `ms05_delta_field_is_reserved_opaque_not_built`
   forbids. Fixed by minting `FIELD_CLAIM_SOURCE = "claim_source"`; the
   claim-source axis is real and unrelated, so it gets its own unambiguous
   key rather than squatting on the reserved one. **Verified the NEG test
   BITES:** temporarily reverted the fix → test failed with
   `receipt must not project the ARCH-0056 Δ field "source" yet`; restored.
2. **Missing `lib.rs` re-exports.** `ProposalRuling`/`ProposalOutcome`/
   `ProposalScope`/`proposal_outcome_*`/`encode|decode_identity_op_amendment`
   were `pub` in-module but never re-exported, so the oracle (an integration
   test, `oneiron::` paths only) could not reach them at all.

### Oracle arming (`tests/merge_split_oracle.rs`)

- 3 × `#[ignore = "armed by ONE-1747"]` removed; **all three green**.
- Local `ProposalRuling`/`ProposalOutcome` stand-ins DELETED → real
  `oneiron::` types. Vocabularies identical, so every assert binds unchanged.
- 4 seam stubs → real APIs; handles `u64` → `EntityId`.
- `receipt_delta_payload` → `proposal_outcome_amended_body` (per blueprint
  L62: BOTH payload asserts bind the amended bytes, not the reserved Δ slot).
- Receipts read back through the PUBLIC `ReceiptQuery` surface, so the
  oracle also witnesses the "queryable by kind" done-means on every assert.
- **Fixture adaptation (arming, NOT weakening):** placeholder payloads
  (`b"narrow-to-work-claims"`, `[0x00,0xFF,0x13,0x37,0x00]`) → real encoded
  amended bodies, because the ratified amendment-scope pin requires the body
  to decode to the same op kind with a subject subset — arbitrary bytes are
  precisely what `AmendmentOutOfScope` must reject. Asserts keep their shape;
  the NEG test additionally now asserts its fixture is genuinely non-UTF-8,
  so "byte-exact round-trip" still proves opacity.
- **ms06 re-armed:** `ms06_streak_offers_standing_grant_never_auto_grants`
  (and the other three ms06 tests) now bind the REAL `ProposalOutcome`;
  stays `#[ignore = "armed by ONE-1748"]`, zero asserts touched.
- **Arming-discipline audit:** ignore census main vs branch — exactly the
  three 1747 entries removed, 1744/1745/1746/1748/1749 all unchanged.
  Assert count 68 → 73 (added only). GOV-1606's zone not crossed.

### Unit tests added (`identity_topology/tests.rs`, 7 new, all green)

Cover the done-means the oracle does not reach: amended body applies (not the
original) + ledger records the applied form · amendment-scope NEG (wrong kind /
unnamed subject / malformed bytes) each fail-closed with the park left OPEN ·
reject = zero effects + park retired (re-resolve errors typed, either ruling) ·
non-proposal + absent + non-effective-ruling rejections · ramp-scope tuple
stamped on all three outcomes + Δ slot always empty · queryable by kind and
outcome + the two type-76 receipt kinds do not bleed · amendment codec
round-trip + unarmed-kind and trailing-byte refusal.
Seeds 0x73–0x8C, all outside `PINNED_ID_BYTES` (seed-band law).

### Cheap gate

- `cargo fmt --all -- --check` clean.
- `cargo clippy -p oneiron --all-features --all-targets -- -D warnings` clean.
- `cargo test -p oneiron --all-features`: **3157 passed / 0 failed** (lib run
  twice back-to-back, both clean).
- One FLAKE observed on a full-suite run:
  `attempt_queue::tests::attempt_queue_cleanup_log_span_has_stable_privacy_preserving_fields`.
  Charged to NO lane: it lives in a module this ticket never touches, passes
  in isolation and in two full lib runs on this branch, and clean main
  (probe worktree at `main`) also ran 3150/0. Load-dependent tracing-capture
  interaction, pre-existing. Flake-guard law applied.

### Status
- [x] blueprint + CLAIMS read end to end
- [x] recon
- [x] flat branch cut
- [x] impl (resolution door, amendment codec + scope pin, outcome receipt)
- [x] oracle armed (3 ms05 green; ms06 re-armed, still ignored)
- [x] unit tests
- [x] cheap gate green (fmt · clippy -D warnings · full suite)
- [ ] NOT PUSHED — workers never push; orchestrator owns the gh stack.

### Packet check
`error.rs`, `identity_topology.rs` (+tests), `lib.rs`, `receipt.rs`,
`tests/merge_split_oracle.rs` — all within the ticket's claim slice.
`Cargo.lock` NOT committed. No `git add -A` used.

## seg0 (cont.) — K3 simplify pass (commit b135e0f)

Deletion-biased polish, no restructuring. Two edits plus import hygiene:

1. **`receipt.rs` projectors return typed errors on dispatch slips.**
   `proposal_outcome_receipt` had `unreachable!` and
   `identity_topology_receipt` had a stale fallback arm fabricating a
   lifecycle receipt for a resolution row (its own comment said the arm
   was unreachable — the shape existed because the enum is exhaustive).
   Both now return `Result<ReceiptRecord>` with
   `Error::InvariantViolation`: a future dispatch slip surfaces as a
   typed error, never a panic or a stealth kind-mix. Both projectors are
   crate-private with the single dispatcher as sole call site — no
   public-API change.
2. **Hoisted `entity_type_registry_entry` to the import block** — the
   deferred `crate::registry::…` use-site was the only one in the
   module.

Sweep findings: zero trailing whitespace / excess blank lines in all six
touched files. Stale-comment audit: comments are dense but accurate; the
one borderline case (the self-describing dead arm) was deleted with the
arm. Kept as-is (deliberate, not excess): the `AmendThenApprove, None`
unreachable-invariant arm in the resolution door (truth-synced
InvariantViolation), the fold's duplicate-resolution rejection (ledger
tabu-defense), and the kind-gate redundancy between scan level and
projector level (belt-and-suspenders, documented in-place).

Gates after: `cargo fmt --all -- --check` clean · `cargo clippy -p
oneiron --all-features --all-targets -- -D warnings` clean · `cargo
test -p oneiron --all-features --lib` **3157/0** · oracle integration
test `merge_split_oracle` **3 passed / 20 ignored** (1748/1749 stubs
intact). No test assertions touched; no public API changed; NO PUSH.

