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
