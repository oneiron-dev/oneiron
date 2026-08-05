# WORKLOG — ONE-1782 (CAL-00: calendar.* claim family + ClaimClassDescriptorRow)

Lane: CAL · worktree /Volumes/Cinema/w5-lt/cal · branch ONE-1782 (base w5/cal/main)
Seat: standard. Frontier head #1 (lane opener, no dispatch gates).

## seg=0 — full read + recon + begin impl

### Custody read (DONE)
- /Users/olety/.claude-wave5/blueprints/CAL/CLAIMS.md — read END-TO-END
- /Users/olety/.claude-wave5/blueprints/CAL/ONE-1782.md — read END-TO-END

### Claims for this ticket
CREATE: crates/oneiron/src/calendar/mod.rs · crates/oneiron/src/calendar/claims.rs
MODIFY: crates/oneiron/src/lib.rs · crates/oneiron/src/claim.rs · crates/oneiron/src/claim/tests.rs
NON-CLAIMS (hard): registry.rs · edge.rs · serialize.rs · no passport.rs · no docs.

### Status
- [x] custody read
- [ ] recon: comm.rs pattern, claim.rs validator chain, ENTITY_TYPE_EVENT, error family
- [ ] impl

### Recon findings (seg0)

**Reference pattern — `crates/oneiron/src/comm.rs`:**
- consts `PREDICATE_COMM_*` → `COMM_CLAIM_PREDICATES: [&str;4]` → `is_comm_claim_predicate` (`.contains`) → `pub(crate) validate_comm_claim_structure(body: &ClaimBody) -> Result<()>`.
- Private helper set at comm.rs:1830-1934: `value_map`, `required_value` (dup-key reject), `required_string`, `optional_string`, `required_u64`, `required_bool`, `required_entity_ref` (EntityId::from_hex), `validate_keys` (len + membership + no-extras), `validate_key_string` (trim/empty/MAX_KEY_BYTES=512), `invalid_claim(&'static str) -> Error::InvalidClaimBody`.
- comm.rs uses `#[cfg(test)] mod tests;` (separate file). CAL-00 blueprint requires `#[cfg(test)]` INLINE in claims.rs (only two files created) — follow blueprint.

**Validator chain — `crates/oneiron/src/claim.rs:1455-1492` `validate_claim_body_and_decode`:**
Exact-family `else if` chain ends at delivery_window (line 1488-1489). Calendar branch appends after it, exactly as blueprinted.

**⚠ SEAM (load-bearing, affects done-means #4 `calendar_claims_require_event_subjects`):**
`validate_claim_body_and_decode` is a BYTE-LEVEL validator: signature `(data: &[u8], allow_reserved_predicate: bool)`. It has **no `&Store` / no `RoTxn`** — it cannot look up the subject's entity-type header. So "entity subjects that are not existing EVENT rows" is NOT enforceable from inside `validate_calendar_claim_structure`.

Precedent for the two halves:
- *Subject-must-be-Entity* (structural, byte-level): every family does it — `comm.rs:384`, `delivery_window.rs:519`, `disclosure.rs:567`, `channel_identity.rs:526`. ✅ belongs in the CAL validator.
- *Subject-must-exist* (store-level): already enforced generically for ALL claims at both write doors — `batch.rs:2624-2628` (`apply_claim_candidate` → `Error::EntityNotFound`) and `claim.rs:2018-2020` (`put_claim_in_txn_with_reserved` → `Error::EntityNotFound`).
- *Subject-must-be-a-SPECIFIC-type* (store-level): precedent is `comm.rs:1224-1236` `put_comm_claim_in_txn` — reads `store.entities` → `EntityMetadataHeader::parse` → compares `header.entity_type == ENTITY_TYPE_PERSON`, else `Error::EntityNotFound`. It lives in the FAMILY's own writer, **not** in the byte validator, and **not** in batch.rs.

Consequence for ONE-1782: batch.rs is a hard non-claim and CAL-00 mints no writer of its own. The EVENT-type check therefore has no in-claims store-aware home unless CAL-00 adds a family-owned helper in `calendar/claims.rs` that takes the store/txn (comm-style), exercised directly by the named test. Byte-level half stays in `validate_calendar_claim_structure`.
Plan: implement BOTH halves inside `calendar/claims.rs` — (a) byte-level `ClaimSubject::Entity` requirement in the structural validator, (b) a `pub(crate)` store-aware EVENT-type assertion mirroring the comm.rs precedent — so `calendar_claims_require_event_subjects` proves both rejections without touching batch.rs.

**ENTITY_TYPE_EVENT** = `crates/oneiron/src/registry.rs:12` (`pub const ENTITY_TYPE_EVENT: u8 = 6;`) — import the const, never the byte (blueprint Shape §6). registry.rs stays unmodified (zero-byte oracle).

### Implementation (seg0) — COMPLETE, cheap gate GREEN

Files (packet == the 5 claimed paths exactly, verified by `git status --porcelain`):
- CREATE `crates/oneiron/src/calendar/mod.rs` — module home, empty `#[non_exhaustive] CalendarError`, blueprint re-export list verbatim.
- CREATE `crates/oneiron/src/calendar/claims.rs` — 12 predicate consts, `CALENDAR_CLAIM_PREDICATES: &[&str]`, all value types + wire codecs, both validator halves, descriptor table, inline `#[cfg(test)]` module (11 tests).
- MODIFY `crates/oneiron/src/lib.rs` — one line: `pub mod calendar;` (alphabetical, after `bm25`).
- MODIFY `crates/oneiron/src/claim.rs` — one `else if` branch appended after `delivery_window`, exactly as blueprinted.
- MODIFY `crates/oneiron/src/claim/tests.rs` — `write_door_validates_calendar_claim_structure`.

Decisions worth flagging to the screen:
1. **EVENT-subject split into two halves** (see seam analysis above). `validate_calendar_claim_structure` enforces `ClaimSubject::Entity`; `require_event_subject(&Vault, &EntityId)` enforces the EVENT type byte. The byte validator physically cannot do the second (no store handle), and batch.rs is a hard non-claim. `require_event_subject` is `pub` (not `pub(crate)`) because its callers land in CAL-02/04/07 — as `pub(crate)` it tripped dead-code at this layer.
2. **`validate_keys(entries, allowed, required)`** takes two key sets rather than comm.rs's one. The family has exactly two documented back-compat defaults (`busy_transparency`, `presence`) where a key is allowed-but-not-required; a single-set helper cannot express that without a second function.
3. **`CalendarBusyTransparency::from_ics_transp`** fails closed to `Busy` on unknown vendor TRANSP tokens — an unrecognized token can never silently free availability. Blueprint only pinned OPAQUE/missing→busy and TRANSPARENT→free; this is the unstated third case.
4. **`CalendarWallTimeValue` / `CalendarAttendeeValue`** were named in the Shape section's value maps but absent from the skeleton's re-export list; implemented as owner types in claims.rs, NOT added to mod.rs's `pub use` (the blueprint list is reproduced verbatim; they remain reachable via `calendar::claims::`).
5. Second range is 0-60 (leap second admitted). Day-of-month is 1-31 structurally — no month-aware date validity here; that is a calendar computation, and this layer is storage.
6. `calendar.rrule` allows CR/LF (RFC 5545 line folding) but no other control chars; other text fields reject all control chars.

### Gate results
- `cargo fmt -p oneiron` applied; `--check` clean.
- `cargo clippy -p oneiron --all-features --all-targets -j 6` — ZERO warnings.
- `cargo test -p oneiron --all-features --lib calendar::claims` — 11/11 pass.
- `cargo test -p oneiron --all-features --lib` — **3162 passed, 0 failed**, 24 ignored.
- Oracles: registry.rs, edge.rs, serialize.rs, Cargo.toml, Cargo.lock ALL UNCHANGED.

### Done-means status: all 15 boxes satisfied at this layer.

### NEXT (seg1)
- Run the `cargo test -p oneiron claim` lane explicitly + integration-test targets (`--tests`) for a full cheap gate.
- Push branch ONE-1782 (worker never pushes — leave to harness per lane law).

### Full cheap gate re-run (post-commit) — ALL GREEN
- `cargo test -p oneiron --all-features -j 6 claim` (all targets): **284 unit + 11 integration-target hits, 0 failed** across 33 test binaries.
- `cargo check --workspace --all-features -j 6`: clean. Only warning is pre-existing `sha1` deprecation in `crates/oneiron-seal/src/native/verify.rs:1280` — untouched by this lane.

Commit: `39d70c7` on branch `ONE-1782` (base `w5/cal/main`). NOT pushed — workers never push.

### seg0 CLOSED. Lane is at a clean resume point.
