# WORKLOG — ONE-1812 [BK-01] Disclosure-ladder grants

Branch `ONE-1812`, cut from `origin/main` `c12b66983` (ONE-1606 #575 + ONE-1816 #601 merged).
Blueprint: `/Users/olety/.claude-wave5/blueprints/BK/ONE-1812.md`.

## What landed

- **CREATE** `crates/oneiron/src/booking/disclosure_rung.rs` — the rung vocabulary
  (`DisclosureRung`), the surface ceiling (`SurfaceClass`), the default-rung policy
  (`CalendarDisclosureDefault` / `default_disclosure_rung`), the projection DTOs
  (`EventRow`, `EventDetailsRow`, `TitledEventRow`, `BusyBlockRow`, `RungProjection`),
  the single chokepoint `project_at_rung`, and the cross-vault adapter
  `project_calendar_grant`. Tests inline under `#[cfg(test)] mod tests`.
- **MODIFY** `booking/mod.rs` (module + re-exports), `access_grant.rs`
  (`AccessGrantScope::Calendar`, `AccessGrantCapability::CalendarDisclosureRead`,
  per-kind scope codec, `AccessGrant::calendar_disclosure` /
  `calendar_disclosure_rung`, `CalendarAccessGrantRow`,
  `Vault::list_calendar_access_grants` / `revoke_calendar_access_grant`),
  `genui.rs` (`GrantMintIntentScope::Calendar` + `calendar_grant_mint_intent`),
  `lib.rs` (append-only re-exports).
- No entity/type byte allocated: calendar grants reuse `ENTITY_TYPE_ACCESS_GRANT = 128`.
- No `registry.rs`, `claim.rs`, `disclosure.rs`, `Cargo.toml`, or `Cargo.lock` edit.
  No descriptor runtime, no interim claim validators, no second `SlotMask`.
  `SlotMask` / `BookingError` are imported from ONE-1816's `crate::booking::{...}`.

## Blueprint deviations — every one declared, none silently absorbed

### D1 (structural) — `AudienceSel` does not exist; the calendar scope is `(calendar_ref, rung)` and the audience is the record's `principal_ref`

Blueprint seam: `Calendar { calendar_ref, audience: AudienceSel, rung }`.

ONE-1606 as landed (#575) delivers `consent.rs` with **`AudienceBound`** (a sorted,
deduped member list; `Clone`, not `Copy`) and does **not** touch `access_grant.rs`
at all. There is no `AudienceSel` in the tree. 1606's own adapter
`disclosure_grant_from_access_grant` already lifts `AccessGrant.principal_ref` into
`AudienceBound::singleton(...)` as the disclosure audience.

Implemented `Calendar { calendar_ref, rung }`, with the audience bound to the
record's `principal_ref`. Reasons:

1. An `AudienceBound` inside the scope would be a **second** audience beside
   `principal_ref` and the two can disagree (a 5-member room on a record whose
   principal is one person). That needs a consistency invariant to police, and
   `disclosure_grant_from_access_grant` would still project only the singleton.
2. `principal_ref`-as-audience is exactly DEC-0006's "one standing grant per
   `(calendar × audience)`" — the blueprint's law is preserved, only its field
   list changes.
3. It keeps `AccessGrantScope: Copy` (an `AudienceBound` field would drop `Copy`
   from `AccessGrantScope` **and** `AccessGrant`, rippling through `consent.rs`,
   `receipt.rs`, and `oneiron-server`).
4. The landed `GrantMintIntent` already carries `principal_ref` beside `scope`, so
   the mint payload is literally `(calendar_ref, audience, rung)`.

No booking-local audience selector was defined; 1606's `AudienceBound` remains the
sole audience vocabulary, reached at the consent seam.

### D2 — `SurfaceClass` non-public variants

Blueprint: "non-public variants follow the landed boundary taxonomy" (unnamed).
Landed nouns are `CompanionScope::{Neutral,Personal,SharedVault}` and
`CustodyClass::CrossVault`. Implemented `SameVault | CrossVault | Public`, ceilings
`Full | Full | Slots`. A fourth `SharedVault` variant was **not** added: shared-vault
membership is a grant/default question (family members get `Full` through
`default_disclosure_rung`), not a ceiling question, so it would behave identically
to `CrossVault`.

### D3 — Vault door signatures

Blueprint sketched `list_calendar_access_grants(&self, calendar_ref: EntityId) -> VaultResult<Vec<AccessGrant>>`
and `revoke_calendar_access_grant(...) -> VaultResult<()>`.

`AccessGrant` carries no id, so a `Vec<AccessGrant>` cannot be revoked from — the
registry's one-tap revoke needs the entity id. Returns
`Vec<CalendarAccessGrantRow { grant_ref, grant }>`, mirroring 1606's
`ConsentGrantRow` / `ConsentRegistryRow`. Both doors take `&EntityId` (house idiom of
`get_access_grant` / `revoke_access_grant`) and `revoke_calendar_access_grant`
returns the revoked `AccessGrant`, matching `revoke_access_grant`.

### D4 — `AccessGrantCapability::CalendarDisclosureRead` added

Not in the skeleton, but `AccessGrant.capability` is mandatory, the codec parses it,
and `disclosure_grant_from_access_grant` uses `capability.as_str()` as the
`DisclosureClass`. Reusing `CompanionProfileRead` would file calendar reads under
the companion class. Wire string `calendar.disclosure_read`. No byte allocated.

### D5 — `project_calendar_grant` added

The done-means requires `cross_vault_reader_cannot_obtain_raw_event_rows` to
"exercise the actual cross-vault adapter" and the registry test to observe
`Nothing` after revoke. No such adapter was landed. `project_calendar_grant`
resolves the grant to a rung (revoked / wrong principal / wrong calendar /
non-calendar scope ⇒ `Nothing`) and **delegates** to `project_at_rung` — it is not a
second projection path and cannot bypass the ceiling.

### D6 — serde plumbing for `EntityId`

`EntityId` carries no serde derives, so the blueprint's
`#[derive(Serialize, Deserialize)]` on `EventRow` / `TitledEventRow` with
`event_ref: EntityId` cannot compile as written. Added local
`entity_ref_serde` / `entity_refs_serde` hex modules — the same
`#[serde(with = "...")]` idiom ONE-1816 landed for `TimeRange` in `constraint.rs`.
Field types stay `EntityId` exactly as specified.

### D7 — `DisclosureRung::narrower` instead of `Ord`

`min(granted, ceiling(surface))` means *less disclosure*. A derived `Ord` over the
blueprint's declaration order would make `Full < Titles`, so `min` would pick
`Full` — silently inverting the clamp. `DisclosureRung` derives no `Ord`; the clamp
goes through the explicit `narrower`, and `narrower` is tested in both argument
orders.

### D8 — test placement

Blueprint: "Tests live beside the modified Rust modules under `#[cfg(test)]`; no
separate test file is claimed." `disclosure_rung.rs` tests are an inline
`mod tests` in the claimed CREATE file. The access-grant and gen-UI tests were
appended to those modules' own existing sibling test files
(`access_grant/tests.rs`, `genui/tests.rs`) — the modules' test home, not new files.

## PACKET_AMEND candidates — 4 files outside the claimed packet

All four are **compile-forced**: `AccessGrantScope` and `GrantMintIntentScope` are
`#[non_exhaustive]`, which does not relax exhaustive matching **inside** the crate,
so appending a variant breaks every in-crate match. Each amendment is one arm; none
changes existing behavior.

1. **`crates/oneiron/src/consent.rs`** (ONE-1606's file; unclaimed by any BK ticket)
   - `access_grant_scope_selectors`: `Calendar` arm emitting
     `calendar:<hex>` + `rung:<name>`.
   - `access_grant_projection_is_active`: accepts `CalendarDisclosureRead` alongside
     `CompanionProfileRead`. **Load-bearing** — without it every calendar grant
     projects as permanently inactive in the unified registry.
2. **`crates/oneiron/src/receipt.rs`** (CLAIMS: SPINE-COMM wall, "no BK projector or
   index edit") — `append_access_grant_scope_fields` gets a `Calendar` arm. No
   projector added; only the arm the compiler demands.
3. **`crates/oneiron/src/gate.rs`** (CLAIMS: GATE-lane wall) —
   `standing_outbound_grant_binding_parts` rejects `GrantMintIntentScope::Calendar`
   with `InvalidOutboundGrantBody`. Forced by the genui variant the blueprint
   mandates. **Also load-bearing safety**: a calendar *read* grant must never mint
   an outbound *send* binding.
4. **`crates/oneiron/src/outbound_grant.rs`** (CLAIMS: "ONE-1814 only within BK") —
   `StandingOutboundGrantScope::from_grant_mint_scope` rejects the `Calendar` arm,
   same reasoning as (3).

Incidental, in-packet: the private const `SCOPE_KEYS` was renamed
`SCOPE_KEYS_COMPANION_PROFILE` (the codec now dispatches on the `kind` tag to a
per-kind key set, so each scope validates against its own pinned keys and cannot
borrow the other's). Four references in `access_grant/tests.rs` updated.

## Done-means coverage

| Done-means test | Where |
|---|---|
| `calendar_access_grant_scope_round_trip_preserves_old_tags` | `access_grant/tests.rs` — also asserts the companion encoding is byte-identical to the pre-existing fixture |
| `calendar_grant_reuses_access_grant_entity_type_128` | `access_grant/tests.rs` |
| `calendar_grant_registry_lists_and_revokes` | `access_grant/tests.rs` — mint → list → revoke → `Nothing` on the next read |
| `default_disclosure_rung_matches_arch0062_r1` | `disclosure_rung.rs` |
| `project_full_keeps_title_and_details` | `disclosure_rung.rs` |
| `project_titles_strips_details_and_attendees` | `disclosure_rung.rs` — asserts the serialized key set |
| `project_busy_is_opaque_intervals_only` | `disclosure_rung.rs` |
| `project_nothing_returns_no_rows` | `disclosure_rung.rs` |
| `public_projection_clamps_full_to_slots_inside_chokepoint` | `disclosure_rung.rs` |
| `public_projection_clamps_titles_and_busy_to_slots_inside_chokepoint` | `disclosure_rung.rs` |
| `slots_projection_without_precomputed_mask_returns_booking_error` | `disclosure_rung.rs` — both the clamped-public and the directly-granted `Slots` path |
| `slot_mask_uses_final_half_open_schema` | `disclosure_rung.rs` — exact wire field order + `[start,end)` validation incl. the exact-fill boundary case |
| `cross_vault_reader_cannot_obtain_raw_event_rows` | `disclosure_rung.rs` |
| `slot_projection_contains_no_event_material` | `disclosure_rung.rs` |
| `grant_mint_intent_calendar_sentence_is_bounded` | `genui/tests.rs` — one triple, three scope keys, no settings grid |
| ARCH-0060 §10 custody answered in comments/tests | module docs + `cross_vault_reader_cannot_obtain_raw_event_rows` |
| Existing access-grant / gen-UI suites pass unchanged | full suite green |

Extra tests not in the done-means, each covering a real failure mode:
`narrower_descends_the_ladder_in_both_argument_orders` (D7's inversion trap),
`revoked_or_mismatched_grant_projects_nothing`, `projection_dtos_round_trip_through_serde`,
`calendar_scope_is_not_an_outbound_grant_scope` (PACKET_AMEND 3/4's safety property).

## Gates

- `cargo fmt -p oneiron` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — zero warnings.
- `cargo check --workspace --all-features --all-targets` — green (the one
  `oneiron-seal` sha1 deprecation warning is pre-existing on main).
- `cargo test -p oneiron --all-features` — green, zero failures.

Flake note, recorded rather than buried: one of five full runs reported
`3581 passed; 1 failed` while other lane agents were compiling on the same box.
The failing test's name was filtered out by the reporting command and could not be
recovered; three subsequent full/lib runs were green
(`3582 passed; 0 failed`, exit 0, `/tmp/one1812-lib.log`), including runs after the
last code change. No ONE-1812 test was involved in any red — the lane's own tests
passed in every run. Treated as a load-induced flake under the flake guard
(red re-runs once on clean base), not attributed to this lane.

## Downstream notes

- **ONE-1823** MODIFYs `disclosure_rung.rs` to wire the `Slots` payload; collision
  order `ONE-1812 → ONE-1823` holds and the file now exists.
- **ONE-1815** must serve `RungProjection::Slots` through `project_at_rung` /
  `project_calendar_grant` and may not hand-roll a redaction. `SurfaceClass::Public`
  is the only value that produces the public ceiling.
- The `Slots` arm needs a solver-produced `SlotMask`; ONE-1823's `BookingSolver`
  supplies it. `project_at_rung` returns `BookingError::Surface` rather than an
  empty mask when the caller has none.

## Simplify pass (K3, on impl tip 3e37a0d11)

Deletion-biased review of the full impl diff. The implementation was already
tight — no dead helpers, no speculative layers, no duplicated doors
(`calendar_grant_mint_intent` is the only mint-intent constructor;
`list_calendar_access_grants` is the first grant-listing door, nothing to
dedup against). Near NO-EDIT; two micro-dedups applied:

- `access_grant.rs`: the two scope-key arrays re-pinned their leading `"kind"`
  literal — they now reference `SCOPE_KEY_KIND` (one literal, three uses).
- `disclosure_rung.rs`: `entity_refs_serde::deserialize` consumed the owned
  `Vec<String>` by reference — now `into_iter()`.

Deliberately kept (checked, not deletion candidates): `RungProjection::rung()`
(test-consumed public API), `validate_slot_mask` (done-means `[start,end)`
validation), the `rung:` consent selector (registry projection contract),
the defensive `CorruptedIndex` header checks in `list_calendar_access_grants`
(mirrors the codebase's fail-closed corruption posture). No test assertion,
fixture, or public API touched.

Gates after the pass: `cargo test -p oneiron --lib` green (3153 passed,
0 failed), `cargo clippy -p oneiron --all-features` zero warnings,
`cargo fmt -p oneiron -- --check` clean.

## VERDICT-FIX (Opus, on simplify tip 38f143c00)

Finder returned 4 items; the verdict leg rejected item 1 with derivation and
ruled the other three REAL. Rejected item is **not** relitigated here.

- **Item 1 — `parallel-consent-path` (P1) — REJECTED / BANKED by the verdict.**
  The demand was to migrate `AccessGrant` into the `consent.grant.v1`
  owner-stamped surface; ONE-1606's ratified law is *fold through ADAPTERS,
  never a migration*, and the blueprint (lines 22/25) names
  `create_access_grant` / `revoke_access_grant` as the doors this lane extends.
  The `GrantMintIntentScope::Calendar` rejection on the outbound-mint path is a
  load-bearing fail-closed arm, not a broken path. Banked observation carried
  forward: `GrantMintIntentScope::Calendar` has no consuming door until
  ONE-1815/ONE-1819 destructure it into `AccessGrant::calendar_disclosure` +
  `create_access_grant` — expected under the flat-ticket decomposition.

### FIX-A — `invalid-grant-state` (item 2, P2): scope×capability is one pair, not two axes

This lane widened the scope×capability space from 1×1 to 2×2 while
`AccessGrant::validate` still checked only `(status, revoked_at)`. A grant with
`scope = Calendar` + `capability = CompanionProfileRead` encoded, decoded, and
persisted, then three live paths disagreed about it: `list_calendar_access_grants`
listed it (scope filter), `access_grant_projection_is_active` called it live
(capability filter), and `calendar_disclosure_rung` denied every read.

Fix at the one door every codec/mint/revoke path already passes through:
`AccessGrantScope::required_capability()` states the pairing law
(`Calendar ⇔ CalendarDisclosureRead`, `CompanionProfile ⇔ CompanionProfileRead`)
and `AccessGrant::validate` rejects any other combination with
`Error::InvalidAccessGrantBody("scope and capability are not a matched pair")`.
One chokepoint arm; no call-site patches — `encode_access_grant_body`,
`decode_access_grant_value`, `revoked`, `put_access_grant`, and
`create_access_grant` all inherit it.

Test: `access_grant_scope_and_capability_must_be_a_matched_pair` — both mismatch
directions rejected at `validate`, `encode`, `revoked`, and `create_access_grant`,
plus a mispaired on-disk body decoding fail-closed.

Mutation (pairing gate deleted from `validate`): test FAILED at
`access_grant/tests.rs:395` — red-before confirmed; green after restore.

### FIX-B — `revocation-toctou` (item 3, P2): admit and rewrite the same record

`revoke_calendar_access_grant` checked the scope through `get_access_grant` in a
read transaction, dropped that snapshot, then called `revoke_access_grant`, which
opened a *separate* write transaction and reread the entity. Public
`put_access_grant` could replace the record between the two, so the door could
revoke a `CompanionProfile` grant it never admitted — exactly the promise the
method makes it will not do.

Restructured to a private `Vault::revoke_admitted_access_grant(id, revoked_at,
admit)`: it opens one write transaction, reads and decodes the record, runs the
`admit` gate on *that* decoded grant, and rewrites it revoked — all before
`commit()`. `revoke_access_grant` passes an always-admit gate (behaviour
unchanged); `revoke_calendar_access_grant` passes the Calendar-scope gate and
keeps its `InvalidAccessGrantBody("grant is not a calendar disclosure grant")`
error. No second snapshot exists for a racing put to swap under the check, and a
rejected scope aborts the whole transaction, so no partial revocation lands.

Test: `revoke_calendar_access_grant_admits_and_rewrites_one_record` — the
rejected companion grant is byte-identical afterwards (no partial write), and the
admitted calendar grant is revoked in place and reads back as the returned record.

Mutation (admission gate removed): `revoke_calendar_access_grant_admits_and_rewrites_one_record`
FAILED at `tests.rs:451` and `calendar_grant_registry_lists_and_revokes` FAILED at
`tests.rs:351` — red-before confirmed; green after restore.

Honest scope note: the single-transaction property is *structural* — the gate now
reads the same `wtxn`-decoded record it revokes. The interleaving itself is not
directly asserted, because a deterministic interleave test would require pausing
production code between the old read and write transactions, and a thread-race
test would be a flake source under the flake guard. The mutation above proves the
gate is load-bearing at the revoke door; the atomicity is proved by construction.

### FIX-C — `packet-violation` (item 4, P2): PACKET_AMEND ratified, not extracted

Production changes reach four files outside the five-file ONE-1812 packet.
Per packet law the remedy is ratification, never burning finished work, and
extraction is impossible here: the three foreign-wall files carry *compile-forced*
exhaustive-match arms — without them the crate does not build.

| File | Arm | Nature |
|---|---|---|
| `consent.rs` | `access_grant_scope_selectors` Calendar arm + `access_grant_projection_is_active` accepting `CalendarDisclosureRead` | load-bearing (registry projection) |
| `receipt.rs` | `append_access_grant_scope_fields` Calendar arm | compile-forced |
| `gate.rs` | `standing_outbound_grant_binding_parts` Calendar reject | compile-forced, fail-closed |
| `outbound_grant.rs` | `StandingOutboundGrantScope` Calendar reject | compile-forced, fail-closed |

FIX-A is what makes the `consent.rs` arm sound: `access_grant_projection_is_active`
now filters on a capability that cannot disagree with its scope.

Collision check re-run mechanically by this leg, CLEAN:
- `gate.rs` — GATE-lane wall, no in-flight writer (`w5/cal-gate-prefix` landed as #597).
- `outbound_grant.rs` — ONE-1814 owns it within BK and is not dispatched.
- `consent.rs` / `receipt.rs` — MS-1748 (#603) and CA-1773 (#605) are merged to main;
  `consent.rs` carries no standing BK claim.
- `git merge-tree --write-tree origin/main HEAD` against `origin/main 33c02b331`
  → `2512979968cf1902da7d01f39d2860868d88ea5b`, zero conflicts.

Ratification appended to `/Users/olety/.claude-wave5/decisions.jsonl` as
`{"type":"packet-amend","lane":"BK-1812","status":"RATIFIED","gate2":true}`,
carrying the file list, the compile-forced rationale, and the collision evidence.
It rides the GATE-2 deviation board.

### Gates after the fix round

- `cargo fmt -p oneiron -- --check` — clean.
- `cargo clippy -p oneiron --all-features --lib --tests` — zero warnings, zero errors.
- `cargo test -p oneiron --all-features` — all green; lib `3584 passed; 0 failed; 17 ignored`,
  every integration target and both doctest targets `0 failed`.

Diff stays within the packet plus the ratified four and the two inline test
modules; no `Cargo.toml` / `Cargo.lock` change.
