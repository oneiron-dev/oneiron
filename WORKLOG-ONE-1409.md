# WORKLOG — ONE-1409 [FED-02] attenuated Delegate tier

Branch `ONE-1409` off `origin/main` @ `070f3b84d` (ONE-1591 #635 merged; the
pact-ceiling check is live in `authorize_sync_selector`).
Worktree `/Volumes/Cinema/w5-lt/ed-1764`.
Blueprint `/Users/olety/.claude-wave5/blueprints/FED-SYNC/ONE-1409.md`.

## What landed

### `/Volumes/Cinema/w5-lt/ed-1764/crates/oneiron/src/federation.rs`
- `FEDERATION_GRANT_BODY_KEYS` grew 5 -> 7 (`expires_at`, `delegated_by`
  appended). `FEDERATION_GRANT_SCHEMA_VERSION` STAYS 1.
- `FEDERATION_GRANT_REQUIRED_KEYS = 5` (private): the head of the key array is
  unconditionally required; the two-key tail is role-conditional.
- `MAX_DELEGATE_TTL_SECS = 7_776_000` (public).
- `FEDERATION_GRANT_FIELDS_FULL` is now an explicit five-key slice, no longer an
  alias of `FEDERATION_GRANT_BODY_KEYS`. MINIMAL/STANDARD are untouched.
  Hydration content and lengths (3/4/5) are unchanged; only the on-disk body grew.
- `FederationGrantRole::Delegate` and `FederationGrantPreset::Delegate`, wire
  string `delegate` on BOTH. `is_admin()` still true only for Owner/Admin.
- `permits_role` is exact: Delegate preset permits only the Delegate role, and
  the Delegate role is rejected by every non-Delegate preset **including Owner**
  (the `Owner => true` arm became `Owner => !matches!(role, Delegate)`; the Admin
  arm gained the Delegate exclusion). Every pre-existing role/preset verdict is
  pinned unchanged by a test that recomputes the old table.
- `FederationGrant` gains `expires_at: Option<u64>` and
  `delegated_by: Option<EntityId>`. `new()` keeps its four-argument signature and
  sets both to `None`.
- `attenuated_delegate(parent, member_ref, now_secs, expires_at_secs)`: parent
  must validate and be `is_admin()`; ceiling is `now_secs.checked_add(MAX)` and
  rejects on overflow; window is `now < expires_at <= now + MAX`. Inherits the
  parent's scope, sets `delegated_by = parent.member_ref` (the parent's
  PRINCIPAL, never a grant entity id).
- `confers_at(now_secs)`: `None` -> always true; `Some(e)` -> `now < e`, so the
  expiry second itself denies.
- `validate()` now also enforces role-conditional presence (both fields required
  for Delegate, both forbidden otherwise) and rejects `expires_at == Some(0)`.
- Codec: encode appends the two keys only when present (a non-delegate body is
  byte-identical to pre-Delegate output); `validate_body_keys` still rejects
  unknown/duplicate keys but only requires the five-key head; decode reads
  `expires_at` via `as_u64` and `delegated_by` via a new
  `decode_canonical_entity_ref`.

### `/Volumes/Cinema/w5-lt/ed-1764/crates/oneiron/src/error.rs`
- ONE new variant `SyncSelectorValidation::GrantExpired`, display
  `"sync selector grant expired"`, placed adjacent to `GrantInactive`.

### `/Volumes/Cinema/w5-lt/ed-1764/crates/oneiron/src/sync/selector.rs`
- `pub(crate) fn authorize_sync_selector_at(vault, grant_scope, selector, now_secs)`;
  the public `authorize_sync_selector` passes `crate::unix_seconds_now()`.
- `authorize_selector_export` took a `now_secs` parameter; its two export
  callers (`filtered_window_doc`, `guest_share_envelope_body`) pass
  `crate::unix_seconds_now()`.
- The 1591 ceiling arm was reshaped from an early `return Ok(Unfiltered)` into a
  `match` that binds `EmptyAxis`, so the new expiry arm runs LAST on every path
  including the unpacted one. Door order is now
  activation -> pact ceiling -> delegate expiry, pinned by a test.

## Decisions taken inside the blueprint (no deviations)

1. **Expiry arm placement.** The blueprint requires the expiry arm to run after
   the 1591 ceiling. The pre-existing ceiling code returned early for unpacted
   grants, so a literal append would have skipped expiry for exactly the unpacted
   delegates. Restructured to a bound `match` instead. Unpacted delegates ARE
   gated: legacy-allow covers a missing PACT, never a lapsed delegation.
2. **`delegated_by` is canonical-hex-only.** Done-means 7 says "canonical
   32-character EntityId hex string". `EntityId::from_hex` is case-insensitive,
   so a new `decode_canonical_entity_ref` adds the `to_hex()` round-trip check
   (same shape the pact-scope decoder already uses in `decode_hex_id_array`).
   `member_ref` deliberately keeps its existing non-canonical-tolerant decode —
   it has shipped bodies behind it; `delegated_by` does not.
3. **`expires_at == 0` rejects in `validate()`, not only at mint.** A mint can
   never produce it (`expires_at > now >= 0`), but a hand-built body can, and
   done-means 7 requires a positive u64.
4. **Parent expiry is NOT re-checked in `attenuated_delegate`.** A Delegate
   parent is already rejected by the `is_admin()` gate, and Owner/Admin parents
   carry no expiry by construction (role-conditional law). Adding a
   `parent.confers_at(now)` call would be unreachable code.
5. **Done-means 5 (old five-key readers fail closed)** is tested as the property
   that makes it true — a delegate body carries exactly 2 keys outside the
   five-key head, and a non-delegate body carries 0 — rather than an impossible
   cross-version runtime assertion. Documented in the test comment as directed.

## PACKET

Committed tree touches exactly the packet:
`federation.rs`, `federation/tests.rs`, `sync/selector.rs`,
`sync/selector/tests.rs`, `error.rs`. No PACKET_AMEND candidates.
`authority.rs` and `sync/lease.rs` untouched (read-only, never opened for edit).
`Cargo.toml` untouched; `Cargo.lock` NEVER staged.

Every `FederationGrant` construction site outside the packet
(`oneiron-server/src/handler/tests.rs`, `oneiron/src/receipt/tests.rs`) goes
through `new()`, whose signature is unchanged — no out-of-packet edit was needed.

## Flagged to the orchestrator (not mine, not fixed here)

- **`Cargo.lock` drift on `origin/main`.** The first `cargo check` in this
  worktree re-locked 16 packages (`icalendar`, `rrule`, `chrono`, `chrono-tz`,
  `phf`, `iana-time-zone`, windows/core-foundation transitives). `Cargo.toml` was
  not modified by this lane, so `main`'s committed lock is out of sync with
  `main`'s committed manifest — most likely a calendar-lane dep addition that
  landed without a lock update. Left unstaged per the never-commit-lock law;
  worth a mechanical fix on the branch that owns it.
- **Flaky test outside the packet:**
  `embed::tests::partial_remote_completion_is_logged_when_local_batch_fails`
  went red once on the first full `--all-features` run and green on the isolated
  re-run and on a full re-run of the same tree. It captures warnings through a
  THREAD-LOCAL `tracing::subscriber::with_default`, so work reaching another
  thread escapes the capture — a parallelism-dependent flake, not a regression.
  Charged to no lane.

## Gates

- `cargo fmt -p oneiron` — clean.
- `cargo clippy -p oneiron --all-features --all-targets` — clean, zero warnings.
- `cargo test -p oneiron --all-features` — **GREEN**: 3999 lib tests passed,
  0 failed, 8 ignored, plus every integration target green.

## Done-means coverage

| # | Where |
|---|---|
| 1 | `federation::tests::attenuated_delegate_round_trips_byte_stable` |
| 2 | `sync::selector::tests::delegate_selector_denies_from_the_expiry_second`, `federation::tests::confers_at_denies_from_the_expiry_second_onward` |
| 3 | `federation::tests::delegate_minting_never_self_widens`, `delegate_is_a_one_to_one_role_preset_pair` |
| 4 | `federation::tests::role_conditional_fields_are_required_and_forbidden` |
| 5 | `federation::tests::delegate_body_grows_while_schema_version_and_hydration_hold` |
| 6 | `federation::tests::delegate_ttl_bounds_are_exact` |
| 7 | `federation::tests::delegate_body_decode_fails_closed_on_new_keys` |
| 8 | `federation::tests::role_conditional_fields_are_required_and_forbidden` |
| 9 | `federation::tests::delegate_body_grows_while_schema_version_and_hydration_hold` |
| 10 | full-suite gate above |
| door order | `sync::selector::tests::delegate_expiry_is_the_last_arm_of_the_door`, `public_authorize_reads_the_wall_clock` |

## Land-and-hold

Committed on `ONE-1409`, NOT pushed, NOT merged. The CY orchestrator publishes.
SWEEP-B rows B2/B3 against this ticket remain UNADJUDICATED and ledgered open —
the FINAL blueprint was built as written; no sweep cuts were re-derived.

## SIMPLIFY pass (K3, tip 96655fe31)

One deletion, no additions:

- `FederationGrant::attenuated_delegate`: removed the trailing
  `delegate.validate()?` re-check. Unreachable-fail by construction — the
  parent's scope is validated two statements up, the Delegate role/preset pair
  is the 1:1 `permits_role` arm, both role-conditional fields are `Some`, and
  `expires_at_secs > now_secs >= 0` rules out the zero-expiry clause. The
  struct's `pub` fields make any construction-time invariant unenforceable
  regardless; encode and decode remain the validating doors. No law weakened:
  the role-conditional key law, TTL bounds, and door ordering are untouched,
  and no test assertion or public API changed.

Everything else read clean: the `optional_value`/`required_value` split, the
`FEDERATION_GRANT_REQUIRED_KEYS` head-count in `validate_body_keys`, the
canonical-hex decode pin, and the selector match-restructure are already the
minimal shape. The verbose doc comments carry ratified design rationale
(fail-closed forward compat, 1:1 pair, parent-principal semantics) and stay.

Gates after the pass: `cargo fmt -p oneiron -- --check` clean; `cargo clippy
-p oneiron --all-features` clean, zero warnings; `cargo test -p oneiron
--all-features --lib` GREEN (3999 passed, 0 failed, 8 ignored).
