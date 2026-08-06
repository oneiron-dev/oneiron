# WORKLOG — ONE-1783 [CAL-01] TZ-at-the-border module

Branch `ONE-1783`, cut off `origin/main` `e356021e0` (1782 / 1791 / 1789 merged).
Blueprint: `~/.claude-wave5/blueprints/CAL/ONE-1783.md`. Claims: `~/.claude-wave5/blueprints/CAL/CLAIMS.md`.

## Packet (⊆ CLAIMS.md ONE-1783 rows)

| File | Mode |
|---|---|
| `crates/oneiron/src/calendar/tz.rs` | CREATE |
| `crates/oneiron/src/calendar/mod.rs` | MODIFY — four TZ `CalendarError` variants + `pub mod tz` + re-export |
| `crates/oneiron/Cargo.toml` | MODIFY — shared calendar dep reservation |

`git diff --name-only` = `Cargo.lock` (never committed), `crates/oneiron/Cargo.toml`,
`crates/oneiron/src/calendar/mod.rs`; untracked `crates/oneiron/src/calendar/tz.rs`.
No stray. No new `tests/` file (none is claimed by this ticket) — the eight named tests
live in `calendar/tz.rs`'s `#[cfg(test)] mod tests`.

## What landed

Public API, no third-party type in any signature or field:

```rust
pub struct WallTime { pub y: i32, pub mo: u8, pub d: u8, pub h: u8, pub mi: u8, pub s: u8 }
pub fn wall_to_utc(w: &WallTime, tz: &str) -> Result<u64, CalendarError>
pub fn utc_to_wall(utc: u64, tz: &str) -> Result<WallTime, CalendarError>
```

Re-exported from `calendar/mod.rs` as `pub use tz::{WallTime, utc_to_wall, wall_to_utc}`,
so the done-means surface is `oneiron::calendar::{WallTime, CalendarError, wall_to_utc, utc_to_wall}`.
`chrono` / `chrono-tz` enter through exactly two private `use` lines in `tz.rs` and nowhere
else in the workspace (oracle below).

`CalendarError` stays the single home in `calendar/mod.rs` and gained exactly the four
timezone variants in blueprint order: `UnknownTimeZone { tz }`, `InvalidWallTime`,
`NonexistentWallTime { wall, tz }`, `TimestampOutOfRange { utc }`. No `AmbiguousWallTime`.
`tz.rs` defines no local error type.

Policy, as ratified: spring-forward gap → typed `NonexistentWallTime`, never a silent
shift into the adjacent hour; fall-back fold → the earlier of the two UTC instants
(pre-transition offset), deterministically, as an `Ok`; unknown zone → typed error,
never a silent UTC fallback (case-mangled real zones included).

## Deviations and under-definitions — declared, not absorbed

1. **PACKET_AMEND CANDIDATE — `reqwest` + `oneiron-vault-contract` deps NOT appended.**
   `CLAIMS.md`'s shared/seam row for `crates/oneiron/Cargo.toml` lists `icalendar`,
   `rrule`, `chrono`, `chrono-tz`, **plus** `reqwest` (rustls, default-features off) and
   the `oneiron-vault-contract` path dep, and states ONE-1784 consumes the `reqwest`
   reservation without reopening Cargo files. The blueprint's Shape section, its keystone
   `Cargo.toml` block, and the dispatch brief's own parenthetical all name only the first
   four. I landed the blueprint set and left the other two, because:
   - `reqwest` 0.13 pulls `tokio` unconditionally. This crate deliberately keeps `tokio`
     optional behind the `sync` feature (see the "BASE deps (not sync-gated)" comment in
     `Cargo.toml`). Landing `reqwest` here silently promotes `tokio` + `hyper` + `rustls`
     into the non-sync base build for a consumer that does not exist yet. That is an
     architecture-shaped change, not a name reservation.
   - `reqwest` 0.13's TLS feature is `rustls`, not the `rustls-tls` the row names — the
     row was written against 0.12, so it needs re-ratification regardless.
   - `oneiron-vault-contract` has no consumer in this crate at this layer.
   **Ask:** ratify either (a) a one-line Cargo amendment on ONE-1784 when it actually
   needs the fetcher, or (b) an amended reservation here specifying `reqwest = { version
   = "0.13", default-features = false, features = ["rustls"] }` and whether `tokio` in
   the base build is intended. `PACKET ⊆ CLAIMS.md` holds either way — this is a subset,
   not a stray.

2. **`CalendarError` derive widened** from `#[derive(Debug, thiserror::Error)]` (ONE-1782's
   shell) to `#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]`. Blueprint-directed
   — the keystone skeleton shows exactly that derive set — and additive/non-breaking. It is
   what lets the tests assert whole error values (`assert_eq!(…, Err(NonexistentWallTime{…}))`)
   instead of a `matches!` shape check that would not catch a wrong payload.

3. **UNDERDEFINED (resolved): pre-epoch wall time in `wall_to_utc`.** The blueprint pins
   `TimestampOutOfRange { utc: u64 }` for `utc_to_wall`'s oversized input and says
   "convert the non-negative timestamp via `u64::try_from`", but does not name the error
   for the negative case — and a negative instant has no `u64` to put in that variant.
   Resolved as `InvalidWallTime`: the wall time is not representable in the engine's `u64`
   UTC model, which is a property of the input civil time, not of a timestamp we never
   obtained. Documented in the `wall_to_utc` rustdoc and pinned by
   `invalid_civil_date_is_typed_error` (`1969-12-31T23:59:59` → `InvalidWallTime`,
   `1970-01-01T00:00:00Z` → `Ok(0)`).

4. **UNDERDEFINED (resolved): leap seconds.** CAL-00's `calendar.wall_time` admits `s` in
   `0..=60`; `chrono` has no civil second 60. `s == 60` therefore returns `InvalidWallTime`.
   Storable is not the same as convertible; documented in the module header and pinned by
   `invalid_civil_date_is_typed_error`.

5. **`default-features = false` on `chrono` is intent, not an achieved floor.** `rrule`
   0.14 depends on `chrono` with defaults, so feature unification resolves `chrono` with
   `clock` (and pulls `iana-time-zone`). The border never calls a clock API; the flag
   states this crate's own need. The `Cargo.toml` comment says so explicitly rather than
   claiming a tree-wide guarantee. `cargo tree -p oneiron -e features -i chrono` is the
   receipt.

6. **No `From<CalendarWallTimeValue> for WallTime` bridge added.** Considered and rejected
   as scope: the blueprint's `wall_time_claim_fields_bridge_without_third_party_types`
   done-means asks the test to *construct* `WallTime` from the scalar claim shape — the
   point is that a plain field copy suffices and no bridge type is needed. The two structs
   stay independent (claims layer = storage, border layer = conversion), so there is still
   exactly one timezone representation.

7. **"Proves no `AmbiguousWallTime` variant exists" satisfied by definition, not by an
   exhaustive in-crate match.** An exhaustive `match` over `CalendarError` inside this
   crate would be a real compile-time oracle, but it would break ONE-1785 and ONE-1784 the
   moment they append their variants — a tripwire aimed at my own stack. The fold test
   instead pins the substantive property: a fold returns `Ok(earliest)` deterministically,
   so no caller ever has an ambiguity branch to write. Variant-set exactness is a source
   fact in `calendar/mod.rs` and is covered by the blueprint's own append-order law.

## Dependency reservation appended

```toml
chrono = { version = "0.4", default-features = false, features = ["std"] }
chrono-tz = "0.10"
icalendar = "0.17"
rrule = "0.14"
```

Resolved: chrono 0.4.45, chrono-tz 0.10.4, icalendar 0.17.13, rrule 0.14.0. All build on
the workspace MSRV (1.96, edition 2024). `icalendar` (CAL-02/CAL-04) and `rrule` (CAL-03)
are unconsumed here by design — the reservation exists so the stacked layers never reopen
this manifest. `Cargo.lock` regenerates and is **not committed**.

## Evidence

- `cargo fmt --all` clean.
- `cargo clippy -p oneiron --all-targets --all-features -- -D warnings` clean.
- `cargo test -p oneiron --all-features --lib calendar::tz` → **8 passed, 0 failed**.
- `cargo test -p oneiron --all-features` → 43 test binaries, **all `ok`**, zero `FAILED`
  lines; lib alone 3571 passed / 0 failed / 17 ignored (`/tmp/1783-final-gate.log`).
  **Flake note (flake-guard):** the first full-crate run showed `3570 passed; 1 failed` in
  the lib binary. Two subsequent runs on the identical tree were fully green, so it is
  charged as a flake, not to this lane. It cannot plausibly be this lane's: the eight
  `calendar::tz` tests are pure functions with no vault, no I/O and no shared state, they
  finish in 0.00s, and they passed in every run including the red one. The suspect class is
  the crate's known LMDB/parallel-vault surface (`vault::tests::*`,
  `vault_open_drop_cycles_survive_pthread_key_limit` is already a >60s outlier). The name
  was lost to a grep filter on the first run and did not recur; flagging rather than
  suppressing.

- `cargo check -p oneiron` (default features) and `cargo check --workspace --all-features
  --all-targets` both finish clean. The one default-features warning —
  `function 'facet_of_endpoints_provably_off_table' is never used` at
  `crates/oneiron/src/batch.rs:4348` — is **pre-existing and not this lane's**: `batch.rs`
  is a lane NON-CLAIM and is untouched by this diff. It is the already-named dead
  non-sync-stub recipe defect, charged to no lane; recorded here so the screen does not
  re-attribute it.

**Pinned instants verified independently** of the crate under test, against system tzdata
(`zdump -v Europe/London | grep 2026`, `TZ=UTC date -r <epoch>`):
London springs forward 2026-03-29 01:00 UT (local 01:00 → 02:00) and falls back
2026-10-25 01:00 UT (local 02:00 BST → 01:00 GMT); New York springs forward 2026-03-08
(local 02:00 → 03:00). The fold's two instants are 00:30Z and 01:30Z; the border returns
00:30Z = 1 792 888 200.

**Mutation checks** (applied, observed failing, reverted) — the two policy tests bite:

| Mutation | Test that failed |
|---|---|
| `Ambiguous(_earlier, later) => later` (pick the late offset) | `wall_to_utc_resolves_dst_fold_to_earliest_offset` |
| `None => `silently retry the civil time +1h` (coerce the gap) | `wall_to_utc_rejects_dst_gap` |

Both are restored; `git diff` on `tz.rs` after restore is empty and the suite is green again.

## Oracles

- **Public-API oracle.** `rg '^\s*pub\s.*\b(chrono\|chrono_tz\|icalendar\|rrule)::' crates/`
  → no hits, whole workspace. `rg -e '\b(chrono|chrono_tz|icalendar|rrule)::' -e '^\s*use
  (chrono|…)\b' crates/` → hits only `crates/oneiron/src/calendar/tz.rs`, lines 36-37
  (`use chrono::{…}`, `use chrono_tz::Tz`). Nothing leaks past `calendar/`.
- **Core-purity oracle.** The diff touches no `src/temporal.rs`, `src/store.rs`,
  `src/batch.rs`, `src/blob_artifact.rs`, `src/registry.rs`, `src/edge.rs`, or
  `src/lib.rs`. Confirmed by `git diff --name-only` above — the core index stays `u64` UTC
  and no crate-root export was needed (the done-means surface is the `calendar` module
  path).

## Notes for the stack

- CAL-03 (`series.rs`, ONE-1785) consumes this border and must not re-derive timezone
  conversion; `rrule` is already reserved.
- The next `CalendarError` writer is ONE-1785 (`InvalidRecurrenceRule { rule }`,
  `InvalidRecurrenceWindow`), then ONE-1784. Append after `TimestampOutOfRange`.
- Cross-lane edge `1783 → 1823` (BK-00 tz border compile dep) is now satisfiable once this
  merges.
