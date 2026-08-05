# WORKLOG — Cluster A fix-forward, l1-secret custody doors

Branch `ONE-1919-ca-fix`, cut from `42cb5e6` (ONE-1728 L1-STORAGE-SPINE).
Five adjudicated items from the #566 bot wave union adjudication, each a named
commit with its own mutation-verified regression test.

## Gate baseline (established before any edit)

`cargo clippy -p oneiron --all-targets --all-features` on clean `42cb5e6`:
**56 lib warnings + 9 lib-test warnings (6 duplicates), plus 2 hard clippy
ERRORS** — i.e. `-D warnings` was ALREADY RED on the merged tree. Captured to
`/tmp/baseline_warnings.txt`; every stage below is gated on "no new warning
line vs. that baseline", plus the errors fixed where they sat in this lane's
own files.

Pre-existing, charged to no lane (banked, see below): the entire
`crates/oneiron/src/calendar/claims.rs` dead-code block (~53 `never used`
warnings). Out of packet; not touched.

---

## C1 — P1 SECRET_CUSTODY apply-time seal REMOVED

**Trace (confirmed).** `reject_secret_custody_byte()` (`secret_custody.rs:625`)
had ZERO call sites crate-wide — mechanically confirmed: the baseline clippy
run lists `function reject_secret_custody_byte is never used`. The replicated
type gate in `batch.rs` named only `POLICY_MANIFEST | ACCESS_GRANT |
OUTBOUND_GRANT`, so `window.rs::forward_rematerialize`'s generic else-arm
(`vault.batch_in().put_replicated(...)`, `replicated_put_op` sets
`allow_maintenance && allow_reserved_predicate`) carried byte 77 past the gate,
into `store.validate_entity_type(77)` (registry-valid) and on to `apply_put`.
A peer-authored custody body — plaintext `value_bytes` and all — landed in
LMDB. The module's "writes ONLY through `Vault::register_secret`" invariant was
false.

**Fix.** Seal in `batch.rs`'s `apply_ops` Put arm, beside the existing
maintenance-kind rejection, returning the module's own
`reject_secret_custody_byte()`. `register_secret` is unaffected: it writes with
`allow_maintenance: true, allow_reserved_predicate: false`, and the seal keys
on BOTH flags (the CRDT replay shape).

**Completeness.** `InvalidSecretCustodyBody` was NOT in
`quarantine::remote_rejection_reason`, so the new refusal would have classified
as a LOCAL failure and wedged the entire forward-remat pass on one hostile row
(remote-triggerable window DoS). Added the arm — a byte-77 carrier now
quarantines-and-continues, like every other typed remote write-door rejection.
Cannot swallow local corruption: a corrupt on-disk custody row surfaces as
`CorruptedIndex` through `read_secret_custody_in_txn`, never this kind.

**Tests (both mutation-verified — seal disabled ⇒ both FAIL, restored ⇒ both
pass).**
* `secret_custody::tests::replicated_put_door_rejects_secret_custody_byte` —
  both replicated entry points (`batch().put_replicated`, in-txn
  `batch_in().put_replicated`) fail typed, store nothing, and the error
  classifies as `remote_rejection_reason == "InvalidSecretCustodyBody"`.
* `sync::window::tests::forward_remat_quarantines_replicated_secret_custody_carrier`
  — end to end at the named trace: a peer files a custody body plus an ordinary
  TURN row in the window doc; the custody row never reaches LMDB, the ordinary
  row still materializes (count == 1), and exactly one `Entities` quarantine
  record lands with reason `InvalidSecretCustodyBody`.

**Also in this commit (gate hygiene, this lane's own file).** The two clippy
ERRORS and two `unused_mut` warnings that pre-existed in
`secret_custody/tests.rs` (`field_reassign_with_default` at the floor-merge
test, `items_after_statements` for the `drop_key` helper, two `let mut wtxn`).
Fixed in place so the file is warning-clean; no assertion changed.

**Doc.** `reject_secret_custody_byte`'s doc comment claimed doors that never
called it. Rewritten to name the doors that actually reject through it and to
say plainly that the selector and reverse-remat doors are deliberately SILENT
(they have no caller to fail).

Files: `crates/oneiron/src/batch.rs`, `crates/oneiron/src/sync/quarantine.rs`,
`crates/oneiron/src/secret_custody.rs`,
`crates/oneiron/src/secret_custody/tests.rs`,
`crates/oneiron/src/sync/window/tests.rs`.

---

## C2 — P1 export-scrub bypass via malformed CRDT key

**Trace (confirmed).** `sync/window.rs::scrub_secret_custody_carriers` parsed
the map key BEFORE classifying the body:

```rust
let Ok(id) = EntityId::from_hex(raw_key) else { return; };   // early return
if is_secret_custody_record(blob) { custody_ids.insert(id); }
```

The map key is peer-chosen; the type byte is not. A custody body filed under
any non-hex key took the early return, was never counted as custody, and
`export_window_updates_since` shipped it — plaintext `value_bytes` and all.

**Fix.** The BODY decides. `is_secret_custody_record(blob)` runs first; a
matching row with an unparseable key cannot be scrubbed by entity id, so it is
deleted by its raw key and quarantined as the protocol violation it is (hashed
evidence only — the quarantine record stores a payload HASH, never bytes). The
existing removal bookkeeping then pins the window history-free, so the
pre-scrub set-op bytes can never take a raw delta/snapshot path later.

**Test (mutation-verified).**
`sync::window::tests::secret_custody_under_malformed_key_never_leaves_doc_via_export`
files a real custody body under `"not-a-canonical-entity-id"` alongside an
ordinary TURN control, exports to a fresh peer, and asserts:
* the exported BYTES do not contain the secret value anywhere (a raw
  `windows()` scan — the load-bearing assertion, independent of map semantics);
* the peer doc has no such key, the ordinary control still exports;
* the local doc was scrubbed in place and the window is pinned history-free;
* exactly one `Entities` quarantine record with reason
  `InvalidSecretCustodyBody` and the malformed key's own hash/len metadata.

Mutation: restoring the old key-first ordering (malformed arm made a no-op)
fails the test at `exported bytes must not carry the secret value` — the leak
is directly demonstrated, not merely inferred.

Files: `crates/oneiron/src/sync/window.rs`,
`crates/oneiron/src/sync/window/tests.rs`.

---

## C3 — P2 generic read doors return the custody body incl. `value_bytes`

**Trace (confirmed).** `register_secret` writes the value-bearing record into
the ENTITIES store; `Vault::get` stripped only the 25-byte header and handed
back the MessagePack body — which contains `value_bytes` verbatim. `pub(crate)`
on the field stopped only an out-of-crate FIELD read; no caller needed the
field, because the plaintext was in the bytes. The mutation run below prints
the returned body with `hunter2` (`104 117 110 116 101 114 50`) in it.

**Fix.** Typed deny at `Vault::get` and `Vault::get_raw` when the header names
byte 77. The only sanctioned value read stays the bound door
`get_secret_value_in_txn`; the value-less `get_secret_metadata` stays open.

**Seal placement (deliberate asymmetry, documented in `vault.rs`).** The seal
sits on the two PUBLIC doors only. `get_raw_in` (txn-scoped, `pub(crate)`) and
the new `get_raw_unsealed` wrapper stay unsealed, because `sync::window`'s
mirror / scrub / rematerialization passes read raw bytes precisely to look at
the type byte and then refuse, skip, or scrub the row — sealing their reader
would make them fail closed on the very row they exist to remove and turn one
custody carrier into a wedged window. The four `sync::window` call sites were
re-pointed to `get_raw_unsealed`; every other caller keeps the sealed door.

**Serde.** Dropped the `Serialize` derive from `SecretCustodyRecord`: a derived
serializer would emit `value_bytes` into whatever format a caller reached for,
with no door in the way — exactly the leak `Debug` is hand-rolled to prevent.
`Deserialize` went with it (nothing consumes either; the hand-written body
codec is the one serialization of this type, and it exists to write the
vault-resident body). Workspace grep confirms no consumer outside
`secret_custody*`.

**Test (mutation-verified).**
`secret_custody::tests::value_read_goes_through_get_secret_value_in_txn_door`
now asserts both generic doors deny with `InvalidSecretCustodyBody` while the
bound door still returns the value and `get_secret_metadata` still works.
Mutation: disabling both seals fails the test with the plaintext visible in the
assertion message.

Files: `crates/oneiron/src/vault.rs`, `crates/oneiron/src/secret_custody.rs`,
`crates/oneiron/src/secret_custody/tests.rs`,
`crates/oneiron/src/sync/window.rs`,
`crates/oneiron/src/sync/window/tests.rs` (the `seed_secret_custody` fixture
reads through the unsealed reader, with a comment saying why).

---

## C4 — P2 binding scope declared but never enforced

**Trace (confirmed).** `get_secret_value_in_txn` gated on
`rec.binding_for(effector).is_none()`, and `binding_for` matches the effector
STRING only:

```rust
self.bindings.iter().find(|b| b.effector == effector)
```

`binding.scopes` was written at register time, round-tripped by the codec, and
read by NO door. A binding declared for rotation only — or one with an empty
scope list — handed over raw plaintext to anything that named the effector.

**Fix.** `SecretBinding::grants_read()` (checking the new `SECRET_SCOPE_READ`
constant), required at the value door: a matched binding without the read grant
gets the same typed `SecretBindingDenied` an unbound effector gets. Naming the
effector is not the grant; the declared scope is.

The two-branch phrasing in the finding ("non-empty must contain read; empty =
no grant") collapses to one predicate — an empty set contains no read scope —
so that is how it is written. The doc says plainly that an empty scope list is
NOT a wildcard, because reading it as one is exactly how a declared-but-unread
field becomes a hole.

`binding_for` itself is unchanged: it is also the tier-admission lookup, and
the read requirement belongs at the read door, not in the lookup.

**Test (mutation-verified).**
`secret_custody::tests::value_read_requires_a_read_scope_on_the_matched_binding`
registers one record with three bindings — no scopes, `["rotate"]`, and
`["rotate", "read"]` — and asserts deny, deny, read. Mutation: restoring the
old `binding_for(effector).is_none()` gate fails it on the first arm.

Files: `crates/oneiron/src/secret_custody.rs`,
`crates/oneiron/src/secret_custody/tests.rs`.

---

## C5 — P1 malformed floor fails OPEN to the default T2 band

**Trace (confirmed).** `decode_floor_keys`' `tier_at` collapsed
`MapValue::Missing` and `MapValue::Duplicate` to the same `None`, and a
`Present` row whose value would not parse as a tier grade also became `None`:

```rust
MapValue::Present(v) => as_u64(v).and_then(|n| CustodyTier::from_u8(...)),
MapValue::Missing | MapValue::Duplicate => None,
```

`None` means "leave the default", and the defaults are the PERMISSIVE band
(`portable`/`device_bound` = `T0..T2`). So a manifest that intended to pin
portable to `T0` but wrote the row wrong resolved to the wide default, and
`register_secret` then admitted the T2 bindings the floor existed to forbid.
`rotation_max_age_secs` and `env_bindings` failed open the same way (a
present-but-wrong-typed row silently became `None` / was skipped).

**Fix.** Absent stays default — that is what "declares no floor" means.
PRESENT-but-unreadable is an ERROR: wrong MessagePack type, tier grade outside
`0..=2`, or DUPLICATED (the intended value is ambiguous, so there is no
declared value to honour). `decode_floor_keys` returns `Result<Option<_>>` and
`SecretCustodyFloor::resolve` propagates. `Ok(None)` now means only "this body
is not a MessagePack map" — the POLICY_MANIFEST body schema belongs to
`crate::gate`, and a body this module cannot open carries no floor rows.

The direction is the whole point: a floor may only ever narrow, so silently
reverting a declared narrowing is the one failure mode this type exists to
prevent.

**Tests (all three mutation-verified together).** New `put_policy_manifest`
fixture writes a real POLICY_MANIFEST row (store put + type-index row) the way
the engine seeder does, so the floor resolves over exactly the bodies it does
in production.
* `malformed_floor_row_errors_instead_of_defaulting_open` — `portable.max`
  written as the string `"0"`; `resolve` errors, and `register_secret` refuses
  a portable-T2 binding instead of admitting it against the widened default
  (name left free).
* `duplicated_floor_row_errors_because_the_intended_value_is_ambiguous` — two
  `cross_vault.max` rows; `resolve` errors rather than picking one.
* `absent_floor_rows_still_take_the_defaults` — the CONTROL: a present,
  readable manifest declaring no custody rows resolves to the defaults and
  still admits a portable T2 binding. Absence is not malformation.

Mutation: restoring the old collapse-to-`None` fails the first two and leaves
the control green — exactly the asymmetry the fix is about.

Files: `crates/oneiron/src/secret_custody.rs`,
`crates/oneiron/src/secret_custody/tests.rs`.

---

## Final gates

* `cargo fmt --check` — clean.
* `cargo clippy -p oneiron --all-targets --all-features` — zero errors; the
  only warnings are the pre-existing `calendar/claims.rs` dead-code block (B1).
  No warning in any file this lane touched. NOT green under `-D warnings`, and
  could not have been on this tree: see B1.
* `cargo test -p oneiron --all-features --no-fail-fast` — **3598 passed**
  across all binaries; the only failures are the three pre-existing calendar
  tests (B2), verified red on clean `42cb5e6`. Lib count went 3290 → 3297
  (+7 new regression tests, one per fix plus C5's two extra arms and control).
* Flake note: one run of the loaded full suite also reported
  `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`.
  It is green in the run before and after, and 3/3 in isolation. The test
  compares `unix_seconds_now()` captured before the fold against the fold's own
  observation clock, so it is wall-clock-boundary sensitive under load. Nothing
  in this lane touches the authority fold. Banked as B3, not attributed here.

---

## Banked (legitimate maximalism / out-of-packet), one per row

| # | Item | Why banked |
|---|---|---|
| B1 | `crates/oneiron/src/calendar/claims.rs` carries ~53 `never used` dead-code warnings on clean `42cb5e6`, so `cargo clippy -- -D warnings` cannot be green on this tree for ANY lane. | Pre-existing, another lane's packet, charged to no lane. Needs its own mechanical cleanup lane. |
| B3 | `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once` is wall-clock-boundary sensitive: it asserts `migrated >= unix_seconds_now()` captured before the fold, so a loaded parallel run can cross a second boundary. Observed failing once in a loaded full run, green immediately before/after and 3/3 in isolation. | Pre-existing test-design flake in another lane's file; nothing in this lane touches the authority fold. Wants a monotone/injected clock rather than a re-run. |
| B2 | Three tests fail on clean `42cb5e6`: `calendar::claims::tests::calendar_claim_validator_rejects_malformed_shapes`, `calendar::claims::tests::calendar_claims_require_event_subjects`, `claim::tests::write_door_validates_calendar_claim_structure`. VERIFIED by stashing this lane's work, checking out `42cb5e6`, and running the three by name — all three FAIL there. Same root as B1: `validate_calendar_claim_structure` is `never used`, i.e. the calendar write door lost its wiring on main. | Pre-existing red on the merged tree, charged to no lane. It IS a real defect on main and should get a ticket, but fixing it here would be an unrelated packet. |
