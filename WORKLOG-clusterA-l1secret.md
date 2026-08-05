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

## Banked (legitimate maximalism / out-of-packet), one per row

| # | Item | Why banked |
|---|---|---|
| B1 | `crates/oneiron/src/calendar/claims.rs` carries ~53 `never used` dead-code warnings on clean `42cb5e6`, so `cargo clippy -- -D warnings` cannot be green on this tree for ANY lane. | Pre-existing, another lane's packet, charged to no lane. Needs its own mechanical cleanup lane. |
