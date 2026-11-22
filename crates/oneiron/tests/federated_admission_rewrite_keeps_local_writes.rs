//! A key this vault's machines wrote keeps its value against a later admitted
//! write (FIX FEDERATED-ADMISSION-FRESH-DOC-LAMPORT-TIE, review P1 on #10291).
//!
//! Before: the write over a window after an admitted part imports took every
//! peer whose first change in the window depended on nothing at Lamport 0 for
//! an admission. A machine's first write in an empty window (each month's
//! window starts empty) is such a change, so a later admitted write to a key
//! that machine edited was written again over the machine's edit.
//! After: only a change an admission marked as its own (or such a write's) is
//! an admission's; a key any other writer set keeps its value.
//!
//! - `an_edit_by_the_window_docs_first_writer_keeps_its_value`: red on #10291's
//!   head 006e72ab051 (the part's value is written again over the edit), green
//!   on the fix.
//! - `an_edit_synced_from_another_machine_keeps_its_value`: the same for a
//!   machine whose writes reach the window by sync, under a peer id other than
//!   the window doc's own: red on 006e72ab051, green on the fix.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test federated_admission_rewrite_keeps_local_writes`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::test_doors::federation_admitted_rewrite::admitted_rewrite;

/// A row the machine writes first in the window.
const ROW_X: &str = "0193a1b2c3d4e5f60718293a4b5c6d01";
/// The row the peer delivers twice and the machine edits between.
const ROW_C: &str = "0193a1b2c3d4e5f60718293a4b5c6d02";
const PEER_FIRST: &[u8] = b"peer image one";
const PEER_SECOND: &[u8] = b"peer image two";
const LOCAL_EDIT: &[u8] = b"local edit";

/// Writes `value` under `key` in `doc`'s entities map and commits.
fn write(doc: &LoroDoc, key: &str, value: &[u8]) {
    doc.get_map("entities")
        .insert(key, LoroValue::Binary(value.to_vec().into()))
        .expect("FIXTURE: entity row inserts");
    doc.commit();
}

/// The bytes `doc` holds under `key` in its entities map.
fn row(doc: &LoroDoc, key: &str) -> Option<Vec<u8>> {
    match doc.get_map("entities").get(key) {
        Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// An admitted part writing `value` under `key`, authored in a fresh document
/// as admission authors one: its ops start at Lamport 0.
fn admitted_part(key: &str, value: &[u8]) -> Vec<u8> {
    let doc = LoroDoc::new();
    write(&doc, key, value);
    doc.export(ExportMode::all_updates())
        .expect("FIXTURE: the part exports")
}

/// Imports the peer's second part into `window` and returns the write over
/// the window its import makes.
fn second_delivery(window: &LoroDoc) -> Option<Vec<u8>> {
    let held = window.oplog_vv();
    let second = admitted_part(ROW_C, PEER_SECOND);
    window
        .import(&second)
        .expect("FIXTURE: the second part imports");
    assert_eq!(
        row(window, ROW_C).as_deref(),
        Some(LOCAL_EDIT),
        "FIXTURE: the edit, at a higher Lamport, outranks the second part's write"
    );
    admitted_rewrite(window, &second, &held).expect("FIXTURE: the part decodes")
}

#[test]
fn an_edit_by_the_window_docs_first_writer_keeps_its_value() {
    // The machine's first write in the empty window depends on nothing and
    // sits at Lamport 0, as an admission's first write does.
    let window = LoroDoc::new();
    write(&window, ROW_X, b"x");
    window
        .import(&admitted_part(ROW_C, PEER_FIRST))
        .expect("FIXTURE: the first part imports");
    assert_eq!(
        row(&window, ROW_C).as_deref(),
        Some(PEER_FIRST),
        "FIXTURE: the first part lands"
    );
    write(&window, ROW_C, LOCAL_EDIT);
    let rewrite = second_delivery(&window);
    assert!(
        rewrite.is_none(),
        "REWROTE-LOCAL-EDIT: the second part's value is written again over the edit of the machine that first wrote the window"
    );
}

#[test]
fn an_edit_synced_from_another_machine_keeps_its_value() {
    // Another machine of the vault wrote the window first; its writes reach
    // this window doc by sync, under its own peer id.
    let machine = LoroDoc::new();
    write(&machine, ROW_X, b"x");
    let first = admitted_part(ROW_C, PEER_FIRST);
    machine
        .import(&first)
        .expect("FIXTURE: the machine imports the first part");
    write(&machine, ROW_C, LOCAL_EDIT);
    let window = LoroDoc::new();
    window
        .import(
            &machine
                .export(ExportMode::all_updates())
                .expect("FIXTURE: the machine's window exports"),
        )
        .expect("FIXTURE: the window syncs the machine's writes");
    assert_ne!(
        window.peer_id(),
        machine.peer_id(),
        "FIXTURE: the edit's peer is not the window doc's own"
    );
    let rewrite = second_delivery(&window);
    assert!(
        rewrite.is_none(),
        "REWROTE-SYNCED-EDIT: the second part's value is written again over another machine's edit"
    );
}
