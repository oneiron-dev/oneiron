//! A parted window row is bound to its key through its joined row (UC-10
//! PR 1; Engine RULING UC10-PR1-PREMISE = A, 15 Nov 17:45). Four window maps
//! carry a row in parts: a repo head, a document pin, a room turn, a room
//! side row. Their manifests name no id, so a manifest filed under one
//! row's key whose parts join to another row is placed by the key's holder.
//!
//! The BASE-window discard projection erased by that holder: it kept the
//! content of the discarded row the parts join to, and erased it when the
//! key's holder went. It now defers the window. The checkpoint capture
//! named the key's holder on the whole window; it now names none. A correct
//! parted row places as before. A turn program row is placed by its body,
//! whatever its key (the D5 guard).
#![cfg(all(oneiron_test_support, feature = "sync"))]

use oneiron::EntityId;
use oneiron::test_doors::sync_parted_row_binding::{
    PARTED_MAPS, PartedMap, checkpoint_refusal, discard_projection, parted_window,
    turn_program_arming_holder,
};

const DEFERRED: &str = "deferred: a parted row whose parts join to a row its key does not name";

/// Two distinct rows: the one whose key files the manifest, and the one its
/// parts join to.
fn two_rows() -> (EntityId, EntityId) {
    let keyed = EntityId::now();
    let mut body = EntityId::now();
    while body == keyed {
        body = EntityId::now();
    }
    (keyed, body)
}

/// The discard projection of a manifest filed under `keyed`'s key whose
/// parts join to `body`'s row defers, whichever of the two is discarded.
fn discard_defers_on_mismatch(map: PartedMap) {
    let (keyed, body) = two_rows();
    let window = parted_window(map, keyed, body).expect("the window writes");
    let body_gone = discard_projection(&window, &[body]).expect("the projection runs");
    assert_eq!(
        body_gone, DEFERRED,
        "{map:?}: discarding the row the parts join to must defer the window, not keep its parts"
    );
    let key_gone = discard_projection(&window, &[keyed]).expect("the projection runs");
    assert_eq!(
        key_gone, DEFERRED,
        "{map:?}: discarding the key's row must defer the window, not erase another row's parts"
    );
}

/// The checkpoint capture of the same window keeps it whole, undecodable,
/// with no owner hint.
fn checkpoint_names_no_owner_on_mismatch(map: PartedMap) {
    let (keyed, body) = two_rows();
    let window = parted_window(map, keyed, body).expect("the window writes");
    let refusal = checkpoint_refusal(&window)
        .expect("the capture runs")
        .expect("a mismatched parted row keeps its window whole");
    assert_eq!(
        refusal.owner, None,
        "{map:?}: the capture named the key's holder {:?} (keyed {keyed:?}, body {body:?})",
        refusal.owner
    );
    assert_eq!(refusal.reason, "Undecodable", "{map:?}");
}

#[test]
fn repo_head_discard_defers_on_mismatch() {
    discard_defers_on_mismatch(PartedMap::RepoHead);
}

#[test]
fn document_pin_discard_defers_on_mismatch() {
    discard_defers_on_mismatch(PartedMap::DocumentPin);
}

#[test]
fn room_turn_discard_defers_on_mismatch() {
    discard_defers_on_mismatch(PartedMap::RoomTurn);
}

#[test]
fn room_side_row_discard_defers_on_mismatch() {
    discard_defers_on_mismatch(PartedMap::RoomSideRow);
}

#[test]
fn repo_head_checkpoint_names_no_owner_on_mismatch() {
    checkpoint_names_no_owner_on_mismatch(PartedMap::RepoHead);
}

#[test]
fn document_pin_checkpoint_names_no_owner_on_mismatch() {
    checkpoint_names_no_owner_on_mismatch(PartedMap::DocumentPin);
}

#[test]
fn room_turn_checkpoint_names_no_owner_on_mismatch() {
    checkpoint_names_no_owner_on_mismatch(PartedMap::RoomTurn);
}

#[test]
fn room_side_row_checkpoint_names_no_owner_on_mismatch() {
    checkpoint_names_no_owner_on_mismatch(PartedMap::RoomSideRow);
}

/// A correct parted row places as before: its holder's discard erases its
/// manifest and every part, another row's discard leaves it, and the
/// capture splits it or names its own holder.
#[test]
fn correct_parted_rows_place_as_before() {
    for map in PARTED_MAPS {
        let row = EntityId::now();
        let (other, _) = two_rows();
        let window = parted_window(map, row, row).expect("the window writes");
        let gone = discard_projection(&window, &[row]).expect("the projection runs");
        let erased: usize = gone
            .strip_prefix("erased ")
            .and_then(|count| count.parse().ok())
            .unwrap_or_else(|| panic!("{map:?}: its holder's discard erases it, got {gone}"));
        assert!(
            erased >= 2,
            "{map:?}: the manifest and its parts go, got {erased}"
        );
        assert_eq!(
            discard_projection(&window, &[other]).expect("the projection runs"),
            "unchanged",
            "{map:?}: another row's discard leaves it"
        );
        let refusal = checkpoint_refusal(&window).expect("the capture runs");
        assert!(
            refusal.as_ref().is_none_or(|refusal| match refusal.owner {
                Some(owner) => owner == row,
                None => refusal.reason != "Undecodable",
            }),
            "{map:?}: the capture splits it or names its own holder, got {refusal:?}"
        );
    }
}

/// D5: a turn program arming row filed under another registration's key is
/// placed under the actor its body names, never one its key chose.
#[test]
fn turn_program_arming_places_by_its_body() {
    let (keyed, registration) = two_rows();
    let actor = EntityId::now();
    assert_eq!(
        turn_program_arming_holder(keyed, registration, actor).expect("the row writes"),
        Some(actor)
    );
}
