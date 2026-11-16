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
//!
//! The erase-reach review (Astra, 15 Nov 19:16) added three: a manifest
//! keeps no part of another map, a capture that reads only part of the
//! history names no owner, and a manifest whose parts join to no row
//! proves no other row, so it places by its key and defers nothing.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use oneiron::EntityId;
use oneiron::test_doors::sync_parted_row_binding::{
    PARTED_MAPS, PartedMap, checkpoint_refusal, discard_projection, parted_pin_fitting_one_part,
    parted_turn_behind_an_unlisted_root, parted_window, parted_window_of_no_row,
    repo_parts_listed_by_a_pin, turn_program_arming_holder,
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

/// The checkpoint capture of the same window keeps it whole, with no owner
/// hint. A repo head, a pin and a turn reach the binding, which refuses the
/// window as undecodable. A room side row's key is a payload key, refused
/// before any binding, so its capture named no holder before the binding
/// too: for that map this is a guard.
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
    if map != PartedMap::RoomSideRow {
        assert_eq!(refusal.reason, "Undecodable", "{map:?}");
    }
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

/// A pin a scrub left in parts under its own key, though its joined pin
/// fits in one part, places as before: the codec refuses that spelling,
/// which proves no other pin.
#[test]
fn document_pin_fitting_one_part_places_as_before() {
    let row = EntityId::now();
    let (other, _) = two_rows();
    let window = parted_pin_fitting_one_part(row).expect("the window writes");
    let gone = discard_projection(&window, &[row]).expect("the projection runs");
    assert!(
        gone.starts_with("erased "),
        "its holder's discard erases it, got {gone}"
    );
    assert_eq!(
        discard_projection(&window, &[other]).expect("the projection runs"),
        "unchanged",
        "another row's discard leaves it"
    );
    let refusal = checkpoint_refusal(&window).expect("the capture runs");
    assert!(
        refusal.as_ref().is_none_or(|refusal| match refusal.owner {
            Some(owner) => owner == row,
            None => refusal.reason != "Undecodable",
        }),
        "the capture splits it or names its own holder, got {refusal:?}"
    );
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

/// A manifest keeps no part of another map (Astra F1): a pin manifest that
/// lists a repo head's parts, with none of its own, leaves the head's
/// discard erasing every repo part, as with no pin.
#[test]
fn manifest_keeps_no_part_of_another_map() {
    let (row, pin_holder) = two_rows();
    let alone = parted_window(PartedMap::RepoHead, row, row).expect("the window writes");
    let listed = repo_parts_listed_by_a_pin(row, pin_holder).expect("the window writes");
    assert_eq!(
        discard_projection(&listed, &[row]).expect("the projection runs"),
        discard_projection(&alone, &[row]).expect("the projection runs"),
        "the repo head's parts go with it, whatever a pin manifest lists"
    );
}

/// A capture whose binding pass stops at a root outside the window's maps
/// reads only part of the history (Astra F2): it cannot clear the key's
/// holder of a parted row, so it names no owner.
#[test]
fn checkpoint_names_no_owner_when_the_binding_reads_part_of_the_history() {
    let (keyed, body) = two_rows();
    let window = parted_turn_behind_an_unlisted_root(keyed, body).expect("the window writes");
    let refusal = checkpoint_refusal(&window)
        .expect("the capture runs")
        .expect("a window with a root outside its maps stays whole");
    assert_eq!(
        refusal.owner, None,
        "the capture named {:?} (keyed {keyed:?}, body {body:?})",
        refusal.owner
    );
}

/// A manifest whose parts join to bytes that read as no row proves no other
/// row (Astra F3): it places by its key as before, so an unrelated discard
/// leaves the window and its key's holder's discard erases it.
#[test]
fn parted_row_of_no_row_places_by_its_key() {
    for map in PARTED_MAPS {
        let (keyed, other) = two_rows();
        let window = parted_window_of_no_row(map, keyed).expect("the window writes");
        assert_eq!(
            discard_projection(&window, &[other]).expect("the projection runs"),
            "unchanged",
            "{map:?}: an unrelated discard leaves it"
        );
        let gone = discard_projection(&window, &[keyed]).expect("the projection runs");
        assert!(
            gone.starts_with("erased "),
            "{map:?}: its key's holder's discard erases it, got {gone}"
        );
    }
}

/// A repo head whose parts join to no manifest keeps its window whole under
/// its CODE entity, as before the binding (FIX 10278's refusal): it proves
/// no other head.
#[test]
fn repo_head_of_no_manifest_checkpoint_names_its_code() {
    let keyed = EntityId::now();
    let window = parted_window_of_no_row(PartedMap::RepoHead, keyed).expect("the window writes");
    let refusal = checkpoint_refusal(&window)
        .expect("the capture runs")
        .expect("a head of no manifest keeps its window whole");
    assert_eq!(refusal.owner, Some(keyed));
    assert_eq!(refusal.reason, "Undecodable");
}
