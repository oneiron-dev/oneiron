//! A whole window row is bound to its key (FIX
//! SYNC-DISCARD-KEEPS-UNBOUND-WHOLE-ROW; Engine RULING UC10-PR1-PREMISE =
//! A, 15 Nov 17:45: "the window defers: its projection stays owed").
//!
//! A document pin, a room turn, a room side row and a turn program arming
//! row each ride whole under a key their own body spells. Filed under one
//! row's key while its body names another, such a row was placed under no
//! one, and the BASE-window discard projection kept it, whichever of the
//! two rows went: the discarded row's content stayed in the persisted
//! window. The projection now defers the window. A correct whole row places
//! as before, and bytes that read as no row prove no other row: they place
//! by their key, as before.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use oneiron::EntityId;
use oneiron::test_doors::sync_parted_row_binding::discard_projection;
use oneiron::test_doors::sync_whole_row_binding::{
    WHOLE_MAPS, WholeMap, arming_actor, turn_window_of_no_row, whole_window,
};

const DEFERRED: &str = "deferred: a whole row filed under a key it does not name";

/// Two distinct rows: the one whose key files the row, and the one its
/// body names.
fn two_rows() -> (EntityId, EntityId) {
    let keyed = EntityId::now();
    let mut body = EntityId::now();
    while body == keyed {
        body = EntityId::now();
    }
    (keyed, body)
}

/// The discard projection of a whole row filed under `keyed`'s key whose
/// body names `body` defers, whichever of the two is discarded.
fn whole_row_discard_defers_on_mismatch(map: WholeMap) {
    let (keyed, body) = two_rows();
    let window = whole_window(map, keyed, body).expect("the window writes");
    let body_gone = discard_projection(&window, &[body]).expect("the projection runs");
    assert_eq!(
        body_gone, DEFERRED,
        "{map:?}: discarding the row the body names must defer the window, not keep the row"
    );
    let key_gone = discard_projection(&window, &[keyed]).expect("the projection runs");
    assert_eq!(
        key_gone, DEFERRED,
        "{map:?}: discarding the key's row must defer the window, not keep the row"
    );
}

#[test]
fn whole_row_discard_defers_on_mismatch_document_pin() {
    whole_row_discard_defers_on_mismatch(WholeMap::DocumentPin);
}

#[test]
fn whole_row_discard_defers_on_mismatch_room_turn() {
    whole_row_discard_defers_on_mismatch(WholeMap::RoomTurn);
}

#[test]
fn whole_row_discard_defers_on_mismatch_room_side_row() {
    whole_row_discard_defers_on_mismatch(WholeMap::RoomSideRow);
}

#[test]
fn whole_row_discard_defers_on_mismatch_turn_program_arming() {
    whole_row_discard_defers_on_mismatch(WholeMap::TurnProgramArming);
}

/// A correct whole row places as before: its holder's discard erases it,
/// another row's discard leaves it.
#[test]
fn correct_whole_rows_place_as_before() {
    for map in WHOLE_MAPS {
        let row = EntityId::now();
        let (other, _) = two_rows();
        let window = whole_window(map, row, row).expect("the window writes");
        let holder = match map {
            WholeMap::TurnProgramArming => arming_actor(),
            _ => row,
        };
        let gone = discard_projection(&window, &[holder]).expect("the projection runs");
        let erased: usize = gone
            .strip_prefix("erased ")
            .and_then(|count| count.parse().ok())
            .unwrap_or_else(|| panic!("{map:?}: its holder's discard erases it, got {gone}"));
        assert!(erased >= 1, "{map:?}: the row goes, got {erased}");
        assert_eq!(
            discard_projection(&window, &[other]).expect("the projection runs"),
            "unchanged",
            "{map:?}: another row's discard leaves it"
        );
    }
}

/// Bytes under a turn key that read as no turn row prove no other row:
/// the projection places them by their key, as before, and keeps them.
#[test]
fn undecodable_whole_row_keeps_todays_placement() {
    let keyed = EntityId::now();
    let window = turn_window_of_no_row(keyed).expect("the window writes");
    assert_eq!(
        discard_projection(&window, &[keyed]).expect("the projection runs"),
        "unchanged"
    );
}
