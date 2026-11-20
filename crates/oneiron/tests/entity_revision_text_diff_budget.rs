//! A row edit diffs each revision text field within a budget. Replacing a
//! large body with an unrelated one lands at once, where on main its diff
//! held the vault's writer for hours (the retrieval-bounds server test hung
//! on this edit in the 19 and 20 Nov nights), and the revision pinned before
//! the edit still reads its own body.

use std::sync::{Arc, mpsc};
use std::time::Duration;

use oneiron::memory::ReadMode;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{EntityId, TimeRange};
use oneiron_testkit::{FixtureVault, fixture_cache};

/// How long the edit may take here; the diff budget is 2 s.
const EDIT_BOUND: Duration = Duration::from_secs(300);

fn turn(txt: &str, at: u64) -> Vec<u8> {
    rmp_serde::to_vec_named(&serde_json::json!({"txt": txt, "spkr": "user", "at": at})).unwrap()
}

#[test]
fn replacing_a_large_body_with_an_unrelated_one_lands_within_the_diff_budget() {
    let fixture = FixtureVault::empty(&fixture_cache!()).unwrap();
    let copy = fixture.copy().unwrap();
    let vault = Arc::new(copy.open().unwrap());
    let id = EntityId::from_bytes([0x5e; 16]).unwrap();
    let range = TimeRange {
        start: 100,
        end: 100,
    };
    let large = turn(&"x".repeat((4 << 20) + 1), 100);
    vault
        .put_entity(&id, ENTITY_TYPE_TURN, range, 100, &large)
        .unwrap();
    let pinned = vault.pin_entity_revision(&id).unwrap();

    let edited = turn("edited", 101);
    let (sent, landed) = mpsc::channel();
    let writer = Arc::clone(&vault);
    let body = edited.clone();
    // Detached, so an edit that never ends fails the test at the bound.
    std::thread::spawn(move || {
        let _ = sent.send(writer.put_entity(&id, ENTITY_TYPE_TURN, range, 101, &body));
    });
    landed
        .recv_timeout(EDIT_BOUND)
        .expect("FAILBEFORE: the edit did not land within the bound")
        .expect("the edit lands");

    let live = vault
        .get_raw_with_mode(&id, ReadMode::Live)
        .unwrap()
        .expect("the live row");
    assert!(live.ends_with(&edited), "the live row is the edit");
    let earlier = vault
        .get_raw_with_mode(&id, ReadMode::Pinned(pinned))
        .unwrap()
        .expect("the pinned row");
    assert!(
        earlier.ends_with(&large),
        "the revision pinned before the edit reads its own body"
    );
}
