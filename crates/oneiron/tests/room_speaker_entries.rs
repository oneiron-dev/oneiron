//! The owner-alone room read sees a voice speaker's entry
//! (PLAN-RUN-RESULT-GUARD-SPEAKER-ENTRIES).
//!
//! A plan run's result is filed into its sub-session only in a room its
//! owner alone reads (PLAN-RUN-TRACE-INTO-SUB-SESSION = B). A voice speaker
//! that enters a room (OF-365) reads its records from its entry on and takes
//! no seat on its ledger, and its entry fact's id is derived from the
//! speaker, never from the room. A derived index files each speaker's entry
//! under its room; the owner-alone read asks it. A vault older than the
//! index holds no row: the rebuild a writable open runs files every entry,
//! and until a whole rebuild has committed no room reads as its owner's
//! alone. A withdrawn entry's Shell keeps its index row but names no
//! speaker: the room reads as its owner's alone again, and the read never
//! fails on it.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test room_speaker_entries`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::conversation::{ContainerAttendee, ContainerAttendeeEvent, HistoryChoice};
use oneiron::core_write::ConversationCreateInput;
use oneiron::memory::Memory;
use oneiron::test_doors::room_speaker_entries;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

/// A rooted vault with its install enrolled and its embedded owner.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Fixture {
        vault,
        owner,
        _dir: dir,
    }
}

fn owner(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// A fresh conversation whose one member is the owner.
fn owner_room(fixture: &Fixture) -> EntityId {
    let created = owner(fixture)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "v": 1,
                "kind": "group",
                "member_ids": [fixture.owner.to_hex()],
                "title": "owner room",
            }),
            text: None,
        })
        .expect("the owner opens a conversation");
    EntityId::from_hex(&created.id).expect("the conversation id")
}

/// An unplaced voice speaker heard in `room` enters it, as a voice host
/// records it (OF-365): its entry fact.
fn enter_speaker(fixture: &Fixture, room: EntityId) -> EntityId {
    let attendee = ContainerAttendee::Speaker {
        session_key: "owner-room-call".to_owned(),
        speaker_key: "speaker-2".to_owned(),
    };
    // The entry commits whether or not its "who is this?" ask is admitted
    // (FIX 10172); the entry is what reads the room.
    let _asked = owner(fixture).container_attendee_entered(&ContainerAttendeeEvent {
        container: room,
        attendee: attendee.clone(),
        roster_revision: 1,
        trigger_turn: None,
        candidates: Vec::new(),
        until: fixture.vault.now_recorded_at() + 3_600,
        history: HistoryChoice::Inherit,
    });
    fixture
        .vault
        .container_attendee_entry(room, &attendee)
        .expect("the room's entries read")
        .expect("the speaker entered the room")
        .entry_ref
}

/// Who alone reads `room`, as the plan run's result filing reads it.
fn sole_reader(fixture: &Fixture, room: EntityId) -> Option<EntityId> {
    room_speaker_entries::room_sole_owner_reader(&fixture.vault, room)
        .expect("the owner-alone read reads")
}

#[test]
fn a_room_a_voice_speaker_entered_is_not_read_by_its_owner_alone() {
    let fixture = fixture();
    let quiet = owner_room(&fixture);
    let heard = owner_room(&fixture);
    assert_eq!(
        sole_reader(&fixture, heard),
        Some(fixture.owner),
        "a room whose one member is the owner reads as the owner's alone"
    );
    enter_speaker(&fixture, heard);
    assert_eq!(
        sole_reader(&fixture, heard),
        None,
        "a speaker's entry reads the room, so the owner no longer reads it alone"
    );
    assert_eq!(
        sole_reader(&fixture, quiet),
        Some(fixture.owner),
        "a room no speaker entered stays the owner's alone"
    );
}

#[test]
fn the_open_rebuild_files_a_speaker_entry_older_than_its_index() {
    let fixture = fixture();
    let quiet = owner_room(&fixture);
    let heard = owner_room(&fixture);
    enter_speaker(&fixture, heard);
    room_speaker_entries::forget_speaker_entry_index(&fixture.vault)
        .expect("the index and its flag go");
    assert_eq!(
        sole_reader(&fixture, quiet),
        None,
        "with no whole index, no room reads as its owner's alone"
    );
    room_speaker_entries::backfill_speaker_entry_index(&fixture.vault)
        .expect("the open rebuild runs");
    assert_eq!(
        sole_reader(&fixture, heard),
        None,
        "the rebuild files the speaker's older entry under its room"
    );
    assert_eq!(
        sole_reader(&fixture, quiet),
        Some(fixture.owner),
        "the rebuilt index leaves a room no speaker entered to its owner"
    );
}

#[test]
fn a_withdrawn_speaker_entry_leaves_the_room_to_its_owner() {
    let fixture = fixture();
    let heard = owner_room(&fixture);
    let entry = enter_speaker(&fixture, heard);
    assert_eq!(
        sole_reader(&fixture, heard),
        None,
        "the speaker's entry reads the room"
    );
    assert!(
        room_speaker_entries::withdraw_to_shell(&fixture.vault, entry)
            .expect("the entry's withdrawal writes"),
        "the withdrawn entry takes its Shell"
    );
    assert_eq!(
        sole_reader(&fixture, heard),
        Some(fixture.owner),
        "a withdrawn entry's Shell names no speaker, so the owner reads the room alone again"
    );
}
