//! Fix list rows ARCHIVE-IMPORT-ACTORLESS-SEATED-ROOM-REFUSED and
//! ARCHIVE-IMPORT-ROOM-PINS-OR-CLOSED-REFUSED (Engine ANSWER
//! ARCHIVE-IMPORT-ACTORLESS-SEATED-ROOM = B, 20 Nov 11:39): a room's members,
//! pin policy and closed bit change only through their room doors, so a
//! whole-vault import door other than the owner's restore keeps an archived
//! room this vault cannot seat as archive data, with the TURN and MESSAGE
//! spoken in it, names each under `RoomNotSeatedHere`, and goes on. The
//! owner's restore writes a room under the pin doors' and the closed-setting
//! door's markers, so a closed room comes back closed.
//!
//! * `the_actorless_import_keeps_rooms_it_cannot_seat_out_with_their_speech`:
//!   a seated room, a room whose pins only its managers change and a closed
//!   room stay out with their TURNs and MESSAGEs, each named; an open room
//!   with no members lands with its TURN and MESSAGE.
//! * `the_actor_import_keeps_a_seated_room_out_with_its_speech`: the same for
//!   a seated room through the actor-taking door.
//! * `the_owner_restore_lands_a_closed_room_closed_and_a_managers_room_with_its_policy`:
//!   the owner's restore lands the closed room closed and the managers room
//!   with its pin policy, each with its TURN and MESSAGE, and names neither.
//!
//! Red on main 6552c26a9c7 (by reading; this run proves it): each import is
//! refused at the first such room it writes, by the room guard
//! (`conversation::validate_put_in_txn`): the actorless and actor doors with
//! "membership changes require the membership door" (or "member must be a
//! PERSON", or the pin or closed check, by row order), the owner's restore
//! with "closing or opening a room requires the room's closed-setting door".
//! The source preconditions pass.
//!
//! Vaults in tempdirs, every step through public doors; each destination
//! opens at least one wall-clock second after its source (sleep 1100 ms), as
//! in `whole_vault_restore_conversation_dag.rs`. Run with `cargo test --locked
//! -p oneiron --all-features --test archive_import_rooms_not_seated_here`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Cursor;

use oneiron::batch::export::WholeVaultImportReceipt;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice, RoomPinPolicy};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::{RoomClosedSet, RoomPinPolicySet};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// What a source room holds when the source is exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoomState {
    /// Open, no members, default pin policy: every door seats it.
    Open,
    /// One member, seated through the membership door.
    Seated,
    /// Its pins change only through its managers (the pin policy door).
    ManagersPinPolicy,
    /// Closed through the room's closed-setting door.
    Closed,
}

/// One source room, the TURN spoken in it and that TURN's MESSAGE.
#[derive(Debug, Clone, Copy)]
struct SpokenRoom {
    state: RoomState,
    room: EntityId,
    turn: EntityId,
    message: EntityId,
}

/// A source vault's whole-vault archive and the rooms it holds.
struct Source {
    archive: Vec<u8>,
    rooms: Vec<SpokenRoom>,
}

impl Source {
    fn room(&self, state: RoomState) -> SpokenRoom {
        *self
            .rooms
            .iter()
            .find(|room| room.state == state)
            .expect("the source holds a room in this state")
    }
}

fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// A fresh destination whose engine-seed seconds differ from the source's:
/// any 1100 ms interval crosses a second boundary.
fn open_later_vault() -> (tempfile::TempDir, Vault) {
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let dir = tempfile::tempdir().expect("temp dir for the destination vault");
    let vault =
        Vault::open(dir.path(), VaultConfig::default()).expect("open the destination vault");
    (dir, vault)
}

/// The owner's trunk TURN in ordinary room `room`, holding one MESSAGE, both
/// under ids this test picks, through the witness gate (`room_pins.rs`'s
/// `say_in_ordinary_room` shape). Returns the TURN and the MESSAGE.
fn speak_in(vault: &Vault, owner: EntityId, room: EntityId) -> (EntityId, EntityId) {
    let turn = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "Water the basil on Sunday.".into(),
                parts: None,
                metadata: Some(serde_json::Value::Object(serde_json::Map::new())),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .expect("the owner speaks in the room");
    (turn, message)
}

/// A source vault (owner-rooted, so its embedded owner owns every room)
/// holding one ordinary group room in each of `states`: the owner creates
/// each room empty, speaks one TURN in it, then gives it its state through
/// the room's own door; the source reads each state back. Returns the
/// source's whole-vault archive and its rooms.
fn source_with_rooms(states: &[RoomState]) -> Source {
    let dir = tempfile::tempdir().expect("temp dir for the source vault");
    let vault =
        Vault::open_owned(dir.path(), VaultConfig::default()).expect("open the source vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let as_owner = WriteActor::new(owner, EdgeActorClass::Human);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let mut rooms = Vec::new();
    for &state in states {
        let room = EntityId::now();
        vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids: vec![],
                    ..Default::default()
                },
                as_owner,
                vault.now_recorded_at(),
            )
            .expect("the owner creates the empty group room");
        let (turn, message) = speak_in(&vault, owner, room);
        match state {
            RoomState::Open => {}
            RoomState::Seated => {
                let member = EntityId::now();
                let now = vault.now_recorded_at();
                vault
                    .put_entity(
                        &member,
                        ENTITY_TYPE_PERSON,
                        TimeRange {
                            start: now,
                            end: now,
                        },
                        now,
                        b"owen",
                    )
                    .expect("the source stores the member's PERSON");
                vault
                    .join_member(room, member, as_owner, now, HistoryChoice::Share)
                    .expect("the owner seats owen in the room");
            }
            RoomState::ManagersPinPolicy => {
                memory
                    .rooms_pins_policy_set(&RoomPinPolicySet {
                        room,
                        policy: RoomPinPolicy::Managers,
                    })
                    .expect("the owner sets the managers pin policy");
            }
            RoomState::Closed => {
                memory
                    .rooms_closed_set(&RoomClosedSet {
                        room_ref: room,
                        closed: true,
                    })
                    .expect("the owner closes the room");
            }
        }
        let body = vault.conversation_body(room).expect("read the source room");
        assert_eq!(
            (body.member_ids.len(), body.pin_policy, body.closed),
            match state {
                RoomState::Open => (0, RoomPinPolicy::Members, false),
                RoomState::Seated => (1, RoomPinPolicy::Members, false),
                RoomState::ManagersPinPolicy => (0, RoomPinPolicy::Managers, false),
                RoomState::Closed => (0, RoomPinPolicy::Members, true),
            },
            "precondition: the source room holds its {state:?} state"
        );
        rooms.push(SpokenRoom {
            state,
            room,
            turn,
            message,
        });
    }
    let archive = vault
        .export_whole_vault(true)
        .expect("whole-vault export")
        .bytes()
        .to_vec();
    Source { archive, rooms }
}

/// The reason the receipt's `destination_omissions` gives for `id`, by its
/// debug name.
fn omission_reason(receipt: &WholeVaultImportReceipt, id: EntityId) -> Option<String> {
    receipt
        .destination_omissions
        .iter()
        .find(|kept| kept.entity_id == id.to_hex())
        .map(|kept| format!("{:?}", kept.reason))
}

fn stored(vault: &Vault, id: EntityId) -> bool {
    vault
        .get_entity_type(&id)
        .expect("read the destination row")
        .is_some()
}

/// `room`, its TURN and its MESSAGE stayed archive data on `dest`, each named
/// under `RoomNotSeatedHere` in `receipt`.
fn assert_kept_out(dest: &Vault, receipt: &WholeVaultImportReceipt, room: SpokenRoom) {
    for (what, id) in [
        ("room", room.room),
        ("TURN", room.turn),
        ("MESSAGE", room.message),
    ] {
        assert!(
            !stored(dest, id),
            "the {:?} room's {what} stays archive data",
            room.state
        );
        assert_eq!(
            omission_reason(receipt, id).as_deref(),
            Some("RoomNotSeatedHere"),
            "the receipt names the {:?} room's {what}: {:?}",
            room.state,
            receipt.destination_omissions
        );
    }
}

/// `room`, its TURN and its MESSAGE came back on `dest`, none named in
/// `receipt`.
fn assert_landed(dest: &Vault, receipt: &WholeVaultImportReceipt, room: SpokenRoom) {
    for (what, id) in [
        ("room", room.room),
        ("TURN", room.turn),
        ("MESSAGE", room.message),
    ] {
        assert!(
            stored(dest, id),
            "the {:?} room's {what} comes back",
            room.state
        );
        assert_eq!(
            omission_reason(receipt, id),
            None,
            "the receipt names no landed {:?} room's {what}",
            room.state
        );
    }
}

#[test]
fn the_actorless_import_keeps_rooms_it_cannot_seat_out_with_their_speech() {
    let source = source_with_rooms(&[
        RoomState::Open,
        RoomState::Seated,
        RoomState::ManagersPinPolicy,
        RoomState::Closed,
    ]);
    let (_dir, dest) = open_later_vault();
    let receipt = dest
        .import_whole_vault_archive_from(Cursor::new(&source.archive))
        .expect("the actorless import goes on past the rooms it cannot seat");
    for state in [
        RoomState::Seated,
        RoomState::ManagersPinPolicy,
        RoomState::Closed,
    ] {
        assert_kept_out(&dest, &receipt, source.room(state));
    }
    assert_landed(&dest, &receipt, source.room(RoomState::Open));
}

#[test]
fn the_actor_import_keeps_a_seated_room_out_with_its_speech() {
    let source = source_with_rooms(&[RoomState::Open, RoomState::Seated]);
    let (_dir, dest) = open_later_vault();
    let owner = dest.ensure_embedded_owner_actor().expect("embedded owner");
    let receipt = dest
        .import_whole_vault_archive_with_actor(
            &source.archive,
            &WriteActor::new(owner, EdgeActorClass::Human),
        )
        .expect("the actor import goes on past the seated room");
    assert_kept_out(&dest, &receipt, source.room(RoomState::Seated));
    assert_landed(&dest, &receipt, source.room(RoomState::Open));
}

#[test]
fn the_owner_restore_lands_a_closed_room_closed_and_a_managers_room_with_its_policy() {
    let source = source_with_rooms(&[RoomState::ManagersPinPolicy, RoomState::Closed]);
    let (_dir, dest) = open_later_vault();
    let owner = owner_proof(&dest);
    let receipt = dest
        .import_whole_vault_archive_from_as_owner(Cursor::new(&source.archive), &owner)
        .expect("the owner's restore lands the closed and the managers rooms");
    let closed = source.room(RoomState::Closed);
    assert_landed(&dest, &receipt, closed);
    assert!(
        dest.conversation_body(closed.room)
            .expect("read the restored closed room")
            .closed,
        "the closed room comes back closed"
    );
    let managers = source.room(RoomState::ManagersPinPolicy);
    assert_landed(&dest, &receipt, managers);
    assert_eq!(
        dest.conversation_body(managers.room)
            .expect("read the restored managers room")
            .pin_policy,
        RoomPinPolicy::Managers,
        "the managers room comes back with its pin policy"
    );
}
