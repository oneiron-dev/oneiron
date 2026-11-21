//! [ROOM-ROLE-UNROOTED-EMBEDDED-OWNER-LIVENESS]: on an unrooted vault the
//! room-role read gave the Owner role by id alone: to the embedded owner
//! (a personal vault's owner shortcut always holds), to the room's creator,
//! and to a PERSON the role door seated as Owner, with no read of that
//! PERSON's row. The role door's own caller is refused once deleted (its
//! write-actor check reads the live row), but a closed room's owners
//! (`conversation::room_owners_in`, the check-in rung `room_owner`), the
//! closed-room and pin judges and a federation peer's room body read roles
//! without it, so a deleted owner stayed an owner there: a closed room's ask
//! waited on a holder who can never answer. A deleted owner is no owner
//! (H149; L9-52 (b), as `disclosure::is_vault_owner` reads it since #7900),
//! and a deleted shell passes no person check (DELETED-ACTOR-SLIP-AUTH = A):
//! the role read now refuses a PERSON whose deletion this vault records.
//!
//! Red on main 2c56ee802949: `a_soft_deleted_embedded_owner_owns_no_room`,
//! `a_hard_deleted_embedded_owner_owns_no_room`,
//! `a_deleted_room_creator_owns_no_room` and
//! `a_deleted_seated_owner_owns_no_room`. Guards (pass on main too):
//! `live_owners_own_the_room` and
//! `an_embedded_owner_never_written_here_still_owns_the_room` (the
//! never-written fallback #7900 kept).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --no-fail-fast --test room_role_deleted_person`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::conversation::{ConversationBody, ConversationKind, RoomRole};
use oneiron::deletion::DeleteReason;
use oneiron::error::RecordError;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::room_owner_standing::{
    embedded_owner_actor_id, person_room_role, room_owners,
};
use oneiron::{EdgeActorClass, EntityId, Error, TimeRange, Vault, VaultConfig, WriteActor};

fn put_person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    let now = vault.now_recorded_at();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"human",
        )
        .expect("a live person");
    person
}

/// An unrooted personal vault and a group room another PERSON created,
/// whose owners are the embedded owner (its owner shortcut), the creator
/// (its creator row) and a PERSON the creator seated as Owner through the
/// role door; one more member holds no role.
struct Room {
    vault: Vault,
    owner: EntityId,
    creator: EntityId,
    seated: EntityId,
    room: EntityId,
    _dir: tempfile::TempDir,
}

impl Room {
    /// `write_owner`: whether the embedded owner's PERSON row is written.
    fn new(write_owner: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open vault");
        // Every delete signs as this install first.
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let owner = if write_owner {
            vault.ensure_embedded_owner_actor().expect("embedded owner")
        } else {
            embedded_owner_actor_id().expect("the embedded owner's id")
        };
        let creator = put_person(&vault);
        let seated = put_person(&vault);
        let member = put_person(&vault);
        let mut member_ids = vec![creator, seated, member];
        if write_owner {
            member_ids.push(owner);
        }
        let room = EntityId::now();
        let as_creator = WriteActor::new(creator, EdgeActorClass::Human);
        vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids,
                    ..Default::default()
                },
                as_creator,
                vault.now_recorded_at(),
            )
            .expect("the room");
        vault
            .set_room_role(room, seated, RoomRole::Owner, as_creator)
            .expect("a seated owner");
        Self {
            vault,
            owner,
            creator,
            seated,
            room,
            _dir: dir,
        }
    }

    fn owners(&self) -> Vec<EntityId> {
        room_owners(&self.vault, self.room).expect("the room's owners")
    }

    fn delete(&self, person: EntityId, reason: DeleteReason) {
        self.vault
            .delete_entity_with_reason(&person, reason)
            .expect("the PERSON's delete");
    }

    /// `person`, acting as a human, holds no role in the room.
    fn assert_no_role(&self, person: EntityId) {
        let refused = person_room_role(&self.vault, self.room, person, true)
            .expect_err("a deleted PERSON holds no room role");
        assert!(
            matches!(refused, Error::Record(RecordError::ConversationDenied)),
            "refused as no role, got {refused:?}"
        );
    }
}

fn sorted(mut ids: Vec<EntityId>) -> Vec<EntityId> {
    ids.sort();
    ids
}

#[test]
fn live_owners_own_the_room() {
    let room = Room::new(true);
    assert_eq!(
        room.owners(),
        sorted(vec![room.owner, room.creator, room.seated])
    );
    for person in [room.owner, room.creator, room.seated] {
        assert_eq!(
            person_room_role(&room.vault, room.room, person, true).expect("a role"),
            RoomRole::Owner
        );
    }
}

#[test]
fn a_soft_deleted_embedded_owner_owns_no_room() {
    let room = Room::new(true);
    room.delete(room.owner, DeleteReason::UserDelete);
    assert_eq!(room.owners(), sorted(vec![room.creator, room.seated]));
    room.assert_no_role(room.owner);
}

#[test]
fn a_hard_deleted_embedded_owner_owns_no_room() {
    let room = Room::new(true);
    room.delete(room.owner, DeleteReason::UserHardDelete);
    assert_eq!(room.owners(), sorted(vec![room.creator, room.seated]));
    room.assert_no_role(room.owner);
}

#[test]
fn a_deleted_room_creator_owns_no_room() {
    let room = Room::new(true);
    room.delete(room.creator, DeleteReason::UserDelete);
    assert_eq!(room.owners(), sorted(vec![room.owner, room.seated]));
    room.assert_no_role(room.creator);
}

#[test]
fn a_deleted_seated_owner_owns_no_room() {
    let room = Room::new(true);
    room.delete(room.seated, DeleteReason::UserDelete);
    assert_eq!(room.owners(), sorted(vec![room.owner, room.creator]));
    room.assert_no_role(room.seated);
}

#[test]
fn an_embedded_owner_never_written_here_still_owns_the_room() {
    let room = Room::new(false);
    assert_eq!(
        room.owners(),
        sorted(vec![room.owner, room.creator, room.seated])
    );
    assert_eq!(
        person_room_role(&room.vault, room.room, room.owner, true).expect("a role"),
        RoomRole::Owner
    );
}
