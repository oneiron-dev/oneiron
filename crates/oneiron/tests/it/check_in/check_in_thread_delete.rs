//! ROLES-CHECKIN P2.5, row 2k5d (ARCH-0082 #act-table "Delete items",
//! #role-defaults and #owner-own-acts; Engine ruling THREAD-DELETE-JUDGE =
//! B, 14 Nov 16:44): `vault.rooms.thread_delete` judges the vault-standing
//! path only, and each receipt records the decision.
//!
//! - The vault's Owner deletes a private thread on their own proof.
//! - An Admin's delete never asks; a Deputy's goes on their own judgment
//!   (`sure`). Each receipt names the membership role it was judged under.
//! - A person seated in the room with no vault standing is not judged and
//!   still hears what an unknown thread hears: nothing waits on this door.
//!
//! Fixture: a project whose home room seats the vault's owner (its leader)
//! and a Member; a shared vault whose roster holds that owner as Owner, a
//! Deputy, an Admin and the Member, each of whom accepted. The Deputy and
//! the Admin hold no seat in the room, so their deletes reach the thread's
//! own authority (FIX 6381), with `rooms.private_threads.admin_delete` at
//! its default, on. The owner speaks a trunk turn, and each private thread
//! is a witness turn on it whose audience is the owner alone.
//!
//! On 2k5c (277924c5cf1) this file does not build: a private thread
//! delete's receipt has no `check_in`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_thread_delete`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::check_in::CheckInDecision;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::memory::{MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::workspace_roster::{
    PrivateThreadDeleteReceipt, PrivateThreadDeleteRequest, ProjectRecord,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const SHARED: u64 = 44;

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `member` accepts its founding invitation to the shared vault at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// The vault, its project's home room and the room's trunk turn every
/// private thread opens on.
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    deputy: EntityId,
    admin: EntityId,
    member: EntityId,
    room: EntityId,
    anchor: EntityId,
}

impl Org {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // `open_owned` holds the writer lease the owner's doors ask for.
        let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("vault");
        // A delete signs its receipt with this install's key.
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let [deputy, admin, member] = std::array::from_fn(|_| EntityId::now());
        for id in [deputy, admin, member] {
            person(&vault, id);
        }
        let founding = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    founding(owner, Role::Owner),
                    founding(deputy, Role::Deputy),
                    founding(admin, Role::Admin),
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Deputy, an Admin and a Member");
        accept(&vault, deputy, Role::Deputy);
        accept(&vault, admin, Role::Admin);
        accept(&vault, member, Role::Member);
        let root = vault.root_project().expect("root project");
        let project = EntityId::now();
        let mut record =
            ProjectRecord::new(project, Some(root), root, owner).expect("a project record");
        record.roster.extend([member.to_hex()]);
        vault
            .put_project(project, &record, vault.now_recorded_at())
            .expect("the project");
        let room = EntityId::from_hex(&record.home_room).expect("home room id");
        let org = Self {
            _dir: dir,
            vault,
            owner,
            deputy,
            admin,
            member,
            room,
            anchor: EntityId::now(),
        };
        org.speak(org.anchor, None);
        org
    }

    /// The owner's witness turn `turn` in the room, one MESSAGE: the trunk
    /// turn, or with `audience` the root of a private thread on the trunk.
    fn speak(&self, turn: EntityId, audience: Option<BTreeSet<EntityId>>) {
        let mut metadata = serde_json::Map::new();
        if audience.is_some() {
            metadata.insert("room_thread_of".into(), self.anchor.to_hex().into());
        }
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .rooms_speak(&WitnessTurn {
                conversation_ref: self.room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: audience,
                messages: vec![WitnessMessage {
                    id: Some(EntityId::now().to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "text".into(),
                    content: "a turn of the room".into(),
                    parts: None,
                    metadata: Some(serde_json::Value::Object(metadata)),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: self.vault.now_recorded_at(),
                assertions: Default::default(),
            })
            .expect("the owner speaks");
    }

    /// A private thread on the trunk whose audience is the owner alone, by
    /// its root TURN.
    fn private_thread(&self) -> EntityId {
        let root = EntityId::now();
        self.speak(root, Some(BTreeSet::from([self.owner])));
        root
    }

    /// `person`'s `vault.rooms.thread_delete` of the thread rooted at `root`.
    fn delete(&self, person: EntityId, root: EntityId) -> MemoryResult<PrivateThreadDeleteReceipt> {
        self.vault
            .memory(person, EdgeActorClass::Human)
            .rooms_thread_delete(&PrivateThreadDeleteRequest {
                thread_ref: root.to_hex(),
            })
    }

    fn deleted(&self, root: EntityId) -> bool {
        self.vault.is_deleted_shell(&root).expect("shell read")
    }
}

fn decision(role: &str, mode: Option<&str>, basis: &str) -> CheckInDecision {
    CheckInDecision {
        act_class: "delete".to_owned(),
        role: role.to_owned(),
        mode: mode.map(str::to_owned),
        basis: basis.to_owned(),
        check_in: None,
        requester: None,
    }
}

#[test]
fn the_owners_thread_delete_goes_on_their_own_proof_and_records_it() {
    let org = Org::new();
    let root = org.private_thread();
    let receipt = org
        .delete(org.owner, root)
        .expect("the Owner deletes the private thread");
    assert_eq!(receipt.thread_ref, root.to_hex());
    assert!(receipt.existed, "the thread's root existed");
    assert!(receipt.receipt_ref.is_some(), "the delete wrote a receipt");
    assert!(org.deleted(root), "the root is a deleted shell");
    assert_eq!(
        receipt.check_in,
        Some(decision("owner", None, "own_proof")),
        "the Owner's delete records their own proof"
    );
}

#[test]
fn an_admins_and_a_deputys_thread_delete_go_at_once_and_record_why() {
    let org = Org::new();
    let cases = [
        (org.admin, "admin", "full-access", "never_ask"),
        (org.deputy, "deputy", "auto", "sure"),
    ];
    for (person, role, mode, basis) in cases {
        let root = org.private_thread();
        let receipt = org
            .delete(person, root)
            .unwrap_or_else(|error| panic!("the {role}'s delete goes at once: {error:?}"));
        assert!(receipt.existed, "the {role}'s thread existed");
        assert!(org.deleted(root), "the {role}'s delete applied");
        assert_eq!(
            receipt.check_in,
            Some(decision(role, Some(mode), basis)),
            "the {role}'s receipt names the membership role and why it went"
        );
    }
}

#[test]
fn a_seated_member_with_no_vault_standing_is_not_judged_and_deletes_nothing() {
    let org = Org::new();
    let root = org.private_thread();
    let refused = org
        .delete(org.member, root)
        .expect_err("a Member outside the thread deletes nothing");
    assert!(!org.deleted(root), "the thread stays: {refused:?}");
    let receipt = org
        .delete(org.owner, root)
        .expect("the Owner still deletes it");
    assert_eq!(
        receipt.check_in,
        Some(decision("owner", None, "own_proof")),
        "no wait stood between: the Owner's delete goes on their own proof"
    );
}
