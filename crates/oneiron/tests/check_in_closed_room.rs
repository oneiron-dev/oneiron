//! An add into a closed room (ARCH-0082 #closed-room; Engine ruling
//! P26-SHAPE Q5 = A): any add asks the room's owners, whoever adds. An
//! owner of the room adds at once; anyone else's add waits AlwaysAsk on the
//! one rung `room_owner`, which pins every owner of the room and no one
//! else; an owner who is not the vault's owner answers it through
//! `vault.check_in.answer`, and the adder's call naming the approved ask
//! lands the add once. Opened again, the room adds as before.
//!
//! A walk-in is a self-add (P26B-WALKIN = A, the lead 15 Nov 04:2x, from
//! ARCH-0082:155): a vault Admin's walk-in into a private thread of a closed
//! room waits on the room's owners, and the Admin's call naming the approved
//! ask walks in; the vault's owner, and a vault Admin who owns the room,
//! walk in at once. An open room's walk-in is not judged.
//!
//! The vault is unrooted: its embedded owner owns every room, and the role
//! door seats a second owner and an admin. Neither the admin nor the
//! newcomers hold a role on the vault, so in an open room the admin's add is
//! not judged. The site is `vault.rooms.thread_audience.add` on a private
//! thread of an ordinary group room; the other three sites share its judge.
//! For the walk-in, [`Room::with_vault_admins`] also shares the vault with
//! two Admins, one of whom the role door makes an owner of the room.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_closed_room`.

use std::collections::BTreeSet;

use oneiron::check_in::{CheckInMode, Rung};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, RoomRole};
use oneiron::federation::{FederationGrantRole, InitialSharedMember};
use oneiron::memory::{
    CHECK_IN_PENDING_REASON_PREFIX, MEMORY_CODE_CHECK_IN_PENDING, Memory, MemoryError,
    MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::workspace_roster::{
    RoomClosedSet, ThreadAudienceAddRequest, ThreadAudienceHistory, ThreadAudienceReceipt,
    ThreadAudienceRemoveRequest,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const ADD: &str = "vault.rooms.thread_audience.add";
const SHARED: u64 = 44;

struct Room {
    vault: Vault,
    owner: EntityId,
    co_owner: EntityId,
    admin: EntityId,
    newcomers: [EntityId; 4],
    /// The vault's two Admins, with [`Room::with_vault_admins`].
    vault_admins: Option<VaultAdmins>,
    room: EntityId,
    thread: EntityId,
    _dir: tempfile::TempDir,
}

/// Two Admins of the shared vault, each seated in the room.
struct VaultAdmins {
    /// No role in the room.
    walker: EntityId,
    /// An owner of the room through the role door.
    room_owner: EntityId,
}

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
            b"owen",
        )
        .expect("a live person");
    person
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// Shares the vault, its embedded `owner` its Owner, with `admins` as
/// Admins, each of whom accepts its founding invitation.
fn share_with_admins(vault: &Vault, owner: EntityId, admins: [EntityId; 2]) {
    let mut members = vec![InitialSharedMember {
        member_ref: owner,
        role: Some(FederationGrantRole::Owner),
    }];
    members.extend(admins.map(|admin| InitialSharedMember {
        member_ref: admin,
        role: Some(FederationGrantRole::Admin),
    }));
    vault
        .initialize_shared_vault(&proof(vault, owner), SHARED, None, &members, 1)
        .expect("a shared vault with two Admins");
    for admin in admins {
        let admin_proof = proof(vault, admin);
        let invitation = vault
            .shared_invitations(&admin_proof, SHARED)
            .expect("the Admin's invitations")
            .into_iter()
            .find(|open| open.role == FederationGrantRole::Admin)
            .expect("the Admin's founding invitation");
        vault
            .accept_shared_invitation(&admin_proof, SHARED, &invitation.id)
            .expect("the Admin accepts");
    }
}

impl Room {
    fn new() -> Self {
        Self::build(false)
    }

    /// [`Room::new`] on a vault shared with two Admins, both seated in the
    /// room: `walker`, and `room_owner`, an owner of the room.
    fn with_vault_admins() -> Self {
        Self::build(true)
    }

    /// The owner's group room seating the owner, a second owner, an admin
    /// and four newcomers, with a private thread whose audience is the
    /// owner, the second owner and the admin. A private thread's audience
    /// is drawn from the room's seats, so the owner is seated too.
    fn build(vault_admins: bool) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open vault");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let co_owner = put_person(&vault);
        let admin = put_person(&vault);
        let newcomers = std::array::from_fn(|_| put_person(&vault));
        let vault_admins = vault_admins.then(|| {
            let admins = VaultAdmins {
                walker: put_person(&vault),
                room_owner: put_person(&vault),
            };
            share_with_admins(&vault, owner, [admins.walker, admins.room_owner]);
            admins
        });
        let room = EntityId::now();
        let as_owner = WriteActor::new(owner, EdgeActorClass::Human);
        let mut member_ids = vec![owner, co_owner, admin];
        member_ids.extend(newcomers);
        member_ids.extend(
            vault_admins
                .iter()
                .flat_map(|admins| [admins.walker, admins.room_owner]),
        );
        vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids,
                    ..Default::default()
                },
                as_owner,
                vault.now_recorded_at(),
            )
            .expect("the room");
        vault
            .set_room_role(room, co_owner, RoomRole::Owner, as_owner)
            .expect("a second owner");
        vault
            .set_room_role(room, admin, RoomRole::Admin, as_owner)
            .expect("an admin");
        if let Some(admins) = &vault_admins {
            vault
                .set_room_role(room, admins.room_owner, RoomRole::Owner, as_owner)
                .expect("a vault Admin who owns the room");
        }
        let fixture = Self {
            vault,
            owner,
            co_owner,
            admin,
            newcomers,
            vault_admins,
            room,
            thread: EntityId::now(),
            _dir: dir,
        };
        let anchor = EntityId::now();
        fixture.speak(anchor, None);
        fixture.speak(
            fixture.thread,
            Some((anchor, [owner, co_owner, admin].into())),
        );
        fixture
    }

    /// The owner's witness turn `turn`: the trunk turn, or with `thread` the
    /// root of a private thread on the trunk turn it names.
    fn speak(&self, turn: EntityId, thread: Option<(EntityId, BTreeSet<EntityId>)>) {
        let mut metadata = serde_json::Map::new();
        if let Some((anchor, _)) = &thread {
            metadata.insert("room_thread_of".into(), anchor.to_hex().into());
        }
        self.person(self.owner)
            .rooms_speak(&WitnessTurn {
                conversation_ref: self.room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: thread.map(|(_, audience)| audience),
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

    fn person(&self, person: EntityId) -> Memory<'_> {
        self.vault.memory(person, EdgeActorClass::Human)
    }

    fn set_closed(&self, closed: bool) {
        self.person(self.owner)
            .rooms_closed_set(&RoomClosedSet {
                room_ref: self.room,
                closed,
            })
            .expect("the owner closes or opens the room");
    }

    /// `adder`'s add of `newcomer` to the thread, from now on.
    fn add(
        &self,
        adder: EntityId,
        newcomer: EntityId,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<ThreadAudienceReceipt> {
        self.person(adder)
            .rooms_thread_audience_add(&ThreadAudienceAddRequest {
                thread_ref: self.thread.to_hex(),
                person_ref: newcomer.to_hex(),
                history: ThreadAudienceHistory::FromNow,
                check_in_ref: check_in_ref.map(str::to_owned),
            })
    }

    /// `person`'s removal of themselves from the thread.
    fn leave(&self, person: EntityId) {
        self.person(person)
            .rooms_thread_audience_remove(&ThreadAudienceRemoveRequest {
                thread_ref: self.thread.to_hex(),
                person_ref: person.to_hex(),
            })
            .expect("a person leaves the thread");
    }

    /// `person` approves check-in `id` over the effect it waits on, through
    /// `vault.check_in.answer`.
    fn approves(&self, person: EntityId, id: &str) -> MemoryResult<serde_json::Value> {
        let row = self
            .vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored");
        let digest: String = row
            .effect_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        invoke(
            &self.person(person),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": digest }),
        )
    }
}

/// The check-in a refusal waits on, 32 hex.
fn pending_id(error: &MemoryError) -> String {
    assert_eq!(
        error.code, MEMORY_CODE_CHECK_IN_PENDING,
        "the act waits: {error:?}"
    );
    error
        .reason_codes
        .iter()
        .find_map(|reason| reason.strip_prefix(CHECK_IN_PENDING_REASON_PREFIX))
        .expect("the wait names its check-in")
        .to_owned()
}

/// The admin's add, not judged while the room is open, waits once it is
/// closed: one rung, `room_owner`, pinning both owners and no one else, mode
/// AlwaysAsk, no grant. A repeat names the same check-in. Someone the rung
/// does not pin cannot answer; the second owner, who is not the vault's
/// owner, approves; the admin's call naming the check-in lands the add with
/// the approved decision, and lands nothing a second time.
#[test]
fn an_admins_add_into_a_closed_room_waits_on_its_owners() {
    let fx = Room::new();
    let [before, newcomer, ..] = fx.newcomers;
    let open = fx
        .add(fx.admin, before, None)
        .expect("in an open room the admin adds");
    assert_eq!(open.check_in, None, "an open room does not judge the add");
    fx.set_closed(true);
    let waiting = fx
        .add(fx.admin, newcomer, None)
        .expect_err("in a closed room the admin's add waits");
    let id = pending_id(&waiting);
    let again = fx
        .add(fx.admin, newcomer, None)
        .expect_err("a repeat waits");
    assert_eq!(pending_id(&again), id, "a repeat names the same check-in");
    let row = fx
        .vault
        .pending_check_in(&EntityId::from_hex(&id).expect("a check-in id"))
        .expect("read the check-in")
        .expect("the check-in is stored");
    assert_eq!((row.asker, row.verb.as_str()), (fx.admin, ADD));
    assert_eq!(row.room, Some(fx.room), "the ask names the closed room");
    assert_eq!(row.mode, CheckInMode::AlwaysAsk);
    assert_eq!(row.grant_ref, "", "the admin holds no grant on the vault");
    assert_eq!(row.delay_window, None);
    assert_eq!(row.undo_plan, None);
    let rungs: Vec<Rung> = row.rungs.iter().map(|entry| entry.rung).collect();
    assert_eq!(rungs, vec![Rung::RoomOwner], "the room's owners alone");
    let pinned: BTreeSet<EntityId> = row.rungs[0]
        .holders
        .iter()
        .map(|holder| holder.principal)
        .collect();
    assert_eq!(pinned, BTreeSet::from([fx.owner, fx.co_owner]));

    let stranger = fx.newcomers[3];
    assert!(
        fx.approves(stranger, &id).is_err(),
        "a person the rung does not pin does not answer"
    );
    let settled = fx
        .approves(fx.co_owner, &id)
        .expect("the second owner answers");
    assert_eq!(settled["eligible"].as_str(), Some("approved"), "{settled}");
    assert_eq!(settled["rung"].as_str(), Some("room_owner"), "{settled}");

    let landed = fx
        .add(fx.admin, newcomer, Some(&id))
        .expect("the approved add lands");
    let decision = landed
        .check_in
        .expect("the landed add records its decision");
    assert_eq!(
        (
            decision.act_class.as_str(),
            decision.role.as_str(),
            decision.mode.as_deref(),
            decision.basis.as_str(),
            decision.check_in.as_deref(),
        ),
        (
            "room_add",
            "none",
            Some(CheckInMode::AlwaysAsk.as_str()),
            "approved",
            Some(id.as_str())
        )
    );
    assert!(
        fx.add(fx.admin, newcomer, Some(&id)).is_err(),
        "a spent check-in lands nothing again"
    );
}

/// An owner of the closed room adds at once, the vault's owner and the
/// second owner alike, basis `room_owner`, and opens no check-in. Opened
/// again, the room does not judge the admin's add.
#[test]
fn an_owners_add_into_a_closed_room_goes_at_once() {
    let fx = Room::new();
    let [first, second, third, _] = fx.newcomers;
    fx.set_closed(true);
    for (adder, newcomer) in [(fx.owner, first), (fx.co_owner, second)] {
        let landed = fx
            .add(adder, newcomer, None)
            .expect("an owner of the room adds at once");
        let decision = landed.check_in.expect("the add records its decision");
        assert_eq!(
            (
                decision.mode.as_deref(),
                decision.basis.as_str(),
                decision.check_in
            ),
            (Some(CheckInMode::AlwaysAsk.as_str()), "room_owner", None)
        );
    }
    let second_owner = fx
        .add(fx.co_owner, third, None)
        .expect("the second owner adds")
        .check_in
        .expect("a decision");
    assert_eq!(
        second_owner.role, "none",
        "the second owner holds no vault role"
    );
    fx.set_closed(false);
    let open = fx
        .add(fx.admin, fx.newcomers[3], None)
        .expect("opened again, the admin adds");
    assert_eq!(open.check_in, None, "an open room does not judge the add");
}

/// A walk-in is a self-add (P26B-WALKIN = A): in an open room a vault
/// Admin's walk-in is not judged. Once the room is closed, the Admin's
/// walk-in waits AlwaysAsk on the one rung `room_owner`, which pins every
/// owner of the room, the Admin who owns it included; the owner approves,
/// and the Admin's call naming the check-in walks in with the approved
/// decision. In again, the Admin's repeat is a self re-add, not judged. The
/// vault's owner, and the Admin who owns the room, walk in at once, basis
/// `room_owner`.
#[test]
fn a_vault_admins_walk_in_to_a_closed_room_waits_on_its_owners() {
    let fx = Room::with_vault_admins();
    let admins = fx.vault_admins.as_ref().expect("the vault's Admins");
    let walker = admins.walker;
    let open = fx
        .add(walker, walker, None)
        .expect("in an open room the Admin walks in");
    assert_eq!(open.check_in, None, "an open room does not judge a walk-in");
    fx.leave(walker);
    fx.set_closed(true);
    let waiting = fx
        .add(walker, walker, None)
        .expect_err("in a closed room the Admin's walk-in waits");
    let id = pending_id(&waiting);
    let again = fx.add(walker, walker, None).expect_err("a repeat waits");
    assert_eq!(pending_id(&again), id, "a repeat names the same check-in");
    let row = fx
        .vault
        .pending_check_in(&EntityId::from_hex(&id).expect("a check-in id"))
        .expect("read the check-in")
        .expect("the check-in is stored");
    assert_eq!((row.asker, row.verb.as_str()), (walker, ADD));
    assert_eq!(row.room, Some(fx.room), "the ask names the closed room");
    assert_eq!(row.mode, CheckInMode::AlwaysAsk);
    let rungs: Vec<Rung> = row.rungs.iter().map(|entry| entry.rung).collect();
    assert_eq!(rungs, vec![Rung::RoomOwner], "the room's owners alone");
    let pinned: BTreeSet<EntityId> = row.rungs[0]
        .holders
        .iter()
        .map(|holder| holder.principal)
        .collect();
    assert_eq!(
        pinned,
        BTreeSet::from([fx.owner, fx.co_owner, admins.room_owner])
    );
    let settled = fx.approves(fx.owner, &id).expect("the owner answers");
    assert_eq!(settled["eligible"].as_str(), Some("approved"), "{settled}");

    let walked = fx
        .add(walker, walker, Some(&id))
        .expect("the approved walk-in lands");
    let decision = walked.check_in.expect("the walk-in records its decision");
    assert_eq!(
        (
            decision.act_class.as_str(),
            decision.role.as_str(),
            decision.mode.as_deref(),
            decision.basis.as_str(),
            decision.check_in.as_deref(),
        ),
        (
            "room_add",
            "admin",
            Some(CheckInMode::AlwaysAsk.as_str()),
            "approved",
            Some(id.as_str())
        )
    );
    let re_add = fx
        .add(walker, walker, None)
        .expect("in again, the Admin's repeat lands");
    assert_eq!(re_add.check_in, None, "a self re-add is not judged");

    fx.leave(fx.owner);
    for (entrant, role) in [(fx.owner, "owner"), (admins.room_owner, "admin")] {
        let decision = fx
            .add(entrant, entrant, None)
            .expect("an owner of the room walks in at once")
            .check_in
            .expect("the walk-in records its decision");
        assert_eq!(
            (
                decision.role.as_str(),
                decision.basis.as_str(),
                decision.check_in
            ),
            (role, "room_owner", None)
        );
    }
}
