//! PROJECT-EXTRA-ROOMS: a project groups extra rooms beside its home room.
//!
//! Public paths only: `Vault` opens, `put_entity`/`put_project` fixtures,
//! `conversations_create` rooms, the `Memory` project-room doors
//! (`projects_rooms_link`/`projects_rooms_unlink`/`projects_rooms_list`)
//! and the membership/room reads named below. Policy grants ride the public
//! `oneiron::test_support` path, as `agent_room_offer.rs` does, so this file
//! needs no `#![cfg(oneiron_test_support)]` gate and no `test_doors` door.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test project_extra_rooms`.

use std::collections::BTreeSet;

use oneiron::conversation::HistoryChoice;
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND};
use oneiron::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
};
use oneiron::workspace_roster::{
    ProjectRecord, ProjectRoomLinkRequest, ProjectRoomPlace, ProjectRoomsRequest,
};
use oneiron::{DeleteReason, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The shipped default policy pack, whose manifest the room reads are added to.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// A vault this process owns, with its embedded owner. The vault closes
/// before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the vault's writer lease, which the owner's doors
    // ask of the embedded owner.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture {
        vault,
        owner,
        _dir: dir,
    })
}

/// `actor`'s bound facade.
fn mem(fixture: &Fixture, actor: EntityId) -> oneiron::memory::Memory<'_> {
    fixture.vault.memory(actor, EdgeActorClass::Human)
}

/// A PERSON row. Acting as it is `vault.memory(person, Human)`: the actor's
/// stored PERSON type is what binds the pen to the person, so
/// `person_of_actor_in_txn` resolves it with no anchor write.
fn person(fixture: &Fixture) -> TestResult<EntityId> {
    let id = EntityId::now();
    fixture.vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    Ok(id)
}

/// Gives every named PERSON an unrestricted `core:read` grant: one row per
/// reader appended to the shipped policy manifest, its other rows kept. A
/// scoped-read key reads nothing until a trusted manifest grants it, so the
/// room reads below would refuse members and strangers alike without this;
/// with it, membership alone decides them.
fn grant_reads(fixture: &Fixture, readers: &[EntityId]) -> TestResult {
    let vault = &fixture.vault;
    let mut shipped = None;
    for id in vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)? {
        let Some(bytes) = vault.get(&id)? else {
            continue;
        };
        let manifest: serde_json::Value = rmp_serde::from_slice(&bytes)?;
        if manifest["pack_id"] == SHIPPED_POLICY_PACK {
            shipped = Some((id, manifest));
            break;
        }
    }
    let (id, mut manifest) = shipped.ok_or("the vault holds no shipped policy manifest")?;
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let scope = serde_json::to_value(&read)?;
    let grants = manifest["scoped_grants"]
        .as_array_mut()
        .ok_or("the shipped policy manifest has no scoped grants")?;
    for reader in readers {
        grants.push(json!({
            "actor_ref": reader.to_hex(),
            "effector": "core:read",
            "scope": scope.clone(),
            "receipt_required": false,
        }));
    }
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest)?,
    )?;
    Ok(())
}

/// Gives every named PERSON a `core:read` grant scoped to CONVERSATION rows
/// only: the `agent_room_offer.rs` shape exactly, selectors included. A lane
/// under this grant admits room rows and withholds every other entity kind,
/// so a guest's PROJECT reads refuse on grants, never on roster membership.
fn grant_conversations_only(fixture: &Fixture, readers: &[EntityId]) -> TestResult {
    let vault = &fixture.vault;
    let mut shipped = None;
    for id in vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)? {
        let Some(bytes) = vault.get(&id)? else {
            continue;
        };
        let manifest: serde_json::Value = rmp_serde::from_slice(&bytes)?;
        if manifest["pack_id"] == SHIPPED_POLICY_PACK {
            shipped = Some((id, manifest));
            break;
        }
    }
    let (id, mut manifest) = shipped.ok_or("the vault holds no shipped policy manifest")?;
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let scope = serde_json::to_value(&read)?;
    let grants = manifest["scoped_grants"]
        .as_array_mut()
        .ok_or("the shipped policy manifest has no scoped grants")?;
    for reader in readers {
        grants.push(json!({
            "actor_ref": reader.to_hex(),
            "effector": "core:read",
            "scope": scope.clone(),
            "receipt_required": false,
            "selectors": {"entity_types": [ENTITY_TYPE_CONVERSATION]},
        }));
    }
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest)?,
    )?;
    Ok(())
}

/// A project led by `leader`, boarded by `board`, seated with `roster`, and
/// its home room. An unsigned owner-door row serves its stored leader, board
/// and roster as its effective authority at once, so the leader, the board
/// and the plain members below are effective with no proof ceremony.
/// Returns the project and its home room.
fn project(
    fixture: &Fixture,
    leader: EntityId,
    board: &[EntityId],
    roster: &[EntityId],
    at: u64,
) -> TestResult<(EntityId, EntityId)> {
    let vault = &fixture.vault;
    let root = vault.root_project()?;
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(root), root, leader)?;
    record.board = board.iter().map(EntityId::to_hex).collect();
    for member in roster {
        let hex = member.to_hex();
        if !record.roster.contains(&hex) {
            record.roster.push(hex);
        }
    }
    vault.put_project(id, &record, at)?;
    let home = EntityId::from_hex(&record.home_room)?;
    Ok((id, home))
}

/// An ordinary group room with `members` in its `member_ids`. Naming members
/// in the body authors the room's membership ledger as the writing owner, so
/// a guest becomes a member with no invite flow.
fn room(fixture: &Fixture, members: &[EntityId], title: &str) -> TestResult<EntityId> {
    let receipt = mem(fixture, fixture.owner).conversations_create(&ConversationCreateInput {
        id: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        body: json!({
            "v": 1,
            "kind": "group",
            "member_ids": members.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
            "title": title,
        }),
        text: None,
    })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// A link/unlink request naming `project` and `room_id`.
fn req(project: EntityId, room_id: EntityId) -> ProjectRoomLinkRequest {
    ProjectRoomLinkRequest {
        project_ref: project.to_hex(),
        room_ref: room_id.to_hex(),
    }
}

/// A list request naming `project`.
fn list_req(project: EntityId) -> ProjectRoomsRequest {
    ProjectRoomsRequest {
        project_ref: project.to_hex(),
    }
}

/// Asserts `project` lists its home room alone to `caller`.
fn assert_home_only(
    fixture: &Fixture,
    caller: EntityId,
    project: EntityId,
    home: EntityId,
) -> TestResult {
    let listed = mem(fixture, caller)
        .projects_rooms_list(&list_req(project))
        .expect("listing reads");
    assert_eq!(listed.rows.len(), 1);
    assert_eq!(listed.rows[0].room_ref, home.to_hex());
    assert_eq!(listed.rows[0].place, ProjectRoomPlace::Home);
    Ok(())
}

/// The room's stored `member_ids` as the owner reads them through the entity
/// get. Both reads below pass through the same projection, so equality is
/// an unchanged stored list.
fn stored_members(fixture: &Fixture, room_id: EntityId) -> TestResult<Vec<String>> {
    let view = mem(fixture, fixture.owner)
        .get_entity(&room_id.to_hex())?
        .value
        .ok_or("the owner reads the room row")?;
    let body = view.body.ok_or("the room row carries a body")?;
    let members = body["member_ids"]
        .as_array()
        .ok_or("the room body lists members")?
        .iter()
        .map(|member| {
            member
                .as_str()
                .expect("a member id reads as hex")
                .to_owned()
        })
        .collect();
    Ok(members)
}

/// The room's served body as `caller` reads it through the entity get.
fn served_body(
    fixture: &Fixture,
    caller: EntityId,
    room_id: EntityId,
) -> TestResult<serde_json::Value> {
    let view = mem(fixture, caller)
        .get_entity(&room_id.to_hex())?
        .value
        .ok_or("the caller reads the room row")?;
    Ok(view.body.ok_or("the room row carries a body")?)
}

/// (a) Linking changes no audience: owen reads the room before and after,
/// yuki never does, and the stored member list is unchanged.
#[test]
fn extra_rooms_a_link_changes_no_audience() -> TestResult {
    let fixture = open()?;
    let owen = person(&fixture)?;
    let yuki = person(&fixture)?;
    let leader = person(&fixture)?;
    grant_reads(&fixture, &[owen, yuki, leader])?;
    let (project, _home) = project(&fixture, leader, &[], &[leader, yuki], 2)?;
    let room_id = room(&fixture, &[fixture.owner, owen], "audience room")?;

    // Before: owen reads the room through its roster; yuki does not.
    assert!(mem(&fixture, owen).room_roster(room_id).is_ok());
    let refused = mem(&fixture, yuki)
        .room_roster(room_id)
        .expect_err("yuki stands nowhere in the room");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(refused.message, "unknown room");

    // The room-side rule seats the leader before the link: a linker who is
    // not the vault owner must read the room, and the leader is no member
    // yet. The member snapshot below is taken after this setup join, so the
    // unchanged-list assertion compares the link alone.
    fixture.vault.join_member(
        room_id,
        leader,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        fixture.vault.now_recorded_at(),
        HistoryChoice::Inherit,
    )?;
    assert!(mem(&fixture, owen).room_roster(room_id).is_ok());
    let refused = mem(&fixture, yuki)
        .room_roster(room_id)
        .expect_err("the setup join grants yuki nothing");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(refused.message, "unknown room");
    let mut before = stored_members(&fixture, room_id)?;
    before.sort();

    let linked = mem(&fixture, leader)
        .projects_rooms_link(&req(project, room_id))
        .expect("the leader links the room");
    assert_eq!(linked.project_ref, project.to_hex());
    assert_eq!(linked.room_ref, room_id.to_hex());
    assert_eq!(linked.place, ProjectRoomPlace::Extra);

    // After: owen still reads the room, yuki still does not.
    assert!(mem(&fixture, owen).room_roster(room_id).is_ok());
    let refused = mem(&fixture, yuki)
        .room_roster(room_id)
        .expect_err("the link grants yuki nothing");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(refused.message, "unknown room");
    let mut after = stored_members(&fixture, room_id)?;
    after.sort();
    assert_eq!(after, before, "the link writes no membership row");

    // The second both-shapes read agrees: the room-turn ceiling opens for
    // the member and refuses the stranger. `RoomTurnHandle` carries no
    // `Debug`, so the refusal is matched, not `expect_err`ed.
    assert!(mem(&fixture, owen).for_room_turn(room_id).is_ok());
    let Err(refused) = mem(&fixture, yuki).for_room_turn(room_id) else {
        panic!("no ceiling for a stranger");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(refused.message, "unknown room");
    Ok(())
}

/// (b) A non-project guest of an extra room sees that room only: R1 reads,
/// the home room and R2 refuse, the project lists empty, the PROJECT record
/// serves to a member and withholds from the guest, the member-gated asks
/// refuse the guest, and the served R1 body omits the key while a project
/// member seated in R1 is served it.
#[test]
fn extra_rooms_b_guest_sees_only_its_room() -> TestResult {
    let fixture = open()?;
    let leader = person(&fixture)?;
    let member = person(&fixture)?;
    let guest = person(&fixture)?;
    // Grant split: members read everything, the guest reads CONVERSATION
    // rows only. No roster-membership gate stands in front of the generic
    // PROJECT get, so the grant shape below is what withholds the PROJECT
    // record from the guest; the report traces this.
    grant_reads(&fixture, &[leader, member])?;
    grant_conversations_only(&fixture, &[guest])?;
    let (project, home) = project(&fixture, leader, &[], &[leader, member], 2)?;
    let r1 = room(&fixture, &[fixture.owner, guest, member], "extra room one")?;
    let r2 = room(&fixture, &[fixture.owner, member], "extra room two")?;
    // The room-side rule seats the leader in both extras before it links them.
    let writer = WriteActor::new(fixture.owner, EdgeActorClass::Human);
    let at = fixture.vault.now_recorded_at();
    fixture
        .vault
        .join_member(r1, leader, writer, at, HistoryChoice::Inherit)?;
    fixture
        .vault
        .join_member(r2, leader, writer, at, HistoryChoice::Inherit)?;
    mem(&fixture, leader)
        .projects_rooms_link(&req(project, r1))
        .expect("the leader links R1");
    mem(&fixture, leader)
        .projects_rooms_link(&req(project, r2))
        .expect("the leader links R2");

    // The guest reads R1 through its roster ...
    assert!(mem(&fixture, guest).room_roster(r1).is_ok());
    // ... but not the project's home room through its history ...
    let no_home = mem(&fixture, guest)
        .rooms_messages(home)
        .expect_err("the guest stands nowhere in the home room");
    assert_eq!(no_home.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(no_home.message, "unknown room");
    // ... and not the extra room it is no member of.
    let no_r2 = mem(&fixture, guest)
        .room_roster(r2)
        .expect_err("the guest stands nowhere in R2");
    assert_eq!(no_r2.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(no_r2.message, "unknown room");
    // The project lists no rooms to a caller who cannot read it: an empty
    // page, no error, no hint.
    let page = mem(&fixture, guest)
        .projects_rooms_list(&list_req(project))
        .expect("the guest lists an empty page");
    assert!(page.rows.is_empty());
    // The PROJECT record surface: the member reads the record with its
    // roster, while the guest's CONVERSATION-only grant withholds the row.
    let member_project = mem(&fixture, member)
        .get_entity(&project.to_hex())?
        .value
        .ok_or("a member reads the PROJECT row")?;
    let member_roster = member_project
        .body
        .ok_or("the PROJECT row carries a body")?["roster"]
        .as_array()
        .ok_or("the PROJECT body carries its roster")?
        .clone();
    assert!(
        member_roster
            .iter()
            .any(|seat| seat.as_str() == Some(leader.to_hex().as_str())),
        "the roster seats the leader: {member_roster:?}"
    );
    assert!(
        member_roster
            .iter()
            .any(|seat| seat.as_str() == Some(member.to_hex().as_str())),
        "the roster seats the member: {member_roster:?}"
    );
    let guest_project = mem(&fixture, guest).get_entity(&project.to_hex())?.value;
    assert!(
        guest_project.is_none(),
        "a CONVERSATION-only grant reads no PROJECT row"
    );
    // The project's asks, a member-gated side read, refuse the guest and
    // serve the member. This is further isolation evidence, not the record
    // assertion above: the asks are not the PROJECT record.
    let no_asks = mem(&fixture, guest)
        .project_asks(project)
        .expect_err("the guest reads no project asks");
    assert_eq!(no_asks.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        no_asks.message.contains("read by its members"),
        "{}",
        no_asks.message
    );
    let asks = mem(&fixture, member)
        .project_asks(project)
        .expect("a member reads the project's asks");
    assert!(asks.is_empty());
    // Redaction: the guest's served R1 body omits the key ...
    let guest_body = served_body(&fixture, guest, r1)?;
    assert!(
        guest_body.get("project_group").is_none(),
        "no topology to outsiders: {guest_body}"
    );
    // ... while a project member seated in R1 is served it, naming the project.
    let member_body = served_body(&fixture, member, r1)?;
    assert_eq!(
        member_body
            .get("project_group")
            .and_then(|key| key.as_str()),
        Some(project.to_hex().as_str())
    );
    Ok(())
}

/// (c) A room belongs to at most one project, as home or as extra.
#[test]
fn extra_rooms_c_room_belongs_to_at_most_one_project() -> TestResult {
    let fixture = open()?;
    let leader = person(&fixture)?;
    grant_reads(&fixture, &[leader])?;
    let (p1, home1) = project(&fixture, leader, &[], &[leader], 2)?;
    let (p2, _home2) = project(&fixture, leader, &[], &[leader], 2)?;
    let room_id = room(&fixture, &[fixture.owner, leader], "shared room")?;

    mem(&fixture, leader)
        .projects_rooms_link(&req(p1, room_id))
        .expect("link R to P1");
    let taken = mem(&fixture, leader)
        .projects_rooms_link(&req(p2, room_id))
        .expect_err("R already belongs to a project");
    assert_eq!(taken.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        taken.message.contains("unlink it first"),
        "{}",
        taken.message
    );
    let again = mem(&fixture, leader)
        .projects_rooms_link(&req(p1, room_id))
        .expect_err("R already belongs to this project");
    assert_eq!(again.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        again.message.contains("unlink it first"),
        "{}",
        again.message
    );
    let home_link = mem(&fixture, leader)
        .projects_rooms_link(&req(p2, home1))
        .expect_err("a home room never links as an extra room");
    assert_eq!(home_link.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        home_link
            .message
            .contains("cannot be linked as an extra room"),
        "{}",
        home_link.message
    );
    let home_unlink = mem(&fixture, leader)
        .projects_rooms_unlink(&req(p1, home1))
        .expect_err("a home room never unlinks");
    assert_eq!(home_unlink.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        home_unlink.message.contains("cannot be unlinked"),
        "{}",
        home_unlink.message
    );
    let wrong = mem(&fixture, leader)
        .projects_rooms_unlink(&req(p2, room_id))
        .expect_err("R is no extra room of P2");
    assert_eq!(wrong.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        wrong.message.contains("not an extra room of this project"),
        "{}",
        wrong.message
    );
    mem(&fixture, leader)
        .projects_rooms_unlink(&req(p1, room_id))
        .expect("unlink R from P1");
    mem(&fixture, leader)
        .projects_rooms_link(&req(p2, room_id))
        .expect("link R to P2 once unlinked");
    Ok(())
}

/// (d) Only the vault owner or a project admin links or unlinks, and a
/// caller who cannot read the room learns nothing about it.
#[test]
fn extra_rooms_d_only_owner_or_admin_links() -> TestResult {
    let fixture = open()?;
    let leader = person(&fixture)?;
    let board = person(&fixture)?;
    let yuki = person(&fixture)?;
    let owen = person(&fixture)?;
    grant_reads(&fixture, &[leader, board, yuki, owen])?;
    let (p1, home1) = project(&fixture, leader, &[board], &[leader, board, yuki], 2)?;
    let room_id = room(&fixture, &[fixture.owner, leader, board], "admin room")?;

    // A plain roster member is refused both ways, and the project still
    // lists its home room alone after each refusal.
    let yuki_link = mem(&fixture, yuki)
        .projects_rooms_link(&req(p1, room_id))
        .expect_err("a plain member links nothing");
    assert_eq!(yuki_link.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        yuki_link.message.contains("leader or board"),
        "{}",
        yuki_link.message
    );
    assert_home_only(&fixture, leader, p1, home1)?;
    let yuki_unlink = mem(&fixture, yuki)
        .projects_rooms_unlink(&req(p1, room_id))
        .expect_err("a plain member unlinks nothing");
    assert_eq!(yuki_unlink.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        yuki_unlink.message.contains("leader or board"),
        "{}",
        yuki_unlink.message
    );
    assert_home_only(&fixture, leader, p1, home1)?;

    // The leader links, a board member unlinks, the owner links again.
    mem(&fixture, leader)
        .projects_rooms_link(&req(p1, room_id))
        .expect("the leader links");
    mem(&fixture, board)
        .projects_rooms_unlink(&req(p1, room_id))
        .expect("a board member unlinks");
    let relinked = mem(&fixture, fixture.owner)
        .projects_rooms_link(&req(p1, room_id))
        .expect("the owner links");
    assert_eq!(relinked.project_ref, p1.to_hex());
    assert_eq!(relinked.room_ref, room_id.to_hex());
    assert_eq!(relinked.place, ProjectRoomPlace::Extra);

    // ROOM SIDE: the leader stands nowhere in R3, so linking and unlinking
    // it refuse exactly as an unknown room id does.
    let r3 = room(&fixture, &[fixture.owner, owen], "stranger room")?;
    let side_link = mem(&fixture, leader)
        .projects_rooms_link(&req(p1, r3))
        .expect_err("the leader reads no R3");
    let unknown = EntityId::now();
    let missing = mem(&fixture, leader)
        .projects_rooms_link(&ProjectRoomLinkRequest {
            project_ref: p1.to_hex(),
            room_ref: unknown.to_hex(),
        })
        .expect_err("an unknown room id links nowhere");
    assert_eq!(side_link.code, MEMORY_CODE_NOT_FOUND);
    assert_eq!(side_link.message, "room not found");
    assert_eq!(missing.code, MEMORY_CODE_NOT_FOUND);
    assert_eq!(missing.message, "room not found");
    assert_eq!(side_link, missing);
    assert_eq!(format!("{side_link}"), format!("{missing}"));
    let side_unlink = mem(&fixture, leader)
        .projects_rooms_unlink(&req(p1, r3))
        .expect_err("the leader unlinks no R3");
    assert_eq!(side_unlink, side_link);

    // The same silence covers a second project's home room the leader is
    // not in: the room-side refusal, not the home-room message.
    let (_p2, home2) = project(&fixture, fixture.owner, &[], &[fixture.owner], 2)?;
    let home_side = mem(&fixture, leader)
        .projects_rooms_link(&req(p1, home2))
        .expect_err("the leader reads no P2 home room");
    assert_eq!(home_side.code, MEMORY_CODE_NOT_FOUND);
    assert_eq!(home_side.message, "room not found");
    assert_eq!(home_side, side_link);

    // The vault owner needs no room standing.
    let owner_link = mem(&fixture, fixture.owner)
        .projects_rooms_link(&req(p1, r3))
        .expect("the owner links R3");
    assert_eq!(owner_link.place, ProjectRoomPlace::Extra);
    Ok(())
}

/// (e) A generic write cannot stamp the key, while a room-body door that
/// rewrites a linked room keeps its link.
#[test]
fn extra_rooms_e_generic_write_cannot_stamp() -> TestResult {
    let fixture = open()?;
    let leader = person(&fixture)?;
    let guest = person(&fixture)?;
    grant_reads(&fixture, &[leader, guest])?;
    let (project, _home) = project(&fixture, leader, &[], &[leader], 2)?;

    // A generic door refuses a body that carries the key.
    let stamped = mem(&fixture, fixture.owner)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({
                "v": 1,
                "kind": "group",
                "member_ids": [fixture.owner.to_hex()],
                "project_group": project.to_hex(),
            }),
            text: None,
        })
        .expect_err("a generic door never stamps the key");
    assert_eq!(stamped.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        stamped.message.contains("project_group"),
        "{}",
        stamped.message
    );

    // A linked room rewritten by the membership door keeps its link: the
    // leader's list still shows it as an extra room.
    let room_id = room(&fixture, &[fixture.owner, leader], "kept link room")?;
    mem(&fixture, leader)
        .projects_rooms_link(&req(project, room_id))
        .expect("the leader links");
    fixture.vault.join_member(
        room_id,
        guest,
        WriteActor::new(fixture.owner, EdgeActorClass::Human),
        fixture.vault.now_recorded_at(),
        HistoryChoice::Inherit,
    )?;
    let listed = mem(&fixture, leader)
        .projects_rooms_list(&list_req(project))
        .expect("the leader lists");
    assert!(
        listed
            .rows
            .iter()
            .any(|row| row.room_ref == room_id.to_hex() && row.place == ProjectRoomPlace::Extra),
        "the rewritten room keeps its link: {listed:?}"
    );
    Ok(())
}

/// (f) Deleting a project drops its links: the freed room groups under a
/// second project.
///
/// The delete is the public soft erase, which keeps the effective record
/// while the entity row goes non-live. The doors tell the two apart: P1's
/// list answers empty (not home-only), and every caller's served body of R
/// drops the stale key with the room's own data preserved.
#[test]
fn extra_rooms_f_project_delete_drops_links() -> TestResult {
    let fixture = open()?;
    let leader = person(&fixture)?;
    grant_reads(&fixture, &[fixture.owner, leader])?;
    let (p1, _home1) = project(&fixture, leader, &[], &[leader], 2)?;
    let (p2, _home2) = project(&fixture, leader, &[], &[leader], 2)?;
    let room_id = room(&fixture, &[fixture.owner, leader], "roaming room")?;
    mem(&fixture, leader)
        .projects_rooms_link(&req(p1, room_id))
        .expect("link R to P1");
    let members_before = stored_members(&fixture, room_id)?;

    // The public project delete drops P1's links: its list answers empty
    // (the live check fails even though the effective record survives), the
    // owner's served body of R drops the stale key with the room's members
    // intact, and the freed room links into P2.
    fixture
        .vault
        .delete_entity_with_reason(&p1, DeleteReason::UserDelete)?;
    let listed = mem(&fixture, leader).projects_rooms_list(&list_req(p1))?;
    assert!(
        listed.rows.is_empty(),
        "P1's list is empty once P1 is deleted"
    );
    let served = served_body(&fixture, fixture.owner, room_id)?;
    assert!(
        served.get("project_group").is_none(),
        "the owner's served body drops the stale key"
    );
    assert_eq!(
        stored_members(&fixture, room_id)?,
        members_before,
        "the room keeps its stored members"
    );
    mem(&fixture, leader)
        .projects_rooms_link(&req(p2, room_id))
        .expect("link R to P2 once P1 is gone");
    Ok(())
}
