//! A pen walks in to a private thread as its PERSON's role (L9-49, OF-529).
//!
//! Owner ruling DECIDE-SWITCHOVER = A and Engine ruling
//! L9-49-AGENT-ROLE-WALK-IN = A: a pen whose PERSON is the vault's Owner or
//! an Admin, adding itself to a private thread it is not in, walks in as
//! that role, from now on, with no earlier messages. An Admin-role pen walks
//! in only while `rooms.private_threads.admin_walk_in` is on (absent reads
//! ON); an Owner-role pen is not bound by that switch. Opening full history
//! stays the human Owner's own act: a pen asking for Full walks in from now.
//! The members' notice names the agent (subject refs) and its role (detail
//! `walk_in as owner` / `walk_in as admin`). Every other agent keeps
//! AGENT_THREAD_WALK_IN_FORBIDDEN.
//!
//! Fixture per test: a project whose home room seats owen, the vault's
//! owner (its leader), and yuki, an ordinary member; a private thread on a
//! trunk turn whose audience the test names; a pen made through the
//! agent-definition door and anchored to its PERSON through the public
//! subject-anchor setter. The Admin test adds a shared vault whose roster
//! holds owen as Owner, yuki as Admin and a member, each accepted, with the
//! Admin holding no seat in the room.
//!
//! Public paths only; no test door.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_thread_agent_walk_in`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::inbox::{INBOX_PAGE_DEFAULT, NotificationKind};
use oneiron::memory::{MEMORY_CODE_INVALID_STATE, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::subject_model::{ActorSubjectAnchor, SubjectKind};
use oneiron::temporal::TimeRange;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    MEMORY_CODE_AGENT_THREAD_WALK_IN_FORBIDDEN, ProjectRecord, RoomPrivateThreadsRequest,
    ThreadAudienceAddRequest, ThreadAudienceHistory,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const SHARED: u64 = 44;

/// A live PERSON holding `name`, by its new id.
fn put_person(vault: &Vault, name: &[u8]) -> TestResult<EntityId> {
    let id = EntityId::now();
    let now = vault.now_recorded_at();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            name,
        )
        .expect("fixture: a live PERSON");
    Ok(id)
}

/// `person`'s owner-tier proof.
fn owner_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("fixture: the owner proof")
}

/// `member` accepts its founding invitation to the shared vault at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = owner_proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("fixture: the invitations read")
        .into_iter()
        .find(|open| open.role == role)
        .expect("fixture: the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("fixture: the member accepts");
}

/// A project led by `leader` whose home room also seats `extra`; the project
/// id and the room id.
fn project_room(
    vault: &Vault,
    leader: EntityId,
    extra: &[EntityId],
) -> TestResult<(EntityId, EntityId)> {
    let root = vault.root_project().expect("fixture: the root project");
    let project = EntityId::now();
    let mut record =
        ProjectRecord::new(project, Some(root), root, leader).expect("fixture: a project record");
    for member in extra {
        record.roster.push(member.to_hex());
    }
    vault
        .put_project(project, &record, vault.now_recorded_at())
        .expect("fixture: the project");
    let room = EntityId::from_hex(&record.home_room).expect("fixture: the home room id");
    Ok((project, room))
}

/// `speaker`'s trunk turn `turn` in `room`, one MESSAGE.
fn speak_trunk(vault: &Vault, speaker: EntityId, room: EntityId, turn: EntityId) {
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .expect("fixture: the trunk turn");
}

/// `speaker`'s private thread root `root` on `anchor` in `room`, one MESSAGE,
/// for `audience`.
fn speak_private_root(
    vault: &Vault,
    speaker: EntityId,
    room: EntityId,
    anchor: EntityId,
    root: EntityId,
    audience: BTreeSet<EntityId>,
) {
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(root.to_hex()),
            thread_audience: Some(audience),
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "yuki".into(),
                parts: None,
                metadata: Some(serde_json::json!({"room_thread_of": anchor.to_hex()})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .expect("fixture: the private thread root");
}

/// A pen made through the agent-definition door as `owner`, then anchored to
/// `person`: `owner`'s own pen when `person` is `owner`.
fn create_pen(
    vault: &Vault,
    owner: EntityId,
    agent_name: &str,
    person: EntityId,
) -> TestResult<EntityId> {
    let pen = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": agent_name,
        "display_name": agent_name,
        "desc": agent_name,
        "version": "1",
    }))
    .expect("fixture: the agent spec parses");
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")
        .expect("fixture: the owner proof for agent create");
    oneiron::verbs::create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: pen,
            definition,
        },
    )
    .expect("fixture: the agent definition");
    vault
        .set_actor_subject_anchor(
            ActorSubjectAnchor {
                actor_ref: pen,
                subject_ref: person,
                subject_kind: SubjectKind::Person,
            },
            &WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )
        .expect("fixture: the pen anchors to its PERSON");
    Ok(pen)
}

/// How many the private thread rooted at `root` seats now, as `reader` (the
/// vault's Owner) lists it.
fn thread_member_count(vault: &Vault, reader: EntityId, room: EntityId, root: EntityId) -> usize {
    vault
        .memory(reader, EdgeActorClass::Human)
        .rooms_private_threads(&RoomPrivateThreadsRequest {
            room_ref: room.to_hex(),
        })
        .expect("read: the room private threads list")
        .into_iter()
        .find(|listed| listed.id == root.to_hex())
        .expect("read: the thread is listed")
        .member_count
}

#[test]
fn an_owner_pen_walks_in_from_now_and_the_notice_names_it() -> TestResult {
    let dir = tempfile::tempdir().expect("fixture: tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("fixture: the vault");
    let owen = vault
        .ensure_embedded_owner_actor()
        .expect("fixture: the vault Owner");
    let yuki = put_person(&vault, b"yuki").expect("fixture: yuki the member");
    let (_project, room) = project_room(&vault, owen, &[yuki]).expect("fixture: the project room");
    let anchor = EntityId::now();
    speak_trunk(&vault, yuki, room, anchor);
    let root = EntityId::now();
    speak_private_root(&vault, yuki, room, anchor, root, BTreeSet::from([yuki]));
    let pen = create_pen(&vault, owen, "owen-pen", owen).expect("fixture: the Owner pen");
    let proof = owner_proof(&vault, owen);
    let settings = vault
        .set_room_thread_admin_settings(&proof, None, Some(false), None)
        .expect("step: turn admin_walk_in OFF");
    assert!(
        !settings.admin_walk_in,
        "step: the switch reads OFF, got {settings:?}"
    );
    assert_eq!(
        thread_member_count(&vault, owen, room, root),
        1,
        "fixture: the thread seats yuki alone"
    );
    let receipt = vault
        .memory(pen, EdgeActorClass::Agent)
        .rooms_thread_audience_add(&ThreadAudienceAddRequest {
            thread_ref: root.to_hex(),
            person_ref: pen.to_hex(),
            history: ThreadAudienceHistory::Full,
            check_in_ref: None,
        })
        .expect("walk-in: the Owner pen adds itself with Full while the switch is OFF");
    assert_eq!(
        receipt.thread_ref,
        root.to_hex(),
        "walk-in: the receipt names the thread"
    );
    assert_eq!(
        receipt.history,
        Some(ThreadAudienceHistory::FromNow),
        "walk-in: the receipt shows from-now, not the Full the call asked"
    );
    assert_eq!(
        thread_member_count(&vault, owen, room, root),
        2,
        "walk-in: the audience now seats the pen too"
    );
    let inbox = vault
        .memory(yuki, EdgeActorClass::Human)
        .inbox_list(None, INBOX_PAGE_DEFAULT)
        .expect("read: yuki inbox");
    let pen_hex = pen.to_hex();
    let root_hex = root.to_hex();
    let walk = inbox
        .rows
        .iter()
        .find(|row| {
            row.kind == NotificationKind::ThreadWalkIn
                && row.subject_refs.contains(&root_hex)
                && row.subject_refs.contains(&pen_hex)
        })
        .expect("notice: yuki lists the pen walk-in");
    assert_eq!(
        walk.source.detail.as_deref(),
        Some("walk_in as owner"),
        "notice: the detail names the Owner role"
    );
    assert!(
        inbox
            .rows
            .iter()
            .all(|row| row.kind != NotificationKind::ThreadHistoryOpened),
        "notice: no history-opened notice for a from-now walk-in"
    );
    Ok(())
}

#[test]
fn an_admin_pen_walks_in_only_while_the_switch_is_on() -> TestResult {
    let dir = tempfile::tempdir().expect("fixture: tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("fixture: the vault");
    let owen = vault
        .ensure_embedded_owner_actor()
        .expect("fixture: the vault Owner");
    let admin = put_person(&vault, b"yuki").expect("fixture: yuki the Admin");
    let member = put_person(&vault, b"human").expect("fixture: the room member");
    let proof = owner_proof(&vault, owen);
    vault
        .initialize_shared_vault(
            &proof,
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owen,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: admin,
                    role: Some(Role::Admin),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(Role::Member),
                },
            ],
            1,
        )
        .expect("fixture: the shared vault");
    accept(&vault, admin, Role::Admin);
    accept(&vault, member, Role::Member);
    let (_project, room) =
        project_room(&vault, owen, &[member]).expect("fixture: the project room");
    let anchor = EntityId::now();
    speak_trunk(&vault, owen, room, anchor);
    let root = EntityId::now();
    speak_private_root(&vault, owen, room, anchor, root, BTreeSet::from([owen]));
    let pen = create_pen(&vault, owen, "yuki-pen", admin).expect("fixture: the Admin pen");
    let add = || {
        vault
            .memory(pen, EdgeActorClass::Agent)
            .rooms_thread_audience_add(&ThreadAudienceAddRequest {
                thread_ref: root.to_hex(),
                person_ref: pen.to_hex(),
                history: ThreadAudienceHistory::Full,
                check_in_ref: None,
            })
    };
    let switched_off = vault
        .set_room_thread_admin_settings(&proof, None, Some(false), None)
        .expect("step: turn admin_walk_in OFF");
    assert!(
        !switched_off.admin_walk_in,
        "step: the switch reads OFF, got {switched_off:?}"
    );
    let refused = add().expect_err("refusal: the Admin pen self-add with the switch OFF");
    assert_eq!(
        refused.code, MEMORY_CODE_INVALID_STATE,
        "refusal: the code is INVALID_STATE, got {:?}",
        refused.code
    );
    assert!(
        refused.code != MEMORY_CODE_AGENT_THREAD_WALK_IN_FORBIDDEN,
        "refusal: the code is the switch-off, not the agent walk-in refusal"
    );
    assert!(
        refused
            .message
            .contains("rooms.private_threads.admin_walk_in"),
        "refusal: the message names the switch, got {:?}",
        refused.message
    );
    assert_eq!(
        thread_member_count(&vault, owen, room, root),
        1,
        "refusal: the audience is unchanged while the switch is OFF"
    );
    let switched_on = vault
        .set_room_thread_admin_settings(&proof, None, Some(true), None)
        .expect("step: turn admin_walk_in ON");
    assert!(
        switched_on.admin_walk_in,
        "step: the switch reads ON, got {switched_on:?}"
    );
    let receipt = add().expect("walk-in: the Admin pen adds itself with the switch ON");
    assert_eq!(
        receipt.history,
        Some(ThreadAudienceHistory::FromNow),
        "walk-in: the receipt shows from-now, not the Full the call asked"
    );
    let inbox = vault
        .memory(owen, EdgeActorClass::Human)
        .inbox_list(None, INBOX_PAGE_DEFAULT)
        .expect("read: the owner inbox");
    let pen_hex = pen.to_hex();
    let root_hex = root.to_hex();
    let walk = inbox
        .rows
        .iter()
        .find(|row| {
            row.kind == NotificationKind::ThreadWalkIn
                && row.subject_refs.contains(&root_hex)
                && row.subject_refs.contains(&pen_hex)
        })
        .expect("notice: the owner lists the pen walk-in");
    assert_eq!(
        walk.source.detail.as_deref(),
        Some("walk_in as admin"),
        "notice: the detail names the Admin role"
    );
    assert!(
        inbox
            .rows
            .iter()
            .all(|row| row.kind != NotificationKind::ThreadHistoryOpened),
        "notice: no history-opened notice for a from-now walk-in"
    );
    Ok(())
}

#[test]
fn an_agent_without_standing_still_cannot_walk_in() -> TestResult {
    let dir = tempfile::tempdir().expect("fixture: tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("fixture: the vault");
    let owen = vault
        .ensure_embedded_owner_actor()
        .expect("fixture: the vault Owner");
    let yuki = put_person(&vault, b"yuki").expect("fixture: yuki the member");
    let (_project, room) = project_room(&vault, owen, &[yuki]).expect("fixture: the project room");
    let anchor = EntityId::now();
    speak_trunk(&vault, yuki, room, anchor);
    let root = EntityId::now();
    speak_private_root(&vault, yuki, room, anchor, root, BTreeSet::from([yuki]));
    let pen = create_pen(&vault, owen, "yuki-pen", yuki).expect("fixture: the member pen");
    let before = thread_member_count(&vault, owen, room, root);
    assert_eq!(before, 1, "fixture: the thread seats yuki alone");
    let refused = vault
        .memory(pen, EdgeActorClass::Agent)
        .rooms_thread_audience_add(&ThreadAudienceAddRequest {
            thread_ref: root.to_hex(),
            person_ref: pen.to_hex(),
            history: ThreadAudienceHistory::Full,
            check_in_ref: None,
        })
        .expect_err("refusal: the pen without standing adds itself");
    assert_eq!(
        refused.code, MEMORY_CODE_AGENT_THREAD_WALK_IN_FORBIDDEN,
        "refusal: the code stays the walk-in refusal, got {:?}",
        refused.code
    );
    assert_eq!(
        thread_member_count(&vault, owen, room, root),
        before,
        "refusal: the audience is unchanged"
    );
    let inbox = vault
        .memory(yuki, EdgeActorClass::Human)
        .inbox_list(None, INBOX_PAGE_DEFAULT)
        .expect("read: yuki inbox");
    let pen_hex = pen.to_hex();
    assert!(
        inbox
            .rows
            .iter()
            .all(|row| !(row.kind == NotificationKind::ThreadWalkIn
                && row.subject_refs.contains(&pen_hex))),
        "refusal: no walk-in notice for a pen that did not enter"
    );
    Ok(())
}
