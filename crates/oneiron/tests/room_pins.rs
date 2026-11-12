//! A room's shared pins (ROOM-SCOPED-PINS; owner 12 Nov 00:04, ROOM-PIN-WRITERS
//! = A; Engine ruling THREADTASK-PINS-SHAPE 00:51): any current member pins
//! and unpins them, an agent only as its pen PERSON's delegate and never
//! beyond that PERSON, the room's managers may be the only writers, each pin
//! records the PERSON, the acting agent and the time, and no served room
//! body carries the list.
//!
//! P2: a reader sees a pin only when it reads the room and the pin's target
//! through its room read. The room's outline (`rooms_render` and its pages)
//! carries the admitted records, and `include_room_pins` puts each admitted
//! target into the MEMORIES PINNED tier with its record. A withheld target
//! leaves no record, row or count.
//!
//! Fixture: a project whose home room seats the leader, a plain member, and
//! four agents: the leader's pen, the member's pen, the pen of an outsider
//! (a PERSON the room does not seat) and an agent that is no one's pen. The
//! leader speaks three trunk turns; their MESSAGEs are the pin targets.
//! None of the PERSONs is the vault's owner. Each holds one public contact
//! the owner precleared at top, since a PERSON with no contact clearance
//! reads only public rows and a room's MESSAGEs are born Sensitive; every
//! seated non-owner holds a grant over the room's messages, since a room
//! read admits a row only when every reader of its audience may.
//!
//! Public paths only; no test door. One delete goes through the
//! `test-support` seam `delete_room_record_unchecked_for_test`.
//! `cargo test --locked -p oneiron --all-features --test room_pins`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::context_board::{MemoriesSection, MemoryTier, assemble_memories_sections};
use oneiron::conversation::{ConversationBody, ConversationKind, RoomPin, RoomPinPolicy, RoomRole};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{ProjectRecord, RoomPinPolicySet, RoomPinReply, RoomPinRequest};
use oneiron::{DeleteReason, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    leader: EntityId,
    member: EntityId,
    outsider: EntityId,
    leader_agent: EntityId,
    member_agent: EntityId,
    outsider_agent: EntityId,
    unanchored_agent: EntityId,
    project_id: EntityId,
    project: ProjectRecord,
    room: EntityId,
    targets: [EntityId; 3],
    directory: tempfile::TempDir,
}

fn put_person(vault: &Vault) -> TestResult<EntityId> {
    let person = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owen",
    )?;
    Ok(person)
}

/// Each of `principals` reads `room`'s MESSAGEs under an active grant.
fn grant_room_messages(vault: &Vault, room: EntityId, principals: &[EntityId]) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for &principal in principals {
        vault.create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope: authority_scope.clone(),
                principal_ref: principal,
                scope: AccessGrantScope::ConversationMessages {
                    conversation_ref: room,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at,
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )?;
    }
    Ok(())
}

/// A trunk turn in `room` holding the one MESSAGE `message`.
fn trunk_turn(vault: &Vault, room: EntityId, message: EntityId) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "owen".into(),
            parts: None,
            metadata: Some(serde_json::Value::Object(serde_json::Map::new())),
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: vault.now_recorded_at(),
        assertions: Default::default(),
    }
}

/// The leader's trunk turn in the home room `room`, one MESSAGE; returns the
/// MESSAGE id.
fn speak_trunk(vault: &Vault, leader: EntityId, room: EntityId) -> TestResult<EntityId> {
    let message = EntityId::now();
    vault
        .memory(leader, EdgeActorClass::Human)
        .rooms_speak(&trunk_turn(vault, room, message))?;
    Ok(message)
}

/// `speaker`'s trunk turn in the ordinary room `room`, one MESSAGE, through
/// the witness gate: `rooms_speak` serves project rooms only and refuses an
/// ordinary room as "invalid project or home room". Returns the MESSAGE id.
fn say_in_ordinary_room(vault: &Vault, speaker: EntityId, room: EntityId) -> TestResult<EntityId> {
    let message = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&trunk_turn(vault, room, message))?;
    Ok(message)
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let leader = put_person(&vault)?;
    let member = put_person(&vault)?;
    let outsider = put_person(&vault)?;
    // One public contact per PERSON, precleared at top through the owner's
    // door. Public discovery is not public disclosure.
    for (person, counterparty, label) in [
        (leader, "owen@example.com", "owen"),
        (member, "yuki@example.com", "yuki"),
        (outsider, "owen.two@example.com", "owen-two"),
    ] {
        let contact = EntityId::now();
        vault.create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(person, counterparty, vault.now_recorded_at())?,
        )?;
        vault.preclear_contact_disclosure(&proof, label, &[contact], Scope::top())?;
    }
    let mut agents = Vec::new();
    for agent_id in ["yuki", "yuki-b", "yuki-c", "yuki-d"] {
        let agent = EntityId::now();
        let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
            "agent_id": agent_id,
            "display_name": "yuki",
            "desc": "yuki",
            "version": "1",
            "ceiling": "auto",
        }))?;
        oneiron::verbs::create_agent_definition_as(
            &vault,
            &proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: agent,
                definition,
            },
        )?;
        agents.push(agent);
    }
    let [leader_agent, member_agent, outsider_agent, unanchored_agent] = agents[..] else {
        return Err("four agents".into());
    };
    // Each pen agent is its PERSON's, by the owner's anchor.
    for (agent, person) in [
        (leader_agent, leader),
        (member_agent, member),
        (outsider_agent, outsider),
    ] {
        oneiron::subject_model::anchor_actor_subject(
            &vault,
            agent,
            person,
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
    }
    // The agents ask under their own Auto ceilings; everyone reads the
    // vault's records. The shipped rows stay.
    let view =
        policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for agent in [leader_agent, member_agent, outsider_agent, unanchored_agent] {
        manifest.actor_ceilings.push(ActorCeiling {
            actor_class: "agent".into(),
            actor_ref: Some(agent.to_hex()),
            ceiling: PolicyCeiling::Auto,
        });
    }
    for actor in [
        leader,
        member,
        outsider,
        leader_agent,
        member_agent,
        outsider_agent,
        unanchored_agent,
    ] {
        rows.push(PolicyScopedGrantRow {
            actor_class: None,
            actor_ref: Some(actor.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
    }
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    let root_project = vault.root_project()?;
    let project_id = EntityId::now();
    let mut project = ProjectRecord::new(project_id, Some(root_project), root_project, leader)?;
    project.roster.extend([
        member.to_hex(),
        leader_agent.to_hex(),
        member_agent.to_hex(),
        outsider_agent.to_hex(),
        unanchored_agent.to_hex(),
    ]);
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    grant_room_messages(
        &vault,
        room,
        &[
            leader,
            member,
            leader_agent,
            member_agent,
            outsider_agent,
            unanchored_agent,
        ],
    )?;
    let targets = [
        speak_trunk(&vault, leader, room)?,
        speak_trunk(&vault, leader, room)?,
        speak_trunk(&vault, leader, room)?,
    ];
    Ok(Fixture {
        vault,
        owner,
        leader,
        member,
        outsider,
        leader_agent,
        member_agent,
        outsider_agent,
        unanchored_agent,
        project_id,
        project,
        room,
        targets,
        directory,
    })
}

fn person(fx: &Fixture, actor: EntityId) -> oneiron::memory::Memory<'_> {
    fx.vault.memory(actor, EdgeActorClass::Human)
}

fn agent(fx: &Fixture, actor: EntityId) -> oneiron::memory::Memory<'_> {
    fx.vault.memory(actor, EdgeActorClass::Agent)
}

fn pin(room: EntityId, target: EntityId) -> RoomPinRequest {
    RoomPinRequest { room, target }
}

/// The pins the stored room body holds, read unscoped as the engine does.
fn stored_pins(fx: &Fixture, room: EntityId) -> TestResult<Vec<RoomPin>> {
    Ok(fx.vault.conversation_body(room)?.pins)
}

fn set_policy(
    memory: &oneiron::memory::Memory<'_>,
    room: EntityId,
    policy: RoomPinPolicy,
) -> Result<RoomPinPolicySet, oneiron::memory::MemoryError> {
    memory.rooms_pins_policy_set(&RoomPinPolicySet { room, policy })
}

/// (a) A member pins and unpins, and so does that member's pen agent, on the
/// one shared list.
#[test]
fn member_and_pen_agent_pin_and_unpin() -> TestResult {
    let fx = open_fixture()?;
    let RoomPinReply { pin: by_member, .. } =
        person(&fx, fx.member).rooms_pins_pin(&pin(fx.room, fx.targets[0]))?;
    assert_eq!(by_member.target, fx.targets[0]);
    let RoomPinReply { pin: by_agent, .. } =
        agent(&fx, fx.member_agent).rooms_pins_pin(&pin(fx.room, fx.targets[1]))?;
    assert_eq!(by_agent.target, fx.targets[1]);
    assert_eq!(
        stored_pins(&fx, fx.room)?,
        vec![by_member.clone(), by_agent]
    );
    // The list is shared: the agent removes the member's pin.
    agent(&fx, fx.member_agent).rooms_pins_unpin(&pin(fx.room, fx.targets[0]))?;
    person(&fx, fx.member).rooms_pins_unpin(&pin(fx.room, fx.targets[1]))?;
    assert!(stored_pins(&fx, fx.room)?.is_empty());
    Ok(())
}

/// (a) A PERSON the room does not seat is refused, and so is its pen agent
/// though the agent itself is seated; an agent that is no one's pen is
/// refused, seated or not, with the pen rule named. Nothing is written.
#[test]
fn nonmember_and_its_agent_are_refused() -> TestResult {
    let fx = open_fixture()?;
    let request = pin(fx.room, fx.targets[0]);
    assert!(person(&fx, fx.outsider).rooms_pins_pin(&request).is_err());
    assert!(
        agent(&fx, fx.outsider_agent)
            .rooms_pins_pin(&request)
            .is_err()
    );
    assert!(person(&fx, fx.outsider).rooms_pins_unpin(&request).is_err());
    let refusal = agent(&fx, fx.unanchored_agent)
        .rooms_pins_pin(&request)
        .expect_err("an agent that is no one's pen never pins");
    assert!(
        format!("{refusal:?}").contains("pen"),
        "the refusal names the pen rule: {refusal:?}"
    );
    assert!(stored_pins(&fx, fx.room)?.is_empty());
    Ok(())
}

/// (b) A home room lets every member pin by default; under Managers a plain
/// member and its agent are refused and the leader succeeds. A plain member
/// and any agent cannot set the policy.
#[test]
fn managers_policy_restricts_home_room_pinning() -> TestResult {
    let fx = open_fixture()?;
    person(&fx, fx.member).rooms_pins_pin(&pin(fx.room, fx.targets[0]))?;
    assert!(set_policy(&person(&fx, fx.member), fx.room, RoomPinPolicy::Managers).is_err());
    assert!(
        set_policy(
            &agent(&fx, fx.leader_agent),
            fx.room,
            RoomPinPolicy::Managers
        )
        .is_err()
    );
    let set = set_policy(&person(&fx, fx.leader), fx.room, RoomPinPolicy::Managers)?;
    assert_eq!(set.policy, RoomPinPolicy::Managers);
    assert_eq!(
        fx.vault.conversation_body(fx.room)?.pin_policy,
        RoomPinPolicy::Managers
    );
    let request = pin(fx.room, fx.targets[1]);
    assert!(person(&fx, fx.member).rooms_pins_pin(&request).is_err());
    assert!(
        agent(&fx, fx.member_agent)
            .rooms_pins_pin(&request)
            .is_err()
    );
    assert!(
        person(&fx, fx.member)
            .rooms_pins_unpin(&pin(fx.room, fx.targets[0]))
            .is_err()
    );
    person(&fx, fx.leader).rooms_pins_pin(&request)?;
    assert_eq!(stored_pins(&fx, fx.room)?.len(), 2);
    Ok(())
}

/// (b) In an ordinary room the owner or an admin sets the policy and a plain
/// member cannot; the default lets a member change the pins, Managers does
/// not, and an admin's pen agent still may. Unpin reads no target, so it
/// shows the writer rule alone.
#[test]
fn managers_policy_in_an_ordinary_room() -> TestResult {
    let fx = open_fixture()?;
    let room = EntityId::now();
    let owner = WriteActor::new(fx.owner, EdgeActorClass::Human);
    fx.vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![fx.leader, fx.member],
            ..Default::default()
        },
        owner,
        fx.vault.now_recorded_at(),
    )?;
    fx.vault
        .set_room_role(room, fx.leader, RoomRole::Admin, owner)?;
    let target = pin(room, fx.targets[0]);
    person(&fx, fx.member).rooms_pins_unpin(&target)?;
    agent(&fx, fx.member_agent).rooms_pins_unpin(&target)?;
    assert!(person(&fx, fx.outsider).rooms_pins_unpin(&target).is_err());
    assert!(set_policy(&person(&fx, fx.member), room, RoomPinPolicy::Managers).is_err());
    set_policy(&person(&fx, fx.leader), room, RoomPinPolicy::Managers)?;
    assert!(person(&fx, fx.member).rooms_pins_unpin(&target).is_err());
    assert!(
        agent(&fx, fx.member_agent)
            .rooms_pins_unpin(&target)
            .is_err()
    );
    person(&fx, fx.leader).rooms_pins_unpin(&target)?;
    agent(&fx, fx.leader_agent).rooms_pins_unpin(&target)?;
    // The owner sets it back; members may again.
    set_policy(&person(&fx, fx.owner), room, RoomPinPolicy::Members)?;
    person(&fx, fx.member).rooms_pins_unpin(&target)?;
    Ok(())
}

/// (c) Each record names the PERSON and the acting agent, with the engine
/// time; a re-pin keeps the first record, and the records survive a reopen.
#[test]
fn pin_records_person_agent_and_time() -> TestResult {
    let fx = open_fixture()?;
    let before = fx.vault.now_recorded_at();
    let direct = person(&fx, fx.member)
        .rooms_pins_pin(&pin(fx.room, fx.targets[0]))?
        .pin;
    let delegated = agent(&fx, fx.leader_agent)
        .rooms_pins_pin(&pin(fx.room, fx.targets[1]))?
        .pin;
    assert_eq!((direct.pinned_by, direct.acting_agent), (fx.member, None));
    assert_eq!(
        (delegated.pinned_by, delegated.acting_agent),
        (fx.leader, Some(fx.leader_agent))
    );
    let after = fx.vault.now_recorded_at();
    for record in [&direct, &delegated] {
        assert!((before..=after).contains(&record.pinned_at));
    }
    // A re-pin by someone else keeps the first record.
    let again = agent(&fx, fx.member_agent)
        .rooms_pins_pin(&pin(fx.room, fx.targets[0]))?
        .pin;
    assert_eq!(again, direct);
    let Fixture {
        vault,
        room,
        directory,
        ..
    } = fx;
    drop(vault);
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    assert_eq!(vault.conversation_body(room)?.pins, vec![direct, delegated]);
    Ok(())
}

/// (d) An agent never pins beyond its PERSON: the outsider's pen is refused
/// though seated, the member's pen is refused under Managers where the
/// member is, and the leader's pen pins there as the leader may.
#[test]
fn delegate_cannot_exceed_its_person() -> TestResult {
    let fx = open_fixture()?;
    let request = pin(fx.room, fx.targets[2]);
    assert!(
        agent(&fx, fx.outsider_agent)
            .rooms_pins_pin(&request)
            .is_err()
    );
    set_policy(&person(&fx, fx.leader), fx.room, RoomPinPolicy::Managers)?;
    assert!(person(&fx, fx.member).rooms_pins_pin(&request).is_err());
    assert!(
        agent(&fx, fx.member_agent)
            .rooms_pins_pin(&request)
            .is_err()
    );
    let record = agent(&fx, fx.leader_agent).rooms_pins_pin(&request)?.pin;
    assert_eq!(
        (record.pinned_by, record.acting_agent),
        (fx.leader, Some(fx.leader_agent))
    );
    Ok(())
}

/// No served read carries the list: the room's entity read and the room
/// list a member gets hold no `pins`, while the stored body does.
#[test]
fn served_room_reads_carry_no_pins() -> TestResult {
    let fx = open_fixture()?;
    person(&fx, fx.leader).rooms_pins_pin(&pin(fx.room, fx.targets[0]))?;
    assert_eq!(stored_pins(&fx, fx.room)?.len(), 1);
    let read = person(&fx, fx.member).get_entity(&fx.room.to_hex())?;
    let served = serde_json::to_value(&read.value)?;
    assert!(!served.is_null(), "the member reads the room record");
    assert!(
        !served.to_string().contains("\"pins\""),
        "a served room body carries no pins: {served}"
    );
    for (id, room) in person(&fx, fx.member).rooms_list()? {
        if id == fx.room {
            assert!(room.pins.is_empty());
        }
    }
    Ok(())
}

/// A project write rebuilds its home room from the PROJECT and keeps the
/// room's own pins and policy.
#[test]
fn project_change_keeps_room_pins() -> TestResult {
    let fx = open_fixture()?;
    let record = person(&fx, fx.member)
        .rooms_pins_pin(&pin(fx.room, fx.targets[0]))?
        .pin;
    set_policy(&person(&fx, fx.leader), fx.room, RoomPinPolicy::Managers)?;
    let mut project = fx.project.clone();
    project
        .roster
        .retain(|seat| *seat != fx.unanchored_agent.to_hex());
    fx.vault
        .put_project(fx.project_id, &project, fx.vault.now_recorded_at())?;
    let body = fx.vault.conversation_body(fx.room)?;
    assert_eq!(body.pins, vec![record]);
    assert_eq!(body.pin_policy, RoomPinPolicy::Managers);
    Ok(())
}

/// A generic room write cannot add a pin or change the policy; only the pin
/// doors do.
#[test]
fn generic_writers_cannot_edit_pins() -> TestResult {
    let fx = open_fixture()?;
    let room = EntityId::now();
    let owner = WriteActor::new(fx.owner, EdgeActorClass::Human);
    let now = fx.vault.now_recorded_at();
    let mut body = ConversationBody {
        kind: ConversationKind::Group,
        member_ids: vec![fx.member],
        ..Default::default()
    };
    let forged = RoomPin {
        target: fx.targets[0],
        pinned_by: fx.member,
        acting_agent: None,
        pinned_at: now,
    };
    let mut seeded = body.clone();
    seeded.pins = vec![forged.clone()];
    assert!(
        fx.vault
            .create_conversation(room, &seeded, owner, now)
            .is_err(),
        "a new room starts with no pins"
    );
    fx.vault.create_conversation(room, &body, owner, now)?;
    let range = TimeRange {
        start: now,
        end: now,
    };
    body = fx.vault.conversation_body(room)?;
    body.pins = vec![forged];
    let refusal = fx
        .vault
        .put_entity(
            &room,
            ENTITY_TYPE_CONVERSATION,
            range,
            now,
            &body.to_bytes()?,
        )
        .expect_err("a generic put never adds a pin");
    assert!(format!("{refusal:?}").contains("pin"), "{refusal:?}");
    body.pins.clear();
    body.pin_policy = RoomPinPolicy::Managers;
    assert!(
        fx.vault
            .put_entity(
                &room,
                ENTITY_TYPE_CONVERSATION,
                range,
                now,
                &body.to_bytes()?
            )
            .is_err(),
        "a generic put never changes the pin policy"
    );
    assert!(fx.vault.conversation_body(room)?.pins.is_empty());
    Ok(())
}

/// The encoded cost of the records: a PERSON's pin is 115 bytes, an agent's
/// for its PERSON 148, the first pin adds the `pins` key and list header (6
/// bytes), Managers adds 20 bytes, and an unpinned room's bytes are those of
/// a body without the fields.
#[test]
fn pin_record_sizes() -> TestResult {
    let empty = ConversationBody::default().to_bytes()?;
    let record = |acting_agent| RoomPin {
        target: EntityId::now(),
        pinned_by: EntityId::now(),
        acting_agent,
        // Unix seconds in today's range encode in five bytes.
        pinned_at: 1_800_000_000,
    };
    let mut one = ConversationBody::default();
    one.pins.push(record(None));
    let one_bytes = one.to_bytes()?;
    assert_eq!(one_bytes.len() - empty.len(), 6 + 115);
    let mut two = one.clone();
    two.pins.push(record(Some(EntityId::now())));
    assert_eq!(two.to_bytes()?.len() - one_bytes.len(), 148);
    let mut managers = ConversationBody::default();
    managers.pin_policy = RoomPinPolicy::Managers;
    assert_eq!(managers.to_bytes()?.len() - empty.len(), 20);
    assert!(!String::from_utf8_lossy(&empty).contains("pin"));
    Ok(())
}

/// The rows of `section`, by entity id, in section order.
fn row_ids(section: &MemoriesSection) -> Vec<String> {
    section.rows.iter().map(|row| row.id.clone()).collect()
}

/// P2 (rule 4, test c): the leader, a member and the member's agent each see
/// the room's pins in its outline with their records. The MEMORIES include
/// puts each target in the PINNED tier with the same record and its text,
/// and the rendered row names the PERSON, the acting agent and the time.
#[test]
fn room_readers_see_admitted_pins_with_records() -> TestResult {
    let fx = open_fixture()?;
    let by_person = person(&fx, fx.member)
        .rooms_pins_pin(&pin(fx.room, fx.targets[0]))?
        .pin;
    let by_agent = agent(&fx, fx.member_agent)
        .rooms_pins_pin(&pin(fx.room, fx.targets[1]))?
        .pin;
    let records = vec![by_person.clone(), by_agent.clone()];
    assert_eq!(person(&fx, fx.leader).rooms_render(fx.room)?.pins, records);
    assert_eq!(person(&fx, fx.member).rooms_render(fx.room)?.pins, records);
    assert_eq!(
        agent(&fx, fx.member_agent).rooms_render(fx.room)?.pins,
        records
    );
    for memory in [person(&fx, fx.member), agent(&fx, fx.member_agent)] {
        let mut section = MemoriesSection::pins_only(None);
        assert_eq!(
            memory.include_room_pins(fx.room, &mut section, None)?,
            records
        );
        assert_eq!(section.rows.len(), 2);
        for record in &records {
            let row = section
                .rows
                .iter()
                .find(|row| row.id == record.target.to_hex())
                .ok_or("a PINNED row for each admitted pin")?;
            assert_eq!(row.tier, MemoryTier::Pinned);
            assert_eq!(row.room_pin.as_ref(), Some(record));
            assert!(
                row.snippet
                    .as_deref()
                    .is_some_and(|text| text.contains("owen")),
                "the row carries its target's text: {:?}",
                row.snippet
            );
        }
        let rendered: Vec<String> = assemble_memories_sections(&section)
            .map_err(|error| format!("{error:?}"))?
            .iter()
            .flat_map(|board| board.pinned_rows().to_vec())
            .collect();
        for record in &records {
            let byline = format!(
                "pinned_by={} acting_agent={} pinned_at={}",
                record.pinned_by.to_hex(),
                record
                    .acting_agent
                    .map_or_else(|| "none".to_owned(), |agent| agent.to_hex()),
                record.pinned_at
            );
            assert!(
                rendered.iter().any(|row| row.contains(&byline)),
                "{byline} in {rendered:?}"
            );
        }
    }
    Ok(())
}

/// P2 (rule 4): a PERSON the room does not seat sees no pin, and neither
/// does a member once it leaves: the outline and the MEMORIES include refuse
/// the room as unknown and add no row. The members who stay still see it.
#[test]
fn outsider_and_former_member_see_no_pins() -> TestResult {
    let fx = open_fixture()?;
    person(&fx, fx.leader).rooms_pins_pin(&pin(fx.room, fx.targets[0]))?;
    let mut section = MemoriesSection::pins_only(None);
    assert!(person(&fx, fx.outsider).rooms_render(fx.room).is_err());
    assert!(
        person(&fx, fx.outsider)
            .include_room_pins(fx.room, &mut section, None)
            .is_err()
    );
    assert!(section.rows.is_empty());
    assert_eq!(person(&fx, fx.member).rooms_render(fx.room)?.pins.len(), 1);
    let mut project = fx.project.clone();
    project.roster.retain(|seat| *seat != fx.member.to_hex());
    fx.vault
        .put_project(fx.project_id, &project, fx.vault.now_recorded_at())?;
    assert!(person(&fx, fx.member).rooms_render(fx.room).is_err());
    assert!(
        person(&fx, fx.member)
            .include_room_pins(fx.room, &mut section, None)
            .is_err()
    );
    assert!(section.rows.is_empty());
    assert_eq!(person(&fx, fx.leader).rooms_render(fx.room)?.pins.len(), 1);
    Ok(())
}

/// P2 (rule 4): a pin whose target the reader no longer reads (here, the
/// target is deleted) leaves no record, row, page count or cursor; the
/// stored list still holds it.
#[test]
fn withheld_target_leaves_no_record_or_count() -> TestResult {
    let fx = open_fixture()?;
    let kept = person(&fx, fx.leader)
        .rooms_pins_pin(&pin(fx.room, fx.targets[0]))?
        .pin;
    person(&fx, fx.leader).rooms_pins_pin(&pin(fx.room, fx.targets[1]))?;
    // The subject is the read after a delete, not who may delete: a plain
    // delete_entity of a room MESSAGE is refused without the room's
    // authority, so the test-support seam deletes it. Every delete signs as
    // this install.
    fx.vault
        .install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    assert!(
        fx.vault
            .delete_room_record_unchecked_for_test(&fx.targets[1], DeleteReason::UserDelete)?
            .existed
    );
    assert_eq!(stored_pins(&fx, fx.room)?.len(), 2);
    let member = person(&fx, fx.member);
    assert_eq!(member.rooms_render(fx.room)?.pins, vec![kept.clone()]);
    let page = member.rooms_render_page_hosted(fx.room, None, None)?;
    assert_eq!(page.pins_total, 1);
    assert_eq!(page.section.pins, vec![kept.clone()]);
    assert!(page.end);
    let mut section = MemoriesSection::pins_only(None);
    assert_eq!(
        member.include_room_pins(fx.room, &mut section, None)?,
        vec![kept]
    );
    assert_eq!(row_ids(&section), vec![fx.targets[0].to_hex()]);
    Ok(())
}

/// P2 (rule 4): an ordinary room shows its own pins, the home room its own;
/// neither shows the other's, in the outline or in MEMORIES.
#[test]
fn each_room_shows_only_its_own_pins() -> TestResult {
    let fx = open_fixture()?;
    let room = EntityId::now();
    fx.vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![fx.leader, fx.member],
            ..Default::default()
        },
        WriteActor::new(fx.owner, EdgeActorClass::Human),
        fx.vault.now_recorded_at(),
    )?;
    // The ordinary room is its own conversation: the home room's grants do
    // not reach it.
    grant_room_messages(&fx.vault, room, &[fx.leader, fx.member])?;
    let said = say_in_ordinary_room(&fx.vault, fx.leader, room)?;
    let in_ordinary = person(&fx, fx.member).rooms_pins_pin(&pin(room, said))?.pin;
    let in_home = person(&fx, fx.member)
        .rooms_pins_pin(&pin(fx.room, fx.targets[0]))?
        .pin;
    let member = person(&fx, fx.member);
    assert_eq!(member.rooms_render(room)?.pins, vec![in_ordinary]);
    assert_eq!(member.rooms_render(fx.room)?.pins, vec![in_home]);
    let mut section = MemoriesSection::pins_only(None);
    member.include_room_pins(room, &mut section, None)?;
    assert_eq!(row_ids(&section), vec![said.to_hex()]);
    let mut section = MemoriesSection::pins_only(None);
    member.include_room_pins(fx.room, &mut section, None)?;
    assert_eq!(row_ids(&section), vec![fx.targets[0].to_hex()]);
    Ok(())
}

/// P2: the outline pages its pins after the roster and the rules, by target
/// id, each pin once, with the count of pins the reader sees on every page
/// and no cap on how many.
#[test]
fn outline_pages_carry_each_pin_once() -> TestResult {
    const PINS: usize = 252;
    let fx = open_fixture()?;
    let leader = person(&fx, fx.leader);
    let mut pinned = Vec::with_capacity(PINS);
    for _ in 0..PINS {
        let target = speak_trunk(&fx.vault, fx.leader, fx.room)?;
        pinned.push(leader.rooms_pins_pin(&pin(fx.room, target))?.pin);
    }
    pinned.sort_by_key(|pin| pin.target);
    let member = person(&fx, fx.member);
    let mut seen = Vec::with_capacity(PINS);
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = member.rooms_render_page_hosted(fx.room, None, cursor.as_deref())?;
        assert_eq!(page.pins_total, u64::try_from(PINS)?);
        seen.extend(page.section.pins.iter().cloned());
        pages += 1;
        if page.end {
            assert!(page.next_cursor.is_none());
            break;
        }
        cursor = Some(
            page.next_cursor
                .ok_or("a page short of the end continues")?,
        );
        assert!(pages < 8, "the stream ends");
    }
    assert!(pages >= 2, "the pins run past the first page");
    assert_eq!(seen, pinned);
    Ok(())
}
