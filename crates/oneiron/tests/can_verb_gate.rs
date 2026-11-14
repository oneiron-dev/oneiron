//! `can({verb})`: one verb's gate for one actor (FIX [UI-GATE-PREVIEW]
//! phases 1 and 2; GENUI-WIRE-GAPS section 4 item 1). For each verb with a
//! preview (the room pin doors, the pin policy, the room invitation, a
//! room's speech and an ask's answer) the
//! gate agrees with the call itself, made right after by the same actor with
//! the same input: `auto` lands, and `person` and `refused` are refused with
//! the one reason the gate names. A verb whose row asks a person's proof
//! answers `person` for an agent; any other verb answers `unchecked`. Only
//! the vault's owner reads another actor's gate, and only an agent's.
//!
//! Fixture: room_pins.rs's. A project whose home room seats the leader, a
//! plain member and four agents: the leader's pen, the member's pen, the pen
//! of an outsider (a PERSON the room does not seat) and an agent that is no
//! one's pen. The leader speaks three trunk turns; their MESSAGEs are the pin
//! targets, and their TURNs an ask's question and answer. Each PERSON holds
//! one public contact the owner precleared, and every seated non-owner holds
//! a grant over the room's messages.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test can_verb_gate`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation::{ConversationBody, ConversationKind, RoomPinPolicy, RoomRole};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    CanAnswer, CanVerbAnswer, CanVerbGate, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory,
    MemoryError, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskOption, TaskAskOptionId, TaskAskQuestion,
    TaskAskSpec, TaskAskTarget, TaskAskWord,
};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentDefinitionSpec, CanRequest, TaskAnswerRequest,
};
use oneiron::workspace_roster::{JoinRequest, ProjectRecord, RoomPinPolicySet, RoomPinRequest};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PIN: &str = "vault.rooms.pins.pin";
const UNPIN: &str = "vault.rooms.pins.unpin";
const POLICY_SET: &str = "vault.rooms.pins.policy.set";
const INVITE: &str = "vault.rooms.invite";
const SPEAK: &str = "vault.rooms.speak";
const ANSWER: &str = "tasks.answer";

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
    room: EntityId,
    /// The leader's three trunk TURNs.
    turns: [EntityId; 3],
    /// Their MESSAGEs, in the same order.
    targets: [EntityId; 3],
    _directory: tempfile::TempDir,
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

/// A trunk turn in the home room `room`, one MESSAGE: the turn, and its TURN
/// and MESSAGE ids.
fn trunk_turn(vault: &Vault, room: EntityId) -> (WitnessTurn, EntityId, EntityId) {
    let turn = EntityId::now();
    let message = EntityId::now();
    let input = WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "owen".into(),
            parts: None,
            metadata: Some(Value::Object(serde_json::Map::new())),
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: vault.now_recorded_at(),
        assertions: Default::default(),
    };
    (input, turn, message)
}

/// The leader's trunk turn in the home room `room`; returns its TURN and
/// MESSAGE ids.
fn speak_trunk(
    vault: &Vault,
    leader: EntityId,
    room: EntityId,
) -> TestResult<(EntityId, EntityId)> {
    let (input, turn, message) = trunk_turn(vault, room);
    vault
        .memory(leader, EdgeActorClass::Human)
        .rooms_speak(&input)?;
    Ok((turn, message))
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
        let definition: AgentDefinitionSpec = serde_json::from_value(json!({
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
    let spoken = [
        speak_trunk(&vault, leader, room)?,
        speak_trunk(&vault, leader, room)?,
        speak_trunk(&vault, leader, room)?,
    ];
    let turns = spoken.map(|(turn, _)| turn);
    let targets = spoken.map(|(_, message)| message);
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
        room,
        turns,
        targets,
        _directory: directory,
    })
}

fn person(fx: &Fixture, actor: EntityId) -> Memory<'_> {
    fx.vault.memory(actor, EdgeActorClass::Human)
}

fn agent(fx: &Fixture, actor: EntityId) -> Memory<'_> {
    fx.vault.memory(actor, EdgeActorClass::Agent)
}

/// `memory`'s `can({verb: {name: verb, params, actor}})`, as the wire
/// carries it.
fn ask_gate(
    memory: &Memory<'_>,
    verb: &str,
    params: &Value,
    actor: Option<EntityId>,
) -> Result<CanVerbAnswer, Box<dyn std::error::Error>> {
    let mut call = json!({ "name": verb, "params": params });
    if let Some(actor) = actor {
        call["actor"] = json!(actor);
    }
    let request: CanRequest = serde_json::from_value(json!({ "verb": call }))?;
    match memory.can(&request) {
        Ok(CanAnswer::Verb(answer)) => Ok(answer),
        Ok(other) => Err(format!("{verb}: not a verb gate: {other:?}").into()),
        Err(error) => Err(Box::new(error)),
    }
}

/// `memory`'s own gate for `verb`, asserted to be `expected` and to name
/// `actor` of `kind`.
fn gate_of(
    fx: &Fixture,
    memory: &Memory<'_>,
    (actor, kind): (EntityId, EdgeActorClass),
    verb: &str,
    params: &Value,
    expected: CanVerbGate,
) -> TestResult<CanVerbAnswer> {
    let answer = ask_gate(memory, verb, params, None)?;
    assert_eq!(answer.gate, expected, "{answer:?}");
    assert_eq!(answer.verb, verb);
    assert_eq!((answer.actor_ref, answer.actor_kind), (actor, kind));
    assert!(answer.checked_at > 0 && answer.checked_at <= fx.vault.now_recorded_at());
    Ok(answer)
}

/// The call made right after agrees with its gate: `auto` lands; `person`
/// and `refused` are refused with the gate's one reason.
fn agrees<T: std::fmt::Debug>(answer: &CanVerbAnswer, call: Result<T, MemoryError>) -> TestResult {
    match (answer.gate, call) {
        (CanVerbGate::Auto, Ok(_)) => Ok(()),
        (CanVerbGate::Person | CanVerbGate::Refused, Err(error)) => {
            assert_eq!(answer.reasons, vec![error.message], "{answer:?}");
            Ok(())
        }
        (gate, call) => Err(format!(
            "{} for {}: the gate answered {gate:?} {:?} but the call answered {call:?}",
            answer.verb,
            answer.actor_ref.to_hex(),
            answer.reasons
        )
        .into()),
    }
}

fn pin_params(room: EntityId, target: EntityId) -> Value {
    json!({ "room": room, "target": target })
}

/// Pin then unpin `target` as `memory`, each call checked against the gate
/// read just before it.
fn pin_and_unpin(
    fx: &Fixture,
    memory: &Memory<'_>,
    who: (EntityId, EdgeActorClass),
    target: EntityId,
    expected: CanVerbGate,
) -> TestResult {
    let params = pin_params(fx.room, target);
    let request = RoomPinRequest {
        room: fx.room,
        target,
    };
    let pinned = gate_of(fx, memory, who, PIN, &params, expected)?;
    agrees(&pinned, memory.rooms_pins_pin(&request))?;
    let unpinned = gate_of(fx, memory, who, UNPIN, &params, expected)?;
    agrees(&unpinned, memory.rooms_pins_unpin(&request))
}

/// The pin doors' gate agrees with the doors, for members, pen agents, a
/// non-member, a non-member's pen and an agent that is no one's pen, under
/// both pin policies.
#[test]
fn the_pin_gate_agrees_with_the_pin_doors() -> TestResult {
    let fx = open_fixture()?;
    let [first, second, third] = fx.targets;
    let human = EdgeActorClass::Human;
    let machine = EdgeActorClass::Agent;
    pin_and_unpin(
        &fx,
        &person(&fx, fx.member),
        (fx.member, human),
        first,
        CanVerbGate::Auto,
    )?;
    pin_and_unpin(
        &fx,
        &agent(&fx, fx.member_agent),
        (fx.member_agent, machine),
        second,
        CanVerbGate::Auto,
    )?;
    pin_and_unpin(
        &fx,
        &person(&fx, fx.outsider),
        (fx.outsider, human),
        third,
        CanVerbGate::Refused,
    )?;
    pin_and_unpin(
        &fx,
        &agent(&fx, fx.outsider_agent),
        (fx.outsider_agent, machine),
        third,
        CanVerbGate::Refused,
    )?;
    let penless = ask_gate(
        &agent(&fx, fx.unanchored_agent),
        PIN,
        &pin_params(fx.room, first),
        None,
    )?;
    assert!(
        penless.reasons.iter().any(|reason| reason.contains("pen")),
        "the refusal names the pen rule: {penless:?}"
    );
    pin_and_unpin(
        &fx,
        &agent(&fx, fx.unanchored_agent),
        (fx.unanchored_agent, machine),
        first,
        CanVerbGate::Refused,
    )?;
    // Managers only: the member and its pen are refused, the leader's pen
    // pins as the leader may.
    person(&fx, fx.leader).rooms_pins_policy_set(&RoomPinPolicySet {
        room: fx.room,
        policy: RoomPinPolicy::Managers,
        check_in_ref: None,
    })?;
    pin_and_unpin(
        &fx,
        &person(&fx, fx.member),
        (fx.member, human),
        first,
        CanVerbGate::Refused,
    )?;
    pin_and_unpin(
        &fx,
        &agent(&fx, fx.member_agent),
        (fx.member_agent, machine),
        second,
        CanVerbGate::Refused,
    )?;
    pin_and_unpin(
        &fx,
        &agent(&fx, fx.leader_agent),
        (fx.leader_agent, machine),
        third,
        CanVerbGate::Auto,
    )
}

/// The owner reads an agent's gate, which is the agent's own; nobody else
/// names another actor, and the owner names only an agent.
#[test]
fn only_the_owner_reads_another_actors_gate() -> TestResult {
    let fx = open_fixture()?;
    let owner = person(&fx, fx.owner);
    let params = pin_params(fx.room, fx.targets[0]);
    for named in [fx.member_agent, fx.unanchored_agent] {
        let read = ask_gate(&owner, PIN, &params, Some(named))?;
        let own = ask_gate(&agent(&fx, named), PIN, &params, None)?;
        assert_eq!(
            (read.actor_ref, read.actor_kind),
            (named, EdgeActorClass::Agent)
        );
        assert_eq!((read.gate, &read.reasons), (own.gate, &own.reasons));
    }
    assert_eq!(
        ask_gate(&owner, PIN, &params, Some(fx.member_agent))?.gate,
        CanVerbGate::Auto
    );
    assert_eq!(
        ask_gate(&owner, PIN, &params, Some(fx.unanchored_agent))?.gate,
        CanVerbGate::Refused
    );
    for (asker, named) in [
        (agent(&fx, fx.member_agent), fx.leader_agent),
        (person(&fx, fx.member), fx.member_agent),
        (person(&fx, fx.leader), fx.leader_agent),
    ] {
        let refusal = ask_gate(&asker, PIN, &params, Some(named))
            .expect_err("only the owner names another actor");
        let refusal = refusal
            .downcast_ref::<MemoryError>()
            .ok_or("a memory refusal")?;
        assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN, "{refusal:?}");
    }
    let refusal = ask_gate(&owner, PIN, &params, Some(fx.leader))
        .expect_err("a PERSON is none of the vault's agents");
    let refusal = refusal
        .downcast_ref::<MemoryError>()
        .ok_or("a memory refusal")?;
    assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST, "{refusal:?}");
    // Naming oneself is reading one's own gate.
    let own = ask_gate(
        &agent(&fx, fx.member_agent),
        PIN,
        &params,
        Some(fx.member_agent),
    )?;
    assert_eq!(own.gate, CanVerbGate::Auto);
    Ok(())
}

/// The pin policy is a person's act: an agent's gate says `person`, a
/// person who does not run the room is refused, the leader's call lands.
#[test]
fn the_pin_policy_gate_is_a_persons() -> TestResult {
    let fx = open_fixture()?;
    let params = json!({ "room": fx.room, "policy": "managers" });
    let input: RoomPinPolicySet = serde_json::from_value(params.clone())?;
    let human = EdgeActorClass::Human;
    for (memory, who, expected) in [
        (
            agent(&fx, fx.leader_agent),
            (fx.leader_agent, EdgeActorClass::Agent),
            CanVerbGate::Person,
        ),
        (
            person(&fx, fx.member),
            (fx.member, human),
            CanVerbGate::Refused,
        ),
        (
            person(&fx, fx.leader),
            (fx.leader, human),
            CanVerbGate::Auto,
        ),
    ] {
        let answer = gate_of(&fx, &memory, who, POLICY_SET, &params, expected)?;
        agrees(&answer, memory.rooms_pins_policy_set(&input))?;
    }
    assert_eq!(
        ask_gate(
            &person(&fx, fx.owner),
            POLICY_SET,
            &params,
            Some(fx.member_agent)
        )?
        .gate,
        CanVerbGate::Person
    );
    Ok(())
}

/// A room invitation is the owner's act: an agent's gate says `person`, a
/// room admin who is not the vault's owner is refused, the owner's call
/// lands.
#[test]
fn the_invite_gate_is_the_owners() -> TestResult {
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
    let params = json!({
        "room": room,
        "subject": { "kind": "person", "id": fx.outsider },
        "paid": false,
        "intent_key": "invite-owen-two",
    });
    let input: JoinRequest = serde_json::from_value(params.clone())?;
    let human = EdgeActorClass::Human;
    for (memory, who, expected) in [
        (
            agent(&fx, fx.leader_agent),
            (fx.leader_agent, EdgeActorClass::Agent),
            CanVerbGate::Person,
        ),
        (
            person(&fx, fx.leader),
            (fx.leader, human),
            CanVerbGate::Refused,
        ),
        (person(&fx, fx.owner), (fx.owner, human), CanVerbGate::Auto),
    ] {
        let answer = gate_of(&fx, &memory, who, INVITE, &params, expected)?;
        agrees(&answer, memory.rooms_invite(&input))?;
    }
    Ok(())
}

/// A verb whose row asks a person's proof answers `person` for an agent;
/// with no preview it answers `unchecked` for a person, and so does a verb
/// with neither. A name outside the catalog, or params that are not the
/// verb's input, are refused; an input naming two requests matches none.
#[test]
fn row_rule_unchecked_and_malformed_requests() -> TestResult {
    let fx = open_fixture()?;
    let params = json!({});
    let removal = ask_gate(
        &agent(&fx, fx.member_agent),
        "vault.members.remove",
        &params,
        None,
    )?;
    assert_eq!(removal.gate, CanVerbGate::Person, "{removal:?}");
    assert_eq!(removal.reasons.len(), 1);
    assert_eq!(
        ask_gate(
            &person(&fx, fx.member),
            "vault.members.remove",
            &params,
            None
        )?
        .gate,
        CanVerbGate::Unchecked
    );
    let wait = ask_gate(&agent(&fx, fx.member_agent), "tasks.wait", &params, None)?;
    assert_eq!((wait.gate, wait.reasons.len()), (CanVerbGate::Unchecked, 0));
    for (verb, params) in [
        ("vault.rooms.members.remove", json!({})),
        (PIN, json!({ "room": fx.room })),
        (SPEAK, json!({})),
        (ANSWER, json!({ "handle": {} })),
    ] {
        let refusal = ask_gate(&person(&fx, fx.member), verb, &params, None)
            .expect_err("refused before any gate");
        let refusal = refusal
            .downcast_ref::<MemoryError>()
            .ok_or("a memory refusal")?;
        assert_eq!(refusal.code, MEMORY_CODE_BAD_REQUEST, "{verb}: {refusal:?}");
    }
    assert!(
        serde_json::from_value::<CanRequest>(json!({
            "verb": { "name": PIN, "params": pin_params(fx.room, fx.targets[0]) },
            "effect": {},
        }))
        .is_err()
    );
    Ok(())
}

/// The speech gate agrees with the room's speak door, read before the turn's
/// witness: the seated leader's trunk turn lands; a person the room does not
/// seat, and an agent the vault does not know, are refused with the door's
/// own reason.
#[test]
fn the_speech_gate_agrees_with_the_speak_door() -> TestResult {
    let fx = open_fixture()?;
    let stranger = EntityId::now();
    for (memory, who, expected) in [
        (
            person(&fx, fx.leader),
            (fx.leader, EdgeActorClass::Human),
            CanVerbGate::Auto,
        ),
        (
            person(&fx, fx.outsider),
            (fx.outsider, EdgeActorClass::Human),
            CanVerbGate::Refused,
        ),
        (
            agent(&fx, stranger),
            (stranger, EdgeActorClass::Agent),
            CanVerbGate::Refused,
        ),
    ] {
        let (input, _, _) = trunk_turn(&fx.vault, fx.room);
        let params = serde_json::to_value(&input)?;
        let answer = gate_of(&fx, &memory, who, SPEAK, &params, expected)?;
        agrees(&answer, memory.rooms_speak(&input))?;
    }
    Ok(())
}

/// The answer gate agrees with the answer door, read through every check a
/// word meets before it is recorded. An agent asks the vault's owner about
/// the leader's turn: the asking agent and a person the ask does not ask are
/// refused with the door's own reason, the owner's read of the agent's gate
/// says the same, and the owner's own word lands.
#[test]
fn the_answer_gate_agrees_with_the_answer_door() -> TestResult {
    let fx = open_fixture()?;
    let [question_turn, answer_turn, _] = fx.turns;
    let mut question = TaskAskQuestion::new(ConsultPayloadRef::Turn(question_turn));
    let option = TaskAskOptionId::new("owen")?;
    question
        .options
        .insert(option.clone(), TaskAskOption::new("owen"));
    let spec = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(BTreeSet::from([fx.owner]))),
        question,
        None,
        TaskAskDefault::AskMe,
    );
    let asker = agent(&fx, fx.unanchored_agent);
    let handle = asker.tasks_ask(&spec)?.handle;
    let mut word = TaskAskWord::new(answer_turn);
    word.option = Some(option);
    word.provenance_refs = BTreeSet::from([ConsultPayloadRef::Turn(answer_turn)]);
    let params = serde_json::to_value(TaskAnswerRequest {
        handle,
        word: word.clone(),
    })?;
    let owner = person(&fx, fx.owner);
    let named = ask_gate(&owner, ANSWER, &params, Some(fx.unanchored_agent))?;
    assert_eq!(
        (named.gate, named.actor_ref),
        (CanVerbGate::Refused, fx.unanchored_agent),
        "{named:?}"
    );
    let own = gate_of(
        &fx,
        &asker,
        (fx.unanchored_agent, EdgeActorClass::Agent),
        ANSWER,
        &params,
        CanVerbGate::Refused,
    )?;
    assert_eq!(own.reasons, named.reasons);
    agrees(&own, asker.tasks_answer(&handle, &word))?;
    let outsider = person(&fx, fx.outsider);
    let unasked = gate_of(
        &fx,
        &outsider,
        (fx.outsider, EdgeActorClass::Human),
        ANSWER,
        &params,
        CanVerbGate::Refused,
    )?;
    agrees(&unasked, outsider.tasks_answer(&handle, &word))?;
    let answered = gate_of(
        &fx,
        &owner,
        (fx.owner, EdgeActorClass::Human),
        ANSWER,
        &params,
        CanVerbGate::Auto,
    )?;
    agrees(&answered, owner.tasks_answer(&handle, &word))
}
