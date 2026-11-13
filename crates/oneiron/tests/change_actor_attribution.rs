//! Who made a change, on the reads the app shows changes from (FIX
//! [UI-GATE-PREVIEW] phase 3; GENUI-WIRE-GAPS section 4 item 2: "by eiri").
//! A `vault.receipts` page and a `vault.rooms.messages` page each carry one
//! `actors` table, keyed by the actor ref their rows name. Each entry agrees
//! with the reader's own `vault.people.list`: the person the actor speaks as,
//! with its handle, name and kind, or `unknown` when that list holds no one
//! for the actor. An agent is named as the agent it is, never as the person
//! it acts for.
//!
//! Fixture: an owned vault with its embedded owner, one PERSON (owen) whose
//! public contact the owner precleared, and one agent (yuki) with its own
//! model PERSON, an auto ceiling and a read grant. A project led by owen
//! seats yuki; both read the home room's messages under a grant. The owner
//! and yuki each write one claim about the owner, and owen speaks one trunk
//! turn.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test change_actor_attribution`.

use std::collections::{BTreeMap, BTreeSet};

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::context_board::{ActorAttribution, ActorAttributionKind, PersonRow};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    ClaimInput, Memory, PeopleListRequest, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{ProjectRecord, RoomMessagesRequest};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    owen: EntityId,
    yuki: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let owen = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &owen,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owen",
    )?;
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::public(owen, "owen@example.com", vault.now_recorded_at())?,
    )?;
    vault.preclear_contact_disclosure(&proof, "owen", &[contact], Scope::top())?;
    let yuki = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
        "agent_id": "yuki",
        "display_name": "yuki",
        "desc": "yuki",
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        &vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: yuki,
            definition,
        },
    )?;
    let view =
        policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".into(),
        actor_ref: Some(yuki.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owen, yuki] {
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
    let mut project = ProjectRecord::new(project_id, Some(root_project), root_project, owen)?;
    project.roster.push(yuki.to_hex());
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for principal in [owen, yuki] {
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
    Ok(Fixture {
        vault,
        owner,
        owen,
        yuki,
        room,
        _directory: directory,
    })
}

/// One claim by `memory`'s actor about the PERSON `subject`: a distinct
/// value of a set-cardinality predicate, so the write appends its own gate
/// decision.
fn write_claim(memory: &Memory<'_>, subject: EntityId, label: &str) -> TestResult {
    memory.claim_upsert(&ClaimInput {
        id: Some(EntityId::now().to_hex()),
        predicate: "decision.practical".to_owned(),
        subject_ref: subject.to_hex(),
        value: json!(format!("keep the {label} entry")),
        confidence: 0.9,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
        confidence_details: None,
    })?;
    Ok(())
}

/// `speaker`'s trunk turn in the home room `room`, one MESSAGE; its TURN id.
fn speak_trunk(vault: &Vault, speaker: EntityId, room: EntityId) -> TestResult<EntityId> {
    let turn = EntityId::now();
    let input = WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
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
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&input)?;
    Ok(turn)
}

/// Every person `memory`'s own `vault.people.list` reads, every page.
fn people_of(memory: &Memory<'_>) -> TestResult<Vec<PersonRow>> {
    let mut rows = Vec::new();
    for page in 0.. {
        let listed = memory.people_list(&PeopleListRequest {
            vault: None,
            page: Some(page),
        })?;
        rows.extend(listed.people);
        if listed.more == 0 {
            break;
        }
    }
    Ok(rows)
}

/// What the people list says of `actor`: the row of the PERSON it is, else
/// the row it speaks for as an actor, else no one.
fn listed_as(people: &[PersonRow], actor: &str) -> ActorAttribution {
    let Ok(actor) = EntityId::from_hex(actor) else {
        return ActorAttribution::unknown();
    };
    people
        .iter()
        .find(|row| row.person == actor)
        .or_else(|| people.iter().find(|row| row.actors.contains(&actor)))
        .map_or_else(ActorAttribution::unknown, |row| ActorAttribution {
            kind: row.kind.into(),
            person: Some(row.person.to_hex()),
            handle: Some(row.handle.clone()),
            name: Some(row.name.clone()),
        })
}

/// Each entry of `actors` is what `people` says of its actor, and `actors`
/// names exactly the `expected` refs.
fn agrees(
    actors: &BTreeMap<String, ActorAttribution>,
    expected: &BTreeSet<String>,
    people: &[PersonRow],
    read: &str,
) {
    assert_eq!(
        actors.keys().cloned().collect::<BTreeSet<_>>(),
        *expected,
        "{read}: one entry for each actor its rows name"
    );
    for (actor, named) in actors {
        assert_eq!(
            *named,
            listed_as(people, actor),
            "{read}: actor {actor} is named as the reader's people list names it"
        );
    }
}

#[test]
fn a_receipts_page_names_each_actor_as_the_readers_people_list_does() -> TestResult {
    let fx = open_fixture()?;
    let owner = fx.vault.memory(fx.owner, EdgeActorClass::Human);
    write_claim(&owner, fx.owner, "owner's")?;
    let yuki = fx.vault.memory(fx.yuki, EdgeActorClass::Agent);
    write_claim(&yuki, fx.owner, "agent's")?;
    let page = owner.receipts_page(100, &[], None)?;
    let refs: BTreeSet<String> = page
        .receipts
        .iter()
        .filter_map(|receipt| receipt.actor_ref.clone())
        .collect();
    assert!(
        refs.contains(&fx.owner.to_hex()) && refs.contains(&fx.yuki.to_hex()),
        "precondition: the owner's page holds the owner's and yuki's receipts: {refs:?}"
    );
    let people = people_of(&owner)?;
    agrees(&page.actors, &refs, &people, "the owner's receipts page");
    let by_owner = &page.actors[&fx.owner.to_hex()];
    assert_eq!(
        (by_owner.kind, by_owner.person.as_deref()),
        (
            ActorAttributionKind::Human,
            Some(fx.owner.to_hex().as_str())
        ),
        "the owner's own receipt is by the owner, a human"
    );
    let by_yuki = &page.actors[&fx.yuki.to_hex()];
    assert_eq!(
        (by_yuki.kind, by_yuki.name.as_deref()),
        (ActorAttributionKind::Agent, Some("yuki")),
        "yuki's receipt is by yuki, an agent, by its own name"
    );
    assert_ne!(
        by_yuki.person, by_owner.person,
        "an agent is named as itself, never as the owner it works for"
    );
    Ok(())
}

#[test]
fn a_room_page_names_each_turns_actor_as_the_readers_people_list_does() -> TestResult {
    let fx = open_fixture()?;
    speak_trunk(&fx.vault, fx.owen, fx.room)?;
    let owen = fx.vault.memory(fx.owen, EdgeActorClass::Human);
    let page = owen.rooms_messages_selected(&RoomMessagesRequest {
        room_ref: fx.room.to_hex(),
        after: None,
        limit: None,
        thread_ref: None,
    })?;
    let refs: BTreeSet<String> = page.rows.iter().map(|turn| turn.actor.clone()).collect();
    assert!(
        refs.contains(&fx.owen.to_hex()),
        "precondition: owen reads his own trunk turn: {refs:?}"
    );
    let people = people_of(&owen)?;
    agrees(&page.actors, &refs, &people, "owen's room page");
    assert!(
        page.actors[&fx.owen.to_hex()].kind != ActorAttributionKind::Agent,
        "owen's own turn is never named as an agent's"
    );
    Ok(())
}
