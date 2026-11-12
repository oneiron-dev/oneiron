//! An open offer card ages out with its thread in an ordinary room, through
//! the one row fold every room's cards take (OF-530, ARCH-0006a:233;
//! THREAD-TASK-EVERY-ROOM P2 removed the ordinary room's DAG fold). A card
//! on a thread whose last turn is older than the room's freshness reads as
//! aged out; a card on a fresh thread stays open; a card on a quiet thread
//! that holds an open bound TASK stays open, since the TASK keeps the thread
//! live.
//!
//! Fixture: owen, the vault's owner, hosts an ordinary group room; agent A
//! stands in it on the Ready join owen gave its offer card, and is the
//! bound TASK's assignee; agent B asks into each thread by a thread offer
//! card. Each thread is a native DAG turn on the trunk and owen's plain
//! reply on it, its root; a quiet thread's turns are dated 90 days back.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test room_offer_ageing`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft, OfferState, OffersRequest,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// The label this file's TASKs and intent keys carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/room_offer_ageing.rs";

/// How far back a quiet thread's turns are dated, in seconds.
const QUIET_AGE_SECS: u64 = 90 * 24 * 60 * 60;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owen: EntityId,
    agent_a: EntityId,
    agent_b: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }
}

/// An agent made through the agent-definition door, as the owner.
fn create_agent(vault: &Vault, owner: EntityId, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": name,
        "display_name": name,
        "desc": name,
        "version": "1",
        "ceiling": "auto",
    }))?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// A asks under its own Auto ceiling, and owen, A and B read the vault's
/// records: rows added to the default policy manifest, the shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId, agent_a: EntityId, agent_b: EntityId) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".into(),
        actor_ref: Some(agent_a.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owen, agent_a, agent_b] {
        rows.push(PolicyScopedGrantRow {
            // Bare census keys carry no actor class.
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
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// An ordinary group room owen creates, and so hosts, holding owen alone.
fn ordinary_room(vault: &Vault, owen: EntityId, title: &str) -> TestResult<EntityId> {
    let receipt = vault
        .memory(owen, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: serde_json::json!({
                "v": 1,
                "kind": "group",
                "member_ids": [owen.to_hex()],
                "title": title,
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// `agent`'s Ready join for the whole of `room`: its offer card, accepted by
/// owen, the room's host.
fn join_room(vault: &Vault, owen: EntityId, room: EntityId, agent: EntityId) -> TestResult {
    let card = vault
        .memory(agent, EdgeActorClass::Agent)
        .rooms_offer(&OfferDraft {
            room,
            branch: None,
            agent,
            what: "Work the room's thread tasks.".to_owned(),
            artifact_ref: Some("artifact:thread-tasks".to_owned()),
            spend_scope: None,
            until: None,
            intent_key: format!("{FIXTURE_PATH}:offer:{}:{}", room.to_hex(), agent.to_hex()),
        })?;
    let accepted = vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_offer_answer(&OfferAnswerRequest {
            offer_id: card.offer_id.clone(),
            action: OfferAnswer::Join,
            intent_key: format!("{FIXTURE_PATH}:answer:{}:{}", room.to_hex(), agent.to_hex()),
        })?;
    let join = accepted.join.ok_or("the host's answer carries no join")?;
    if join.decision.state != JoinDecision::Ready {
        return Err(format!("fixture: the join is {:?}, not Ready", join.decision.state).into());
    }
    Ok(())
}

/// `principal` reads `room`'s MESSAGEs under an active grant.
fn grant_messages(vault: &Vault, room: EntityId, principal: EntityId) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: principal,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent_a = create_agent(&vault, owen, "yuki")?;
    let agent_b = create_agent(&vault, owen, "yuki-two")?;
    grant_reads(&vault, owen, agent_a, agent_b)?;
    let room = ordinary_room(&vault, owen, "ordinary room")?;
    for principal in [agent_a, agent_b] {
        grant_messages(&vault, room, principal)?;
    }
    join_room(&vault, owen, room, agent_a)?;
    Ok(Fixture {
        vault,
        owen,
        agent_a,
        agent_b,
        room,
        _directory: directory,
    })
}

/// owen's plain TURN in the room for the DAG's append doors, dated
/// `age_secs` back.
fn plain_turn(fixture: &Fixture, age_secs: u64) -> TestResult<AppendRecord> {
    let now = fixture.vault.now_recorded_at();
    let at = now.saturating_sub(age_secs);
    Ok(AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: None,
        quote: None,
        address: AddressMode::Broadcast,
        recipients: vec![],
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange { start: at, end: at },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
        thread_audience: None,
    })
}

/// A thread dated `age_secs` back: owen's native DAG turn on the trunk and
/// owen's plain reply on it. Returns the thread's root, the reply.
fn thread(fixture: &Fixture, age_secs: u64) -> TestResult<EntityId> {
    let mut input = plain_turn(fixture, age_secs)?;
    input.parent = fixture.vault.head(&fixture.room)?;
    input.advance = true;
    let anchor = fixture.vault.append_dag_record(&fixture.owen(), &input)?.id;
    let reply = plain_turn(fixture, age_secs)?;
    Ok(fixture
        .vault
        .reply_in_thread(&fixture.owen(), anchor, &reply)?
        .id)
}

/// B's offer card on the thread `root`.
fn thread_card(fixture: &Fixture, root: EntityId) -> TestResult {
    fixture
        .vault
        .memory(fixture.agent_b, EdgeActorClass::Agent)
        .rooms_offer(&OfferDraft {
            room: fixture.room,
            branch: Some(root),
            agent: fixture.agent_b,
            what: "Help with this thread.".to_owned(),
            artifact_ref: None,
            spend_scope: None,
            until: None,
            intent_key: format!("{FIXTURE_PATH}:thread-offer:{}", root.to_hex()),
        })?;
    Ok(())
}

/// The state owen reads for B's card on the thread `root`.
fn card_state(fixture: &Fixture, root: EntityId) -> TestResult<OfferState> {
    let page = fixture.owen().rooms_offers(&OffersRequest {
        room: fixture.room,
        branch: Some(root),
        after: None,
        limit: None,
    })?;
    let card = page
        .rows
        .into_iter()
        .find(|card| card.agent == fixture.agent_b && card.branch == Some(root))
        .ok_or("B's thread card is not listed")?;
    Ok(card.state)
}

/// A card on a thread quiet for 90 days reads as aged out; a card on a
/// fresh thread stays open.
#[test]
fn ordinary_room_thread_card_ages_out_with_its_quiet_thread() -> TestResult {
    let fixture = open_fixture()?;
    let quiet = thread(&fixture, QUIET_AGE_SECS)?;
    let fresh = thread(&fixture, 0)?;
    thread_card(&fixture, quiet)?;
    thread_card(&fixture, fresh)?;
    assert_eq!(card_state(&fixture, quiet)?, OfferState::AgedOut);
    assert!(
        matches!(card_state(&fixture, fresh)?, OfferState::Open { .. }),
        "the fresh thread's card stays open"
    );
    Ok(())
}

/// A quiet thread with an open TASK bound to it is live, so its card stays
/// open: the fold reads the binding from the thread's room row.
#[test]
fn ordinary_room_thread_card_stays_open_while_a_bound_task_is_open() -> TestResult {
    let fixture = open_fixture()?;
    let kept = thread(&fixture, QUIET_AGE_SECS)?;
    let spec = TaskCreateSpec::new(
        rmpv::Value::Nil,
        Some(FIXTURE_PATH.into()),
        Some(fixture.owen),
        Some(fixture.vault.now_recorded_at()),
    )
    .with_assignee(TaskAssignee::AgentDef {
        agent_def_ref: fixture.agent_a,
    });
    let task = fixture
        .owen()
        .tasks_create(&spec)?
        .task_ref
        .ok_or("TASK creation did not take effect")?;
    fixture
        .vault
        .bind_room_thread_task(fixture.owen, fixture.room, kept, task)?;
    thread_card(&fixture, kept)?;
    assert!(
        matches!(card_state(&fixture, kept)?, OfferState::Open { .. }),
        "the bound open TASK keeps the thread, and its card, live"
    );
    Ok(())
}
