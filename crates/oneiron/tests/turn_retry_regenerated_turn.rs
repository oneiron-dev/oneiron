//! A Retry's regenerated reply lands where the reply it answers again
//! landed (Engine TASK 13 Nov 04:50, OPUS-TRIAGECENSUS).
//!
//! An ordinary group room keeps the conversation DAG, so a Retry appends its
//! assistant TURN beside the replaced reply's TURN, in the stream's terminal
//! write. Two refusals stopped an agent's Retry there while its first reply
//! landed:
//!
//! - FIX [DAG-ENGINE-APPEND-PERSON-PENDS], the Retry half: the TURN was
//!   checked as a generated claim, so on a default vault it pended on
//!   `gate.pending.source_trust`. The witness lands the first reply's TURN
//!   with no claim check and checks its MESSAGE as transcript recording; the
//!   Retry's TURN now meets that same transcript gate.
//! - FIX [G230-RETRY-OMITTED-SESSION-BAND]: the TURN joins the sitting the
//!   replaced reply joined, and the reference check refused it when the
//!   owner had narrowed the agent's reads to the conversation's own kinds.
//!   The sitting is the replaced reply's own placement, read by the engine
//!   from that reply's TURN; the Retry keeps it whatever the agent's read
//!   bands. The agent's reply sits in its own sitting when its stream binds
//!   none, and in the caller's when the chat host binds the caller's, as
//!   `/v1/ai/chat` does.
//!
//! Controls: the owner's actor ceiling naming the agent still holds a Retry,
//! and a public append that names a sitting the agent cannot read is still
//! refused at `/session`.
//!
//! The fixture follows OPUS-T0-F's G230 gate pins
//! (tests/gate_pins_turn_retry_model_routing.rs at 0c16632c569), without
//! their actor-bound generated source-trust row. Public paths only.
//! `cargo test --locked -p oneiron --all-features --test turn_retry_regenerated_turn`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::conversation::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt, TurnActionRequest};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_INVENTED_REFERENCE, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifest, PolicyManifestPut, PolicyManifestRead,
    PolicyScopedGrantRow, policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use oneiron::session_lifecycle::SessionKey;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The label this file's offer cards carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/turn_retry_regenerated_turn.rs";

/// The bands the owner narrows the agent's reads to: the conversation's own
/// kinds, without SESSION.
const CONVERSATION_BANDS: [u8; 3] = [
    ENTITY_TYPE_CONVERSATION,
    ENTITY_TYPE_TURN,
    ENTITY_TYPE_MESSAGE,
];

/// An ordinary group room owen, the vault's owner, hosts; agent yuki stands
/// in it on a Ready join, reads the vault's records under a `core:read` row
/// of the default policy manifest, and reads the room's MESSAGEs under a
/// grant. As tests/room_thread_task_parity.rs builds its ordinary room.
struct RoomFixture {
    vault: Vault,
    owen: EntityId,
    agent: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
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

/// The default policy manifest with `edit` applied, put back by the owner.
fn edit_default_manifest(
    vault: &Vault,
    owen: EntityId,
    edit: impl FnOnce(&mut PolicyManifest),
) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.policy_manifests.put")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    edit(&mut manifest);
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

/// The agent asks under its own Auto ceiling, and owen and the agent read
/// the vault's records: rows added to the default policy manifest, the
/// shipped rows kept. No source-trust row is added: the agent's generated
/// words are trusted only as the shipped manifest trusts them.
fn grant_reads(vault: &Vault, owen: EntityId, agent: EntityId) -> TestResult {
    edit_default_manifest(vault, owen, |manifest| {
        manifest.actor_ceilings.push(ActorCeiling {
            actor_class: "agent".into(),
            actor_ref: Some(agent.to_hex()),
            ceiling: PolicyCeiling::Auto,
        });
        let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
        for actor in [owen, agent] {
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
    })
}

/// The owner sets the agent's own actor ceiling row to `ceiling`.
fn set_agent_ceiling(
    vault: &Vault,
    owen: EntityId,
    agent: EntityId,
    ceiling: PolicyCeiling,
) -> TestResult {
    let agent_ref = agent.to_hex();
    edit_default_manifest(vault, owen, |manifest| {
        for row in &mut manifest.actor_ceilings {
            if row.actor_ref.as_deref() == Some(agent_ref.as_str()) {
                row.ceiling = ceiling;
            }
        }
    })
}

/// The owner narrows the agent's `core:read` row to `bands`, every other
/// axis kept.
fn narrow_agent_reads(vault: &Vault, owen: EntityId, agent: EntityId, bands: &[u8]) -> TestResult {
    let agent_ref = agent.to_hex();
    edit_default_manifest(vault, owen, |manifest| {
        for row in manifest.scoped_grants.iter_mut().flatten() {
            if row.actor_ref.as_deref() == Some(agent_ref.as_str()) && row.effector == "core:read" {
                row.scope.bands = ScopeAxis::Some(bands.iter().copied().collect());
            }
        }
    })
}

/// An ordinary group room owen creates, and so hosts, holding owen alone.
fn ordinary_room(vault: &Vault, owen: EntityId) -> TestResult<EntityId> {
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
                "title": "gate pins room",
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// The agent's Ready join for the whole of `room`: its offer card, accepted
/// by owen, the room's host.
fn join_room(vault: &Vault, owen: EntityId, room: EntityId, agent: EntityId) -> TestResult {
    let card = vault
        .memory(agent, EdgeActorClass::Agent)
        .rooms_offer(&OfferDraft {
            room,
            branch: None,
            agent,
            what: "Answer the room.".to_owned(),
            artifact_ref: Some("artifact:gate-pins".to_owned()),
            spend_scope: None,
            until: None,
            intent_key: format!("{FIXTURE_PATH}:offer:{}", agent.to_hex()),
        })?;
    let accepted = vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_offer_answer(&OfferAnswerRequest {
            offer_id: card.offer_id.clone(),
            action: OfferAnswer::Join,
            intent_key: format!("{FIXTURE_PATH}:answer:{}", agent.to_hex()),
        })?;
    let join = accepted.join.ok_or("the host's answer carries no join")?;
    if join.decision.state != JoinDecision::Ready {
        return Err(format!("fixture: the join is {:?}, not Ready", join.decision.state).into());
    }
    Ok(())
}

/// The agent reads the room's MESSAGEs under an active grant.
fn grant_messages(vault: &Vault, room: EntityId, agent: EntityId) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: agent,
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

fn open_room() -> TestResult<RoomFixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent = create_agent(&vault, owen, "yuki")?;
    grant_reads(&vault, owen, agent)?;
    let room = ordinary_room(&vault, owen)?;
    grant_messages(&vault, room, agent)?;
    join_room(&vault, owen, room, agent)?;
    Ok(RoomFixture {
        vault,
        owen,
        agent,
        room,
        _directory: directory,
    })
}

/// Whose sitting the agent's reply joins.
#[derive(Clone, Copy)]
enum ReplySitting {
    /// The agent's stream binds no sitting, so the witness joins its reply
    /// to the agent's own open sitting, as an in-process host's stream does.
    AgentsOwn,
    /// The agent's stream is bound to owen's sitting, and the agent to it
    /// as its answerer, as `/v1/ai/chat` binds the caller's sitting.
    CallersBoundByTheChatHost,
}

/// What the original exchange left: the owner's TURN, the agent's reply
/// TURN and MESSAGE, and the sitting the reply joined.
struct Exchange {
    user_turn: EntityId,
    reply_turn: EntityId,
    reply_message: EntityId,
    sitting: EntityId,
}

/// The open sitting of `actor` on this machine, minted for the exchange.
fn open_sitting(vault: &Vault, actor: EntityId) -> TestResult<(SessionKey, EntityId)> {
    let key = vault.local_session_key(actor)?;
    vault.mint_session(key, vault.now_recorded_at())?;
    let sitting = vault
        .open_session(key)?
        .ok_or("fixture: the sitting is not open")?
        .session;
    Ok((key, sitting))
}

/// owen speaks on the room's trunk, then the agent answers through the
/// witness stream, its reply joining the sitting `placement` names.
fn exchange(fixture: &RoomFixture, placement: ReplySitting) -> TestResult<Exchange> {
    let vault = &fixture.vault;
    let agent = vault.memory(fixture.agent, EdgeActorClass::Agent);
    let (agent, sitting) = match placement {
        ReplySitting::AgentsOwn => (agent, open_sitting(vault, fixture.agent)?.1),
        ReplySitting::CallersBoundByTheChatHost => {
            let (key, sitting) = open_sitting(vault, fixture.owen)?;
            vault
                .bind_session_answer(key, fixture.agent)?
                .ok_or("fixture: owen's sitting took no answerer")?;
            (agent.with_session(key), sitting)
        }
    };

    let user_turn = EntityId::now();
    vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: fixture.room.to_hex(),
            turn_ref: Some(user_turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen asks".into(),
                parts: None,
                metadata: Some(serde_json::json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;

    let reply_turn = EntityId::now();
    let handle = agent.begin_message_stream(
        &WitnessTurn {
            conversation_ref: fixture.room.to_hex(),
            turn_ref: Some(reply_turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::Companion,
                message_type: "text".into(),
                content: String::new(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        },
        None,
    )?;
    agent.append_to_stream(handle, "yuki answers")?;
    let reply = agent.finalize_stream(handle)?;
    Ok(Exchange {
        user_turn,
        reply_turn,
        reply_message: reply.message_id,
        sitting,
    })
}

/// The owner's Retry of the reply, claimed as the host's turn-action
/// worker claims it.
fn queue_retry(fixture: &RoomFixture, exchange: &Exchange) -> TestResult<TurnActionAttempt> {
    let vault = &fixture.vault;
    let receipt = vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .conversations_turn_retry(&TurnActionRequest {
            turn_id: exchange.reply_turn.to_hex(),
        })?;
    assert_eq!(receipt.turn_id, exchange.reply_turn.to_hex());
    let claimed = AttemptQueue::new(vault).claim_kind(
        TURN_ACTION_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "turn-retry-regenerated-turn".to_owned(),
            now: vault.now_recorded_at(),
        },
    )?;
    let ClaimOutcome::Claimed(attempt) = claimed else {
        return Err(format!("fixture: the Retry is not claimable: {claimed:?}").into());
    };
    let action = TurnActionAttempt::decode(&attempt)?;
    // The Retry answers owen's turn again, in place of the agent's reply.
    assert_eq!(action.user_turn, exchange.user_turn);
    assert_eq!(action.assistant_turn, exchange.reply_turn);
    assert_eq!(action.message, exchange.reply_message);
    Ok(action)
}

/// The agent answers the Retry as the chat host does: a fresh stream on the
/// conversation, one empty Companion MESSAGE, then its words. `before_end`
/// runs after the words, before the stream's terminal write. Returns the
/// new MESSAGE.
fn answer_retry(
    fixture: &RoomFixture,
    action: &TurnActionAttempt,
    before_end: impl FnOnce() -> TestResult,
) -> TestResult<EntityId> {
    let vault = &fixture.vault;
    let agent = vault.memory(fixture.agent, EdgeActorClass::Agent);
    let handle = agent.begin_message_regeneration(
        &WitnessTurn {
            conversation_ref: action.conversation.to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::Companion,
                message_type: "text".into(),
                content: String::new(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        },
        action,
        None,
    )?;
    agent.append_to_stream(handle, "yuki answers again")?;
    before_end()?;
    let receipt = agent.finalize_stream(handle)?;
    Ok(receipt.message_id)
}

/// The agent answers the Retry, and the regenerated MESSAGE lands: it
/// points at the one it regenerates, and the room's HEAD stays where the
/// Retry found it (a Retry's sibling never advances it).
fn answer_retry_lands(
    fixture: &RoomFixture,
    exchange: &Exchange,
    action: &TurnActionAttempt,
) -> TestResult {
    let vault = &fixture.vault;
    let head = vault.head(&fixture.room)?;
    let message = answer_retry(fixture, action, || Ok(()))?;
    assert_ne!(message, exchange.reply_message);
    assert_eq!(vault.get_entity_type(&message)?, Some(ENTITY_TYPE_MESSAGE));
    assert!(
        vault.edges_out(&message)?.iter().any(
            |edge| edge.kind == EdgeKind::Regenerates && edge.target == exchange.reply_message
        ),
        "the new MESSAGE carries no Regenerates edge to the old one"
    );
    assert_eq!(vault.head(&fixture.room)?, head);
    Ok(())
}

/// Whether the agent's lane reads `id`.
fn agent_reads(fixture: &RoomFixture, id: EntityId) -> TestResult<bool> {
    Ok(fixture
        .vault
        .memory(fixture.agent, EdgeActorClass::Agent)
        .get_entity(&id.to_hex())?
        .value
        .is_some())
}

/// The room, the exchange, and the owner's Retry claimed; then the owner
/// narrows the agent's reads to the conversation's own kinds, so the agent
/// no longer reads the sitting its reply joined.
fn narrowed_retry(
    placement: ReplySitting,
) -> TestResult<(RoomFixture, Exchange, TurnActionAttempt)> {
    let fixture = open_room()?;
    let exchange = exchange(&fixture, placement)?;
    let action = queue_retry(&fixture, &exchange)?;
    narrow_agent_reads(
        &fixture.vault,
        fixture.owen,
        fixture.agent,
        &CONVERSATION_BANDS,
    )?;
    if agent_reads(&fixture, exchange.sitting)? {
        return Err("fixture: the narrowed agent still reads the reply's sitting".into());
    }
    Ok((fixture, exchange, action))
}

/// Red on main: the Retry's TURN pended on `gate.pending.source_trust`,
/// checked as a generated claim, while the reply it answers again landed.
#[test]
fn an_agents_retry_on_a_default_vault_lands_beside_its_reply() -> TestResult {
    let fixture = open_room()?;
    let exchange = exchange(&fixture, ReplySitting::AgentsOwn)?;
    let action = queue_retry(&fixture, &exchange)?;
    assert!(agent_reads(&fixture, exchange.sitting)?);
    answer_retry_lands(&fixture, &exchange, &action)
}

/// Red on main: "regeneration reference not found", the reply's own sitting
/// read against the agent's narrowed bands.
#[test]
fn an_agents_retry_lands_when_its_reads_omit_its_own_sitting() -> TestResult {
    let (fixture, exchange, action) = narrowed_retry(ReplySitting::AgentsOwn)?;
    answer_retry_lands(&fixture, &exchange, &action)
}

/// Red on main, as above: the chat host's reply sits in owen's sitting.
#[test]
fn an_agents_retry_lands_when_its_reply_sat_in_the_callers_sitting() -> TestResult {
    let (fixture, exchange, action) = narrowed_retry(ReplySitting::CallersBoundByTheChatHost)?;
    answer_retry_lands(&fixture, &exchange, &action)
}

/// Control: once the owner sets the agent's own ceiling row to Proposed,
/// the Retry's terminal write is held by the gate, as the agent's first
/// reply would be.
#[test]
fn an_agents_retry_is_held_once_the_owner_sets_its_ceiling_proposed() -> TestResult {
    let fixture = open_room()?;
    let exchange = exchange(&fixture, ReplySitting::AgentsOwn)?;
    let action = queue_retry(&fixture, &exchange)?;
    let held = answer_retry(&fixture, &action, || {
        set_agent_ceiling(
            &fixture.vault,
            fixture.owen,
            fixture.agent,
            PolicyCeiling::Proposed,
        )
    });
    let Err(error) = held else {
        return Err("the Retry landed past the owner's Proposed ceiling".into());
    };
    let error = format!("{error:?}");
    assert!(
        error.contains("gate write rejected"),
        "the Retry was refused, but not by the gate: {error}"
    );
    Ok(())
}

/// Control: a sitting the agent cannot read stays refused when the agent
/// names it itself, through the public append door.
#[test]
fn an_agents_append_naming_a_sitting_it_cannot_read_is_refused() -> TestResult {
    let (fixture, exchange, _) = narrowed_retry(ReplySitting::CallersBoundByTheChatHost)?;
    let vault = &fixture.vault;
    let now = vault.now_recorded_at();
    let input = AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: None,
        quote: None,
        address: AddressMode::Broadcast,
        recipients: Vec::new(),
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({ "speaker": "assistant" }))?,
        text: Vec::new(),
        session: Some(exchange.sitting),
        actor: WriteActor::new(fixture.agent, EdgeActorClass::Agent),
        thread_audience: None,
    };
    let writer = vault.memory(fixture.agent, EdgeActorClass::Agent);
    let Err(error) = vault.append_dag_record(&writer, &input) else {
        return Err("the agent appended a TURN naming a sitting it cannot read".into());
    };
    assert_eq!(error.code, MEMORY_CODE_INVENTED_REFERENCE, "{error:?}");
    assert!(error.message.contains("`/session`"), "{error:?}");
    Ok(())
}
