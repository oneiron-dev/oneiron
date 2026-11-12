//! OPUS-T0-F gate pins, PR 5 (Engine NOTE 13 Nov 02:19): green pins for six
//! write gates of OPUS-TRIAGECENSUS's census (census/TRIAGE.md, class
//! GAP-PASSES: real callers pass these gates today, and no running test
//! drove them from a door). Each test drives the door a real caller uses,
//! with that caller's inputs, through the gate, and reads the write back. A
//! pin that goes red is a live refusal of a real caller (GAP-BROKEN).
//!
//! Each test name starts with the census id, so `-- g230_` runs one gate's
//! pins.
//!
//! - G230 `require_append_references_in_txn`, the Retry path: an agent's
//!   regenerated reply to the owner's Retry lands beside the old one. The
//!   agent's reply joined the agent's own open sitting, so the Retry names
//!   that SESSION; two pins vary the bands the agent's read row grants. The
//!   Retry's TURN answers owen's turn, so owen's turn addresses the agent
//!   (ARCH-0006a: an agent speaks only when it is addressed there). The
//!   Retry's assistant TURN is checked as generated under the agent, so the
//!   owner gives the agent an actor-bound generated source-trust permit, as
//!   `put_dag_test_policy` does; without it the TURN pends on
//!   `gate.pending.source_trust` after this gate passes (FIX-LIST
//!   DAG-ENGINE-APPEND-PERSON-PENDS, the Retry half, open).
//! - G134 `write_model_manifest_in_txn`: a manifest pinned with a passing
//!   teacher probe, then written again under the saved approval.
//! - G142 `validate_context_spec`: a dispatch's context spec resolves.
//! - G55 `ModelManifest::bind_request`: the dreamer's extraction call binds
//!   the offline teacher role.
//! - G187 `declare_embedding_space_in_txn`: the host seeds a fresh space,
//!   and the owner declares it again at its width.
//! - G241 `CatalogSeed::from_installed_pack_in_txn`: the first-party model
//!   catalog pack installs and its rows are read.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test gate_pins_turn_retry_model_routing`.

use std::collections::{BTreeMap, BTreeSet};

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::context_projection::{
    ChatProjection, ContextResolutionRequest, ContextSpec, MemoryProjection, resolve_context_spec,
};
use oneiron::conversation::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt, TurnActionRequest};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::embed::{EmbeddingSpace, InputKind};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::manifest::{
    MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
};
use oneiron::llm::registry::ModelWireFormat;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifest, PolicyManifestPut, PolicyManifestRead,
    PolicyScopedGrantRow, PolicySource, SensitivityBand, SourceTrust, SourceTrustRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use oneiron::skill_hub::pack_catalog::{
    PackFitPolicy, PackFitVerdict, PackInstallDisposition, PackPermissions, PackSource,
    PackSourceAdapter,
};
use oneiron::skill_hub::{
    HubFile, HubPackage, HubPin, HubRef, SkillHubAdapter, SkillHubKind, default_skill_hub_id,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, EdgeActorClass, EdgeKind, EntityId, LlmRequest, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, TimeRange, Vault, VaultConfig,
    WriteActor,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The label this file's offer cards carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/gate_pins_turn_retry_model_routing.rs";

// ── G230: the Retry of an agent's reply ─────────────────────────────────

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

/// The agent asks under its own Auto ceiling, its generated words are
/// trusted at the unstamped claim band, and owen and the agent read the
/// vault's records: rows added to the default policy manifest, the shipped
/// rows kept.
fn grant_reads(vault: &Vault, owen: EntityId, agent: EntityId) -> TestResult {
    edit_default_manifest(vault, owen, |manifest| {
        manifest.actor_ceilings.push(ActorCeiling {
            actor_class: "agent".into(),
            actor_ref: Some(agent.to_hex()),
            ceiling: PolicyCeiling::Auto,
        });
        // The permit `put_dag_test_policy` installs: band 2 is the
        // unstamped claim band the Retry TURN's check reads.
        let permit = SourceTrustRow {
            actor_ref: Some(agent.to_hex()),
            max_auto_sensitivity: Some(SensitivityBand::Number(2)),
            auto: None,
            auto_checker: None,
            receipted: true,
            warned: true,
        };
        // The shipped generated entry is a row list; the agent's row joins it.
        let rows = match manifest.source_trust.remove(&PolicySource::Generated) {
            Some(SourceTrust::Rows(mut rows)) => {
                rows.push(permit);
                rows
            }
            Some(SourceTrust::Row(shipped)) => vec![shipped, permit],
            _ => vec![permit],
        };
        manifest
            .source_trust
            .insert(PolicySource::Generated, SourceTrust::Rows(rows));
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

/// What the original exchange left: the owner's TURN, the agent's reply
/// TURN and MESSAGE, and the agent's sitting the reply joined.
struct Exchange {
    user_turn: EntityId,
    reply_turn: EntityId,
    reply_message: EntityId,
    sitting: EntityId,
}

/// owen speaks on the room's trunk, addressing the agent, then the agent, in
/// its own open sitting, answers through the witness stream, as the chat
/// host streams a reply.
fn exchange(fixture: &RoomFixture) -> TestResult<Exchange> {
    let vault = &fixture.vault;
    // The agent's sitting, open before its reply: the witness joins a
    // stream reply's TURN to the open sitting of (agent, this machine).
    let key = vault.local_session_key(fixture.agent)?;
    vault.mint_session(key, vault.now_recorded_at())?;
    let sitting = vault
        .open_session(key)?
        .ok_or("fixture: the agent's sitting is not open")?
        .session;

    // owen's TURN, appended on the room's DAG and addressed to the agent:
    // an agent speaks only when it is addressed on the turn it answers
    // (ARCH-0006a), and the Retry's TURN answers this one. A turn witnessed
    // in an ordinary room addresses no one. As
    // tests/room_thread_task_parity.rs appends a plain TURN.
    let owen = vault.memory(fixture.owen, EdgeActorClass::Human);
    let now = vault.now_recorded_at();
    let user_turn = vault
        .append_dag_record(
            &owen,
            &AppendRecord {
                conversation: fixture.room,
                parent: vault.head(&fixture.room)?,
                reply_to: None,
                quote: None,
                address: AddressMode::Direct,
                recipients: vec![fixture.agent],
                advance: true,
                kind: ENTITY_TYPE_TURN,
                containing_turn: None,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen asks"}))?,
                text: vec![],
                session: None,
                actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
                thread_audience: None,
            },
        )
        .map_err(|error| format!("fixture: owen's addressed TURN: {error:?}"))?
        .id;
    // His words, witnessed into that TURN: a Retry answers the newest turn
    // before the reply that holds a User line.
    owen.rooms_speak(&WitnessTurn {
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
    })
    .map_err(|error| format!("fixture: owen's MESSAGE in his TURN: {error:?}"))?;
    let row = owen
        .rooms_messages(fixture.room)?
        .into_iter()
        .find(|row| row.turn_id == user_turn.to_hex())
        .ok_or("fixture: owen's TURN keeps no room row")?;
    if !row.addressed_agents.contains(&fixture.agent.to_hex()) {
        return Err(format!("fixture: owen's TURN does not address the agent: {row:?}").into());
    }

    let agent = vault.memory(fixture.agent, EdgeActorClass::Agent);
    let reply_turn = EntityId::now();
    let handle = agent
        .begin_message_stream(
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
        )
        .map_err(|error| format!("fixture: the agent's reply opens: {error:?}"))?;
    agent.append_to_stream(handle, "yuki answers")?;
    let reply = agent
        .finalize_stream(handle)
        .map_err(|error| format!("fixture: the agent's reply lands: {error:?}"))?;
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
            lease_owner: "gate-pins-turn-actions".to_owned(),
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
/// conversation, one empty Companion MESSAGE, then its words. Returns the
/// new MESSAGE.
fn answer_retry(fixture: &RoomFixture, action: &TurnActionAttempt) -> TestResult<EntityId> {
    let vault = &fixture.vault;
    let agent = vault.memory(fixture.agent, EdgeActorClass::Agent);
    let handle = agent
        .begin_message_regeneration(
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
        )
        .map_err(|error| format!("the Retry's answer opens: {error:?}"))?;
    agent.append_to_stream(handle, "yuki answers again")?;
    let receipt = agent
        .finalize_stream(handle)
        .map_err(|error| format!("the Retry's answer lands: {error:?}"))?;
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
    let message = answer_retry(fixture, action)?;
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

#[test]
fn g230_a_retry_by_an_agent_that_reads_every_band_lands() -> TestResult {
    let fixture = open_room()?;
    let exchange = exchange(&fixture)?;
    let action = queue_retry(&fixture, &exchange)?;
    assert!(agent_reads(&fixture, exchange.sitting)?);
    answer_retry_lands(&fixture, &exchange, &action)
}

#[test]
fn g230_a_retry_by_an_agent_whose_grant_bands_include_session_lands() -> TestResult {
    let fixture = open_room()?;
    let exchange = exchange(&fixture)?;
    let action = queue_retry(&fixture, &exchange)?;
    narrow_agent_reads(
        &fixture.vault,
        fixture.owen,
        fixture.agent,
        &[
            ENTITY_TYPE_CONVERSATION,
            ENTITY_TYPE_TURN,
            ENTITY_TYPE_MESSAGE,
            ENTITY_TYPE_SESSION,
        ],
    )?;
    assert!(agent_reads(&fixture, exchange.sitting)?);
    answer_retry_lands(&fixture, &exchange, &action)
}

// ── model routing: G134, G55 ────────────────────────────────────────────

const PIN_TIER: &str = "gate-pins";

/// A v2 manifest binding every role, each to its own model; the extraction
/// encoder on the Oneironer slot and every other role on the LLM slot, all
/// slots routed on device.
fn manifest() -> TestResult<ModelManifest> {
    let mut roles = BTreeMap::new();
    for role in MODEL_ROLES {
        roles.insert(
            role,
            ModelBinding {
                model: ModelId::new(format!("gate-pins/{role:?}@r1"))?,
                slot: if role == ModelRole::ExtractionEncoder {
                    ModelSlot::Oneironer
                } else {
                    ModelSlot::Llm
                },
                tier: ModelTierRef(PIN_TIER.to_owned()),
                route_models: BTreeMap::new(),
                disposition: None,
                reads_audio: false,
            },
        );
    }
    Ok(ModelManifest {
        version: 2,
        roles,
        routes: BTreeMap::from([
            (ModelSlot::Llm, ModelLocality::OnDevice),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]),
        verdict: None,
        seat_policy: None,
    })
}

/// Pins `manifest` with a passing teacher-probe approval, as the bench
/// publishes one.
fn pin_manifest(vault: &Vault, manifest: &ModelManifest) -> TestResult {
    let policy = vault.teacher_probe_policy(None)?;
    let approval = TeacherProbeApproval::for_scored_checkpoint(manifest, &policy, 1_000_000)?;
    vault.set_model_manifest_with_teacher_approval(manifest, &approval)?;
    Ok(())
}

fn open_device() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    Ok((directory, vault))
}

#[test]
fn g134_a_teacher_approved_manifest_is_pinned_and_rewritten() -> TestResult {
    let (_directory, vault) = open_device()?;
    let manifest = manifest()?;
    pin_manifest(&vault, &manifest)?;
    assert_eq!(vault.model_manifest()?, Some(manifest.clone()));
    // A later write keeps the saved teacher approval.
    let mut rewritten = manifest;
    rewritten
        .roles
        .get_mut(&ModelRole::GenerativeReasoner)
        .ok_or("no reasoner row")?
        .model = ModelId::new("gate-pins/reasoner-next@r2")?;
    vault.set_model_manifest(&rewritten)?;
    assert_eq!(vault.model_manifest()?, Some(rewritten));
    Ok(())
}

#[test]
fn g55_the_dreamers_extraction_call_binds_the_offline_teacher() -> TestResult {
    let (_directory, vault) = open_device()?;
    let manifest = manifest()?;
    pin_manifest(&vault, &manifest)?;
    let teacher = manifest
        .binding(ModelRole::ExtractionTeacher)?
        .model
        .clone();
    // The dreamer's extraction request (dreamer_consolidation/follower_attempt
    // /request.rs), served by the host's supervised native transport.
    let request = LlmRequest {
        model: teacher.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("global".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![],
        tools: vec![],
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    };
    let host = HostInferenceContext {
        binding: HostInferenceBinding::SupervisedNativeLocal {
            model: teacher.clone(),
            paid: false,
        },
        extraction_egress: None,
    };
    let authorized = vault.authorize_model_role(ModelRole::ExtractionTeacher, request, &host)?;
    assert_eq!(authorized.binding().model(), &teacher);
    assert_eq!(authorized.request().model, teacher);
    assert_eq!(
        authorized.request().envelope.locality,
        ModelLocality::OnDevice
    );
    Ok(())
}

// ── G142: a dispatch's context spec ─────────────────────────────────────

#[test]
fn g142_a_dispatch_context_spec_resolves() -> TestResult {
    let (_directory, vault) = open_device()?;
    // The shape `agents.spawn` and code mode's `self.context` send: named
    // layers, scoped memory, recent chat and a briefing.
    let projection = resolve_context_spec(
        &vault,
        ContextResolutionRequest {
            spec: ContextSpec {
                layers: vec!["persona".to_owned()],
                memory: MemoryProjection::Scoped {
                    domains: vec!["preference".to_owned()],
                    limit: 8,
                },
                chat: ChatProjection::Recent { last_n: 4 },
                briefing: Some("Summarise the week.".to_owned()),
                annotation: None,
            },
            parent: None,
            context_from: Vec::new(),
            world_scope: None,
        },
    )?;
    assert_eq!(projection.layers, ["persona"]);
    assert_eq!(projection.briefing.as_deref(), Some("Summarise the week."));
    assert!(projection.chat_sections.len() <= 4);
    assert!(projection.memory_sections.len() <= 8);
    Ok(())
}

// ── G187: embedding spaces ──────────────────────────────────────────────

fn text_space(id: &str) -> EmbeddingSpace {
    EmbeddingSpace {
        id: id.to_owned(),
        dimensions: 4,
        accepts: BTreeSet::from([InputKind::Text]),
        query_towers: BTreeSet::from([InputKind::Text]),
        evidence: None,
    }
}

#[test]
fn g187_a_host_seeded_space_is_declared_again_by_the_owner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Vault::open_owned(directory.path(), config)?;
    // The host's `[embedding]` config seeds a fresh space at startup.
    let space = text_space("gate-pins-embedder@r1@own_server");
    vault.seed_embedding_space(space.clone())?;
    let held = vault.embedding_spaces()?;
    assert!(
        held.contains(&space),
        "the seeded space is not held: {held:?}"
    );
    // The owner declares it again at its width, widening what it accepts.
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let mut widened = space.clone();
    widened.accepts.insert(InputKind::Image);
    vault.declare_embedding_space(&owner, widened.clone())?;
    let held = vault.embedding_spaces()?;
    let row = held
        .iter()
        .find(|row| row.id == space.id)
        .ok_or("the declared space is gone")?;
    assert_eq!(row.dimensions, 4);
    assert!(row.accepts.contains(&InputKind::Image));
    Ok(())
}

// ── G241: the installed model catalog ───────────────────────────────────

/// The pinned Git transport's successful fetch of the model-pack fixture
/// tree (as llm/registry/tests.rs models it).
struct CatalogAdapter {
    hub: EntityId,
    endpoint: String,
    source: PackSource,
}

impl SkillHubAdapter for CatalogAdapter {
    fn hub_id(&self) -> EntityId {
        self.hub
    }
    fn kind(&self) -> SkillHubKind {
        SkillHubKind::Git
    }
    fn endpoint(&self) -> Option<&str> {
        Some(&self.endpoint)
    }
    fn fetch_package(&self, _: &HubRef) -> oneiron::Result<HubPackage> {
        Err(oneiron::Error::EntityNotFound)
    }
}

impl PackSourceAdapter for CatalogAdapter {
    fn fetch_pack_source(&self, _: &HubRef) -> oneiron::Result<PackSource> {
        Ok(self.source.clone())
    }
}

/// A data-only pack fits.
struct DataOnlyFit;

impl PackFitPolicy for DataOnlyFit {
    fn evaluate(
        &self,
        _: &PackSource,
        permissions: &PackPermissions,
    ) -> oneiron::Result<PackFitVerdict> {
        assert!(permissions.grants.is_empty());
        assert!(permissions.wakes.is_empty());
        assert!(permissions.bundled_skills.is_empty());
        Ok(PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: false,
        })
    }
}

#[test]
fn g241_the_first_party_model_catalog_installs() -> TestResult {
    let (_directory, vault) = open_device()?;
    let source = PackSource::from_files(vec![
        HubFile::new(
            "PACK.md",
            include_bytes!("fixtures/model-pack/PACK.md").to_vec(),
        ),
        HubFile::new(
            "knowledge/catalog.json",
            include_bytes!("fixtures/model-pack/knowledge/catalog.json").to_vec(),
        ),
    ])?;
    let at = TimeRange { start: 1, end: 1 };
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(
        owner,
        "principal:catalog-owner",
        true,
        GateDecisionId::now(),
    )?;
    let hub = default_skill_hub_id()?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:model-catalog", hub)?;
    // The first-party hub's model-catalog subtree, pinned to the fetched bytes.
    let reference = HubRef::new(
        hub,
        "packs/model-catalog",
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    let adapter = CatalogAdapter {
        hub,
        endpoint: vault.skill_hub_record(&hub)?.endpoint,
        source: source.clone(),
    };
    let (source_id, pinned) =
        vault.fetch_pack_from_adapter(&adapter, &reference, &publisher, at, 1)?;
    let ask = vault.prepare_pack_install(source_id, &pinned, &publisher, &DataOnlyFit)?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        return Err("the data-only model pack did not install".into());
    };
    assert!(receipt.skills.is_empty());
    let entries = vault.model_catalog_entries(ModelWireFormat::OpenaiCompat)?;
    assert!(!entries.is_empty(), "the installed catalog serves no model");
    assert_eq!(vault.model_registry_rows()?.len(), entries.len());
    // Catalog data never binds a role.
    assert!(vault.model_manifest()?.is_none());
    Ok(())
}
