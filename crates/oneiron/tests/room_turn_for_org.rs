//! A bound house's room turns read "<agent>, for <org>" (HOUSE-BIND = A,
//! ARCH-0063 #house-bind, ARCH-0067 #people-house-link; FIX row
//! SPEAKER-BYLINE-FOR-ORG; Engine RULING L3-18 = A, 13 Nov 20:49).
//!
//! `vault.rooms.messages` answers `for_org`, by turn id, and
//! `vault.rooms.trunk` answers `for_org` for its one turn: the org the
//! turn's speaker ran as its house at the turn's `at`, read from the house
//! link receipts on each read. Nothing is stored on the turn, so an unbind
//! never changes how a turn written before it reads, and a turn written
//! after the unbind reads no org. A speaker that is no house (the owner)
//! has no entry.
//!
//! The fixture joins two shipped ones: the house bind of
//! tests/house_bind_interval.rs (the seeded `sys.default` agent is the
//! house, on an injected clock) and the ordinary group room of
//! tests/turn_retry_regenerated_turn.rs, where that agent answers the
//! owner's addressed turn through the witness stream. The replies are read
//! as JSON, the shape the verbs answer.
//!
//! `cargo test --locked -p oneiron --all-features --test room_turn_for_org`.
// The fixture binds the host owner through oneiron::test_support.
#![cfg(feature = "test-support")]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::HostSlipIssuer;
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{FederationGrantRole, Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_ORG, ENTITY_TYPE_TURN};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::workspace_roster::{
    JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft, RoomMessagesRequest,
    WorkCompanionPolicy, WorkspaceRosterPreset,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The label this file's offer cards carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/room_turn_for_org.rs";

const WORKSPACE: &str = "room-turn-for-org-workspace";

/// The org the house runs.
const ORG: [u8; 16] = [0xB3; 16];

/// A vault on an injected clock whose seeded `sys.default` agent is bound
/// as the house of a workspace that runs [`ORG`], and stands in an
/// ordinary group room its owner hosts.
struct HouseRoom {
    vault: Vault,
    clock: Arc<ManualClock>,
    start: u64,
    owner: EntityId,
    house: EntityId,
    room: EntityId,
    owner_proof: oneiron::consent::AuthenticatedOwner,
    issuer: HostSlipIssuer,
    _directory: tempfile::TempDir,
}

/// The owner puts the default policy manifest back with the house's Auto
/// ceiling and a `core:read` row for the owner and the house, the shipped
/// rows kept.
fn grant_reads(vault: &Vault, owner: EntityId, house: EntityId) -> TestResult {
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.policy_manifests.put")?;
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
        actor_ref: Some(house.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owner, house] {
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

/// An ordinary group room the owner creates, and so hosts, holding the
/// owner alone.
fn ordinary_room(vault: &Vault, owner: EntityId) -> TestResult<EntityId> {
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: serde_json::json!({
                "v": 1,
                "kind": "group",
                "member_ids": [owner.to_hex()],
                "title": "house byline room",
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// The house's Ready join for the whole of `room`, accepted by the owner,
/// and its read of the room's MESSAGEs under an active grant.
fn join_room(vault: &Vault, owner: EntityId, room: EntityId, house: EntityId) -> TestResult {
    let card = vault
        .memory(house, EdgeActorClass::Agent)
        .rooms_offer(&OfferDraft {
            room,
            branch: None,
            agent: house,
            what: "Answer the room.".to_owned(),
            artifact_ref: Some("artifact:house-byline".to_owned()),
            spend_scope: None,
            until: None,
            intent_key: format!("{FIXTURE_PATH}:offer:{}", house.to_hex()),
        })?;
    let accepted = vault
        .memory(owner, EdgeActorClass::Human)
        .rooms_offer_answer(&OfferAnswerRequest {
            offer_id: card.offer_id.clone(),
            action: OfferAnswer::Join,
            intent_key: format!("{FIXTURE_PATH}:answer:{}", house.to_hex()),
        })?;
    let join = accepted.join.ok_or("the host's answer carries no join")?;
    if join.decision.state != JoinDecision::Ready {
        return Err(format!("fixture: the join is {:?}, not Ready", join.decision.state).into());
    }
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: house,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

fn house_room() -> TestResult<HouseRoom> {
    let start = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let clock = ManualClock::new(start);
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), config)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    {
        let signer = vault.owner_project_signer(&issuer)?;
        vault.sign_owner_project(&owner_proof, &signer, vault.root_project()?)?;
    }
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("sys.default is seeded on open")?;
    vault.put_entity(
        &EntityId::from_bytes(ORG)?,
        ENTITY_TYPE_ORG,
        TimeRange { start: 1, end: 1 },
        1,
        b"room turn for org",
    )?;
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: 43,
        org_ref: EntityId::from_bytes(ORG)?,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault.establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &owner_proof)?;
    grant_reads(&vault, owner, house)?;
    let room = ordinary_room(&vault, owner)?;
    join_room(&vault, owner, room, house)?;
    // The house's own sitting, which its witness replies join.
    let key = vault.local_session_key(house)?;
    vault.mint_session(key, vault.now_recorded_at())?;
    let _sitting = vault
        .open_session(key)?
        .ok_or("fixture: the house's sitting is not open")?;
    Ok(HouseRoom {
        vault,
        clock,
        start,
        owner,
        house,
        room,
        owner_proof,
        issuer,
        _directory: directory,
    })
}

/// The owner's turn on the room's DAG, addressed to the house (an agent
/// speaks only when addressed on the turn it answers, ARCH-0006a), with his
/// words as a DAG MESSAGE in it; then the house's reply through the witness
/// stream. Returns the owner's TURN and the house's reply TURN.
fn exchange(fixture: &HouseRoom, words: &str) -> TestResult<(EntityId, EntityId)> {
    let vault = &fixture.vault;
    let owner = vault.memory(fixture.owner, EdgeActorClass::Human);
    let now = vault.now_recorded_at();
    let user_turn = vault
        .append_dag_record(
            &owner,
            &AppendRecord {
                conversation: fixture.room,
                parent: vault.head(&fixture.room)?,
                reply_to: None,
                quote: None,
                address: AddressMode::Direct,
                recipients: vec![fixture.house],
                advance: true,
                kind: ENTITY_TYPE_TURN,
                containing_turn: None,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: rmp_serde::to_vec_named(&serde_json::json!({ "txt": words }))?,
                text: Vec::new(),
                session: None,
                actor: WriteActor::new(fixture.owner, EdgeActorClass::Human),
                thread_audience: None,
            },
        )
        .map_err(|error| format!("fixture: the owner's addressed TURN: {error:?}"))?
        .id;
    vault
        .append_dag_record(
            &owner,
            &AppendRecord {
                conversation: fixture.room,
                parent: None,
                reply_to: None,
                quote: None,
                address: AddressMode::Broadcast,
                recipients: Vec::new(),
                advance: false,
                kind: ENTITY_TYPE_MESSAGE,
                containing_turn: Some(user_turn),
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                body: rmp_serde::to_vec_named(&serde_json::json!({
                    "author": "user",
                    "type": "text",
                    "content": words,
                    "is_visible": true,
                    "order": 0,
                }))?,
                text: Vec::new(),
                session: None,
                actor: WriteActor::new(fixture.owner, EdgeActorClass::Human),
                thread_audience: None,
            },
        )
        .map_err(|error| format!("fixture: the owner's MESSAGE in his TURN: {error:?}"))?;

    let house = vault.memory(fixture.house, EdgeActorClass::Agent);
    let reply_turn = EntityId::now();
    let handle = house
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
        .map_err(|error| format!("fixture: the house's reply stream: {error:?}"))?;
    house.append_to_stream(handle, "the house answers")?;
    house
        .finalize_stream(handle)
        .map_err(|error| format!("fixture: the house's reply: {error:?}"))?;
    Ok((user_turn, reply_turn))
}

/// The room's first page, read by the owner, as `vault.rooms.messages`
/// answers it.
fn messages_page(fixture: &HouseRoom) -> TestResult<serde_json::Value> {
    let page = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .rooms_messages_selected(&RoomMessagesRequest {
            room_ref: fixture.room.to_hex(),
            after: None,
            limit: None,
            thread_ref: None,
        })?;
    Ok(serde_json::to_value(&page)?)
}

/// The org the page's `for_org` names for `turn`, if any.
fn page_for_org(page: &serde_json::Value, turn: EntityId) -> Option<String> {
    page.get("for_org")
        .and_then(|map| map.get(turn.to_hex()))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// What the scenario left: the turns written inside the bind and after its
/// unbind.
struct Scenario {
    fixture: HouseRoom,
    owner_turn: EntityId,
    reply_in_bind: EntityId,
    reply_after_unbind: EntityId,
}

/// The house is bound (at `start`), answers once (at `start + 60`), is
/// unbound (at `start + 600`) and answers again (at `start + 1200`).
fn bind_answer_unbind_answer() -> TestResult<Scenario> {
    let fixture = house_room()?;
    let vault = &fixture.vault;
    let signer = vault.owner_project_signer(&fixture.issuer)?;
    vault.bind_workspace_house_leader(
        WORKSPACE,
        FederationGrantRole::Member,
        &fixture.owner_proof,
        &signer,
    )?;
    fixture.clock.set(fixture.start + 60);
    let (owner_turn, reply_in_bind) = exchange(&fixture, "what does the garden need")?;
    fixture.clock.set(fixture.start + 600);
    if !vault.unbind_house_leader(&fixture.owner_proof, &signer)? {
        return Err("fixture: the unbind found no bound house".into());
    }
    fixture.clock.set(fixture.start + 1_200);
    let (_, reply_after_unbind) = exchange(&fixture, "and now")?;
    drop(signer);
    let page = messages_page(&fixture)?;
    let rows = page["rows"]
        .as_array()
        .ok_or("fixture: the page has no rows")?;
    for reply in [reply_in_bind, reply_after_unbind] {
        let row = rows
            .iter()
            .find(|row| row["turn_id"] == reply.to_hex())
            .ok_or_else(|| {
                format!(
                    "fixture: the house's reply {} has no room row",
                    reply.to_hex()
                )
            })?;
        if row["actor"] != fixture.house.to_hex() {
            return Err(format!("fixture: the reply's row names another speaker: {row}").into());
        }
    }
    Ok(Scenario {
        fixture,
        owner_turn,
        reply_in_bind,
        reply_after_unbind,
    })
}

#[test]
fn room_messages_name_the_org_a_house_ran_when_it_spoke() -> TestResult {
    let scenario = bind_answer_unbind_answer()?;
    let page = messages_page(&scenario.fixture)?;
    let org = EntityId::from_bytes(ORG)?.to_hex();
    assert_eq!(
        page_for_org(&page, scenario.reply_in_bind),
        Some(org),
        "a turn the house wrote inside its bind reads for its org, after the unbind too: {page}",
    );
    assert_eq!(
        page_for_org(&page, scenario.reply_after_unbind),
        None,
        "a turn written after the unbind reads no org",
    );
    assert_eq!(
        page_for_org(&page, scenario.owner_turn),
        None,
        "the owner is no house",
    );
    Ok(())
}

#[test]
fn room_trunk_names_the_org_a_house_ran_when_it_spoke() -> TestResult {
    let scenario = bind_answer_unbind_answer()?;
    let owner = scenario
        .fixture
        .vault
        .memory(scenario.fixture.owner, EdgeActorClass::Human);
    let trunk = |turn: EntityId| -> TestResult<serde_json::Value> {
        Ok(serde_json::to_value(
            owner.rooms_trunk(scenario.fixture.room, turn)?,
        )?)
    };
    let org = EntityId::from_bytes(ORG)?.to_hex();
    let in_bind = trunk(scenario.reply_in_bind)?;
    assert_eq!(
        in_bind.get("for_org").and_then(serde_json::Value::as_str),
        Some(org.as_str()),
        "the trunk turn the house wrote inside its bind reads for its org: {in_bind}",
    );
    let after = trunk(scenario.reply_after_unbind)?;
    assert_eq!(
        after.get("for_org"),
        None,
        "a trunk turn written after the unbind reads no org: {after}",
    );
    Ok(())
}
