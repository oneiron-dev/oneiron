//! An ordinary room's witness lands every turn it mints on the room's trunk,
//! and the room's threads live on its conversation DAG. So a witness turn
//! whose message names a PRIVATE thread's TURN as its reply parent
//! (`room_reply_to`) or its thread anchor (`room_thread_of`) is refused,
//! rather than shown to the whole room (CHAT-ORDINARY-ROOM-REPLY-TO-TRUNK;
//! RULING CHAT-THREAD-REPLY-REFUSAL-SCOPE = B). Chat's `reply_to`, a
//! `rooms.speak` reply and an offer accepted on a thread all stamp those
//! keys, and all reach this witness; these cases speak through
//! `rooms.speak`, and one answers an agent's offer card on a private
//! thread. A reply aimed at a room-wide thread, and one to a trunk TURN,
//! still land on the trunk, as before. The chat route's case is
//! `crates/oneiron-server/tests/chat_ordinary_room_private_thread_reply.rs`.
//!
//! Fixture: owen, the vault's owner, who reads the vault's records under
//! the default policy manifest, in an ordinary group room he holds alone.
//! A trunk witness turn is the anchor. owen's DAG replies on it open a
//! private thread (audience owen) and a room-wide thread. The offer case
//! adds an agent and its own model PERSON to the room (`open_offer_fixture`).
//!
//! Red on main (by assertion): there the witness lands each private-thread
//! reply on the trunk, a row that answers no turn and names no thread, and
//! the offer's acceptance lands there too. The room-wide thread and trunk
//! controls pass on both.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test ordinary_room_thread_reply_refused`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, Memory, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    OfferAnswer, OfferAnswerRequest, OfferDraft, OfferState, RoomTurn,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owen: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }
}

/// owen reads the vault's records: a row added to the default policy
/// manifest, the shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId) -> TestResult {
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
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        // Bare census keys carry no actor class.
        actor_class: None,
        actor_ref: Some(owen.to_hex()),
        effector: "core:read".into(),
        scope: Scope::top(),
        selectors: None,
        budget: None,
        receipt_required: false,
    });
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
                "title": "ordinary room",
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    grant_reads(&vault, owen)?;
    let room = ordinary_room(&vault, owen)?;
    Ok(Fixture {
        vault,
        owen,
        room,
        _directory: directory,
    })
}

/// owen's one-message witness turn in the room through the room speech
/// door, its message carrying `metadata`. Returns the TURN it names and the
/// door's answer.
fn speak(
    fixture: &Fixture,
    metadata: serde_json::Value,
) -> (EntityId, oneiron::memory::MemoryResult<()>) {
    let turn = EntityId::now();
    let spoken = fixture
        .owen()
        .rooms_speak(&WitnessTurn {
            conversation_ref: fixture.room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: fixture.vault.now_recorded_at(),
            assertions: Default::default(),
            project: None,
        })
        .map(|_| ());
    (turn, spoken)
}

/// owen's plain TURN for the DAG's thread reply door, read by `audience`
/// alone when it names one.
fn plain_turn(fixture: &Fixture, audience: Option<BTreeSet<EntityId>>) -> TestResult<AppendRecord> {
    let now = fixture.vault.now_recorded_at();
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
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
        thread_audience: audience,
    })
}

/// owen's reply on `anchor` through the DAG's thread reply door. Returns the
/// TURN.
fn thread_reply(
    fixture: &Fixture,
    anchor: EntityId,
    audience: Option<BTreeSet<EntityId>>,
) -> TestResult<EntityId> {
    let input = plain_turn(fixture, audience)?;
    Ok(fixture
        .vault
        .reply_in_thread(&fixture.owen(), anchor, &input)?
        .id)
}

/// A trunk witness turn, the anchor the threads hang from.
fn anchor(fixture: &Fixture) -> TestResult<EntityId> {
    let (turn, spoken) = speak(fixture, serde_json::json!({}));
    spoken?;
    Ok(turn)
}

/// The room row of `turn` in owen's room history, if the room keeps one.
fn row(fixture: &Fixture, turn: EntityId) -> TestResult<Option<RoomTurn>> {
    Ok(fixture
        .owen()
        .rooms_messages(fixture.room)?
        .into_iter()
        .find(|row| row.turn_id == turn.to_hex()))
}

/// The witness refused `spoken` as a thread reply, and the room keeps no
/// row for `turn`.
fn assert_refused_and_unlanded(
    fixture: &Fixture,
    turn: EntityId,
    spoken: oneiron::memory::MemoryResult<()>,
    case: &str,
) -> TestResult {
    let landed = row(fixture, turn)?;
    let error = match spoken {
        Ok(()) => {
            return Err(format!(
                "{case}: the witness took the reply and landed it as {landed:?}, \
                 a trunk turn the whole room reads"
            )
            .into());
        }
        Err(error) => error,
    };
    assert!(
        format!("{error:?}").contains("reply door"),
        "{case}: refused for another reason: {error:?}"
    );
    assert!(landed.is_none(), "{case}: a refused turn kept {landed:?}");
    Ok(())
}

/// A reply to the root of a private thread is refused, and lands nowhere.
#[test]
fn a_reply_to_a_private_threads_root_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(&fixture, anchor, Some(BTreeSet::from([fixture.owen])))?;
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_reply_to": root.to_hex()}),
    );
    assert_refused_and_unlanded(&fixture, turn, spoken, "private thread root")
}

/// A reply to a later TURN of a private thread is refused: that TURN reads
/// its thread's audience through its root.
#[test]
fn a_reply_to_a_later_turn_of_a_private_thread_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(&fixture, anchor, Some(BTreeSet::from([fixture.owen])))?;
    // A reply naming no audience continues the thread owen reads.
    let later = thread_reply(&fixture, anchor, None)?;
    assert_ne!(root, later);
    let work = fixture
        .vault
        .turn_room_work(later)?
        .ok_or("the later reply sits in no thread")?;
    assert_eq!(
        work.branch,
        Some(root),
        "the later reply continues the thread"
    );
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_reply_to": later.to_hex()}),
    );
    assert_refused_and_unlanded(&fixture, turn, spoken, "private thread later turn")
}

/// Control, green on main too: a reply aimed at a room-wide thread still
/// lands on the trunk, as before (RULING CHAT-THREAD-REPLY-REFUSAL-SCOPE =
/// B: misplaced, but read by no one the thread hides it from).
#[test]
fn a_reply_to_a_room_wide_thread_still_lands_on_the_trunk() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(&fixture, anchor, None)?;
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_reply_to": root.to_hex()}),
    );
    spoken?;
    let landed = row(&fixture, turn)?.ok_or("the room-wide thread reply keeps no room row")?;
    assert_eq!(landed.thread_of, None);
    assert_eq!(landed.reply_to, None);
    Ok(())
}

/// A turn naming a private thread's TURN as its thread anchor is refused.
#[test]
fn a_turn_naming_a_private_thread_turn_as_its_anchor_is_refused() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(&fixture, anchor, Some(BTreeSet::from([fixture.owen])))?;
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_thread_of": root.to_hex()}),
    );
    assert_refused_and_unlanded(&fixture, turn, spoken, "thread turn as anchor")
}

/// Control, green on main too: a reply to a trunk TURN, the anchor a thread
/// hangs from included, still lands on the trunk.
#[test]
fn a_reply_to_a_trunk_turn_still_lands_on_the_trunk() -> TestResult {
    let fixture = open_fixture()?;
    let anchor = anchor(&fixture)?;
    thread_reply(&fixture, anchor, Some(BTreeSet::from([fixture.owen])))?;
    let (turn, spoken) = speak(
        &fixture,
        serde_json::json!({"room_reply_to": anchor.to_hex()}),
    );
    spoken?;
    let landed = row(&fixture, turn)?.ok_or("the trunk reply keeps no room row")?;
    assert_eq!(landed.thread_of, None);
    assert_eq!(landed.actor, fixture.owen.to_hex());
    Ok(())
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

/// The agent asks under its own Auto ceiling, and owen and the agent read
/// the vault's records: rows added to the default policy manifest, the
/// shipped rows kept.
fn grant_offer_reads(vault: &Vault, owen: EntityId, agent: EntityId) -> TestResult {
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

/// An ordinary group room owen creates, and so hosts, holding `members`.
fn ordinary_room_with(vault: &Vault, owen: EntityId, members: &[EntityId]) -> TestResult<EntityId> {
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
                "member_ids": members.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
                "title": "ordinary room",
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// `agent` reads `room`'s MESSAGEs under an active grant.
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

/// Fixture for the offer path: owen, the vault's owner, an agent made
/// through the agent-definition door, and an ordinary group room owen hosts
/// holding owen and the agent's own model PERSON. An AGENT_DEF is never a
/// ledger member (the ledger seats PERSONs alone), but the agent counts as
/// one for a private audience through that PERSON, so a thread may name
/// them both while the agent still asks by a card, never as a pen.
fn open_offer_fixture() -> TestResult<(Fixture, EntityId)> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent = create_agent(&vault, owen, "yuki-offer")?;
    let person = vault
        .actor_subject_anchor(&agent, vault.now_recorded_at())?
        .map(|held| held.subject_ref)
        .ok_or("the agent names no model PERSON")?;
    grant_offer_reads(&vault, owen, agent)?;
    let room = ordinary_room_with(&vault, owen, &[owen, person])?;
    grant_messages(&vault, room, agent)?;
    Ok((
        Fixture {
            vault,
            owen,
            room,
            _directory: directory,
        },
        agent,
    ))
}

/// Path 3 of the ruling: the agent's offer card on a private thread's root,
/// answered Join by owen, the room's host. The settlement witnesses the
/// agent's acceptance turn with `room_reply_to` naming that root, so the
/// head refuses the answer with BAD_REQUEST (the witness's "reply door"
/// refusal) and lands no turn: owen's room history holds no row whose
/// actor is the agent.
///
/// Red on main by assertion: there the acceptance lands on the trunk, so
/// the answer is Ok and the agent owns a room row.
#[test]
fn an_offer_accepted_on_a_private_thread_is_refused() -> TestResult {
    let (fixture, agent) = open_offer_fixture()?;
    let anchor = anchor(&fixture)?;
    let root = thread_reply(
        &fixture,
        anchor,
        Some(BTreeSet::from([fixture.owen, agent])),
    )?;
    // owen files the agent's card as its principal: the vault's own agent
    // asks through a live owner, and owen reads the private root.
    let card = fixture.owen().rooms_offer(&OfferDraft {
        room: fixture.room,
        branch: Some(root),
        agent,
        what: "Tend the private thread.".to_owned(),
        artifact_ref: None,
        spend_scope: None,
        until: None,
        intent_key: "ordinary-room-thread-reply-refused:offer".to_owned(),
    })?;
    assert!(
        matches!(card.state, OfferState::Open { .. }),
        "the card lands open, waiting on the host: {:?}",
        card.state
    );
    let answered = fixture.owen().rooms_offer_answer(&OfferAnswerRequest {
        offer_id: card.offer_id.clone(),
        action: OfferAnswer::Join,
        intent_key: "ordinary-room-thread-reply-refused:answer".to_owned(),
        check_in_ref: None,
    });
    let error = match answered {
        Ok(settlement) => {
            return Err(format!("the acceptance landed on the trunk: {settlement:?}").into());
        }
        Err(error) => error,
    };
    assert_eq!(
        error.code.as_str(),
        MEMORY_CODE_BAD_REQUEST,
        "the refusal keeps its code: {error:?}"
    );
    assert!(
        error.message.contains("reply door"),
        "refused for another reason: {error:?}"
    );
    let agent_rows: Vec<_> = fixture
        .owen()
        .rooms_messages(fixture.room)?
        .into_iter()
        .filter(|row| row.actor == agent.to_hex())
        .collect();
    assert!(
        agent_rows.is_empty(),
        "a refused acceptance kept {agent_rows:?}"
    );
    Ok(())
}
