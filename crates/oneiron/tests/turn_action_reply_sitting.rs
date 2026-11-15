//! A queued Retry's new reply joins the sitting the reply it answers again
//! joined (FIX 1034). The turn-action worker answers with the agent's own
//! handle, which binds no sitting, because a queued action keeps no
//! authenticated machine: its new TURN joined none, or the agent's own.
//! The engine now names the sitting from the replaced reply's TURN, as FIX
//! G230-RETRY-OMITTED-SESSION-BAND places a room's Retry.
//!
//! The conversation is owen's own 1:1 chat with agent yuki, which keeps no
//! DAG: the Retry's TURN is minted by its stream's witness, not by the DAG
//! door. yuki's first reply is streamed as `/v1/ai/chat` streams it, bound
//! to owen's sitting.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test turn_action_reply_sitting`
#![cfg(all(oneiron_test_support, feature = "test-support"))]

use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::conversation::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt, TurnActionRequest};
use oneiron::federation::Scope;
use oneiron::memory::{Memory, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::session_lifecycle::SessionKey;
use oneiron::test_doors::turn_sitting::turn_sitting;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// owen's vault, agent yuki, owen's open sitting on this machine, and the
/// conversation they chat in.
struct Fixture {
    vault: Vault,
    owen: EntityId,
    agent: EntityId,
    sitting_key: SessionKey,
    sitting: EntityId,
    conversation: EntityId,
    _directory: tempfile::TempDir,
}

/// Agent yuki, created by the owner, under an Auto ceiling.
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
/// the vault's records: rows added to the default policy manifest, as
/// tests/turn_retry_regenerated_turn.rs adds them.
fn grant_reads(vault: &Vault, owen: EntityId, agent: EntityId) -> TestResult {
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
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".into(),
        actor_ref: Some(agent.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owen, agent] {
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

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent = create_agent(&vault, owen, "yuki")?;
    grant_reads(&vault, owen, agent)?;
    let sitting_key = vault.local_session_key(owen)?;
    vault.mint_session(sitting_key, vault.now_recorded_at())?;
    let sitting = vault
        .open_session(sitting_key)?
        .ok_or("fixture: owen's sitting is not open")?
        .session;
    Ok(Fixture {
        vault,
        owen,
        agent,
        sitting_key,
        sitting,
        conversation: EntityId::now(),
        _directory: directory,
    })
}

/// One MESSAGE by `author` in a new TURN `turn` of the conversation, empty
/// at birth (`id` None lets a regeneration mint its own).
fn birth(
    fixture: &Fixture,
    turn: Option<EntityId>,
    author: WitnessAuthor,
    id: Option<EntityId>,
) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: fixture.conversation.to_hex(),
        turn_ref: turn.map(|turn| turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: id.map(|id| id.to_hex()),
            author,
            message_type: "text".into(),
            content: String::new(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: fixture.vault.now_recorded_at(),
        assertions: WitnessAssertions::default(),
    }
}

/// `memory` streams `words` into a new TURN as `author`; returns the TURN.
fn stream_turn(
    fixture: &Fixture,
    memory: &Memory<'_>,
    author: WitnessAuthor,
    words: &str,
) -> TestResult<EntityId> {
    let turn = EntityId::now();
    let handle = memory.begin_message_stream(
        &birth(fixture, Some(turn), author, Some(EntityId::now())),
        None,
    )?;
    memory.append_to_stream(handle, words)?;
    memory.finalize_stream(handle)?;
    Ok(turn)
}

/// owen asks; yuki answers, its stream bound to owen's sitting when
/// `bound`, as the chat host binds its caller's, else to none. Returns
/// yuki's reply TURN.
fn exchange(fixture: &Fixture, bound: bool) -> TestResult<EntityId> {
    let owen = fixture
        .vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .with_session(fixture.sitting_key);
    stream_turn(fixture, &owen, WitnessAuthor::User, "owen asks")?;
    let agent = fixture.vault.memory(fixture.agent, EdgeActorClass::Agent);
    let agent = if bound {
        agent.with_session(fixture.sitting_key)
    } else {
        agent
    };
    stream_turn(fixture, &agent, WitnessAuthor::Companion, "yuki answers")
}

/// owen's Retry of `reply`, claimed as the host's turn-action worker
/// claims it.
fn queue_retry(fixture: &Fixture, reply: EntityId) -> TestResult<TurnActionAttempt> {
    let vault = &fixture.vault;
    vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .conversations_turn_retry(&TurnActionRequest {
            turn_id: reply.to_hex(),
        })?;
    let claimed = AttemptQueue::new(vault).claim_kind(
        TURN_ACTION_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: "turn-action-reply-sitting".to_owned(),
            now: vault.now_recorded_at(),
        },
    )?;
    let ClaimOutcome::Claimed(attempt) = claimed else {
        return Err(format!("fixture: the Retry is not claimable: {claimed:?}").into());
    };
    Ok(TurnActionAttempt::decode(&attempt)?)
}

/// yuki answers the Retry as the turn-action worker did: its own handle,
/// bound to no sitting. Returns the new reply's TURN.
fn answer_retry(fixture: &Fixture, action: &TurnActionAttempt) -> TestResult<EntityId> {
    let vault = &fixture.vault;
    let agent = vault.memory(fixture.agent, EdgeActorClass::Agent);
    let handle = agent.begin_message_regeneration(
        &birth(fixture, None, WitnessAuthor::Companion, None),
        action,
        None,
    )?;
    agent.append_to_stream(handle, "yuki answers again")?;
    let receipt = agent.finalize_stream(handle)?;
    let turn = vault
        .edges_out(&receipt.message_id)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::PartOf)
        .ok_or("the Retry's MESSAGE has no TURN")?
        .target;
    Ok(turn)
}

/// Red on #8265's head: the Retry's new TURN joined no sitting, though
/// the reply it answers again sat in owen's.
#[test]
fn a_retrys_new_turn_joins_the_sitting_its_replaced_reply_joined() -> TestResult {
    let fixture = open_fixture()?;
    let reply = exchange(&fixture, true)?;
    assert_eq!(
        turn_sitting(&fixture.vault, &reply)?,
        Some(fixture.sitting),
        "fixture: yuki's first reply did not join owen's sitting"
    );
    let action = queue_retry(&fixture, reply)?;
    let regenerated = answer_retry(&fixture, &action)?;
    assert_ne!(regenerated, reply);
    assert_eq!(
        turn_sitting(&fixture.vault, &regenerated)?,
        Some(fixture.sitting),
        "the Retry's TURN did not join the sitting its replaced reply joined"
    );
    Ok(())
}

/// Control: a reply that joined no sitting gives its Retry none, and the
/// Retry does not take owen's open sitting in its place.
#[test]
fn a_retry_of_a_reply_in_no_sitting_joins_none() -> TestResult {
    let fixture = open_fixture()?;
    let reply = exchange(&fixture, false)?;
    assert_eq!(
        turn_sitting(&fixture.vault, &reply)?,
        None,
        "fixture: yuki's unbound reply joined a sitting"
    );
    let action = queue_retry(&fixture, reply)?;
    let regenerated = answer_retry(&fixture, &action)?;
    assert_eq!(turn_sitting(&fixture.vault, &regenerated)?, None);
    Ok(())
}
