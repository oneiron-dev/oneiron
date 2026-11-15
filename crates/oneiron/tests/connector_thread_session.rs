//! OWN-VOICE-EPOCHS = C, Engine ruling UNBUILT-02-SITTING = A: "A connector
//! thread keeps its own SESSION."
//!
//! Every connector conversation (an external thread) holds its turns in one
//! SESSION, its id derived from the conversation, minted at the first
//! connector witness with an open lifecycle record and no open pointer, so
//! `Vault::open_sessions()` never lists it. Each witness holds, in its own
//! transaction, every turn of the thread that has no SESSION yet, an older
//! turn too, except one that occurred before the last turn the thread's
//! landed epochs cover. The thread SESSION numbers its turns by (occurred
//! time, id), as its transcript orders them. The agent still lists its thread
//! and reads its log as a compaction window.
//!
//! The doors in `oneiron::test_doors::connector_thread_session` read the
//! thread's conversation and SESSION, a turn's SESSION, the thread's turn
//! order and a log's window. On main the door does not exist, so this file
//! does not compile there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test connector_thread_session`.
#![cfg(oneiron_test_support)]

use std::path::Path;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::ingest::ConnectorLogLine;
use oneiron::memory::ConversationListFilter;
use oneiron::outbound::CONNECTOR_REPLY_REF;
use oneiron::surface_event::{
    SurfaceConnectorPayload, SurfaceCounterpartyStamp, SurfaceEventAction,
    SurfaceEventDispatchRoute, SurfaceEventSource, SurfaceSourceApp,
};
use oneiron::test_doors::connector_thread_session::{
    log_window_turns, thread_conversation, thread_session, thread_turn_order, turn_session,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn open(path: &Path) -> TestResult<Vault> {
    Ok(Vault::open_owned(path, VaultConfig::default())?)
}

fn define_agent(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let definition = AgentDefinition::new(
        name,
        "Derivation verbs fixture agent",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

fn origin(
    agent: EntityId,
    identity: EntityId,
    event_id: &str,
    received_at: u64,
) -> SurfaceConnectorPayload {
    SurfaceConnectorPayload {
        surface_event_id: event_id.to_owned(),
        channel: "line".to_owned(),
        receiving_address_or_handle: "line-test-address".to_owned(),
        workspace_ref: None,
        receiving_identity_ref: identity.to_hex(),
        actor_ref: agent.to_hex(),
        facet_ref: None,
        subject_ref: None,
        counterparty: SurfaceCounterpartyStamp::unknown("line:user:alice"),
        source: SurfaceEventSource::new(SurfaceSourceApp::Line, "line:user:alice"),
        action: SurfaceEventAction::Message,
        route: SurfaceEventDispatchRoute::ActorSelf,
        thread_ref: Some("thread-1".to_owned()),
        correlation_id: event_id.to_owned(),
        payload_ref: None,
        received_at,
        foreign_inbound: true,
        claims_not_instructions: true,
        identity_retiring: false,
    }
}

fn witness_turn(refs: &[String]) -> TestResult<EntityId> {
    let hex = refs.get(1).ok_or("a connector witness names its turn")?;
    Ok(EntityId::from_hex(hex)?)
}

#[test]
fn connector_thread_turns_join_their_own_session() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open(directory.path())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let agent = define_agent(&vault, "connector-thread-agent")?;
    let identity = EntityId::from_bytes([0x21; 16])?;
    let base = 1_800_000_000u64;
    let origin1 = origin(agent, identity, "evt-1", base + 100);
    let origin2 = origin(agent, identity, "evt-2", base + 200);
    let inbound1 = vault.witness_connector_inbound(agent, &origin1, "first inbound", base + 110)?;
    let reply1 = vault.witness_connector_reply(
        agent,
        &origin1,
        CONNECTOR_REPLY_REF,
        "first reply",
        base + 120,
        base + 130,
    )?;
    let inbound2 =
        vault.witness_connector_inbound(agent, &origin2, "second inbound", base + 210)?;
    let reply2 = vault.witness_connector_reply(
        agent,
        &origin2,
        CONNECTOR_REPLY_REF,
        "second reply",
        base + 220,
        base + 230,
    )?;
    let conversation = thread_conversation(&origin1)?;
    assert_eq!(
        thread_conversation(&origin2)?,
        conversation,
        "both exchanges share one conversation"
    );
    let session = thread_session(conversation)?;
    for witness in [&inbound1, &reply1, &inbound2, &reply2] {
        let turn = witness_turn(&witness.refs)?;
        assert_eq!(
            turn_session(&vault, turn)?,
            Some(session),
            "the turn joins the thread SESSION"
        );
    }
    assert!(
        vault
            .open_sessions()?
            .iter()
            .all(|row| row.session != session),
        "the thread SESSION holds no open pointer"
    );
    let record = vault
        .session_lifecycle_record(&session)?
        .ok_or("the thread SESSION has a lifecycle record")?;
    assert!(record.ended_at.is_none(), "the thread SESSION stays open");
    Ok(())
}

#[test]
fn an_older_thread_turn_joins_its_session_on_the_next_witness() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open(directory.path())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let agent = define_agent(&vault, "connector-thread-agent")?;
    let identity = EntityId::from_bytes([0x21; 16])?;
    let base = 1_800_000_000u64;
    let origin1 = origin(agent, identity, "evt-1", base + 100);
    vault.witness_connector_inbound(agent, &origin1, "first inbound", base + 110)?;
    vault.witness_connector_reply(
        agent,
        &origin1,
        CONNECTOR_REPLY_REF,
        "first reply",
        base + 120,
        base + 130,
    )?;
    let conversation = thread_conversation(&origin1)?;
    let session = thread_session(conversation)?;
    let older = EntityId::from_bytes([0x4a; 16])?;
    let older_at = base + 50;
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("question"),
        )]),
    )?;
    vault.put_entity(
        &older,
        oneiron::registry::ENTITY_TYPE_TURN,
        TimeRange {
            start: older_at,
            end: older_at,
        },
        older_at,
        &body,
    )?;
    vault.put_edge(&older, EdgeKind::ChildOf, &conversation, 1.0)?;
    assert_eq!(
        turn_session(&vault, older)?,
        None,
        "the older turn starts with no SESSION"
    );
    let origin2 = origin(agent, identity, "evt-2", base + 200);
    vault.witness_connector_inbound(agent, &origin2, "second inbound", base + 210)?;
    vault.witness_connector_reply(
        agent,
        &origin2,
        CONNECTOR_REPLY_REF,
        "second reply",
        base + 220,
        base + 230,
    )?;
    assert_eq!(
        turn_session(&vault, older)?,
        Some(session),
        "the next witness holds the older turn"
    );
    Ok(())
}

#[test]
fn connector_thread_turns_are_numbered_as_they_occurred() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open(directory.path())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let agent = define_agent(&vault, "connector-thread-agent")?;
    let identity = EntityId::from_bytes([0x21; 16])?;
    let base = 1_800_000_000u64;
    let origin1 = origin(agent, identity, "evt-1", base + 100);
    let origin2 = origin(agent, identity, "evt-2", base + 200);
    let origin3 = origin(agent, identity, "evt-3", base + 300);
    let inbound1 = vault.witness_connector_inbound(agent, &origin1, "first inbound", base + 110)?;
    let reply1 = vault.witness_connector_reply(
        agent,
        &origin1,
        CONNECTOR_REPLY_REF,
        "first reply",
        base + 120,
        base + 130,
    )?;
    let inbound2 =
        vault.witness_connector_inbound(agent, &origin2, "second inbound", base + 210)?;
    let reply2 = vault.witness_connector_reply(
        agent,
        &origin2,
        CONNECTOR_REPLY_REF,
        "second reply",
        base + 220,
        base + 230,
    )?;
    let inbound3 = vault.witness_connector_inbound(agent, &origin3, "third inbound", base + 310)?;
    let reply3 = vault.witness_connector_reply(
        agent,
        &origin3,
        CONNECTOR_REPLY_REF,
        "third reply",
        base + 320,
        base + 330,
    )?;
    let mut by_time = vec![
        (base + 100, witness_turn(&inbound1.refs)?),
        (base + 120, witness_turn(&reply1.refs)?),
        (base + 200, witness_turn(&inbound2.refs)?),
        (base + 220, witness_turn(&reply2.refs)?),
        (base + 300, witness_turn(&inbound3.refs)?),
        (base + 320, witness_turn(&reply3.refs)?),
    ];
    by_time.sort_by_key(|(at, _)| *at);
    let expected: Vec<EntityId> = by_time.into_iter().map(|(_, turn)| turn).collect();
    let conversation = thread_conversation(&origin1)?;
    assert_eq!(
        thread_conversation(&origin2)?,
        conversation,
        "the exchanges share one conversation"
    );
    assert_eq!(
        thread_conversation(&origin3)?,
        conversation,
        "the exchanges share one conversation"
    );
    let order =
        thread_turn_order(&vault, conversation)?.ok_or("the thread SESSION numbers its turns")?;
    assert_eq!(order, expected, "turns are numbered as they occurred");
    Ok(())
}

#[test]
fn the_agent_still_sees_its_own_thread_in_its_list() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open(directory.path())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let agent = define_agent(&vault, "connector-thread-agent")?;
    let identity = EntityId::from_bytes([0x21; 16])?;
    let base = 1_800_000_000u64;
    let origin1 = origin(agent, identity, "evt-1", base + 100);
    let origin2 = origin(agent, identity, "evt-2", base + 200);
    let witnesses = [
        vault.witness_connector_inbound(agent, &origin1, "first inbound", base + 110)?,
        vault.witness_connector_reply(
            agent,
            &origin1,
            CONNECTOR_REPLY_REF,
            "first reply",
            base + 120,
            base + 130,
        )?,
        vault.witness_connector_inbound(agent, &origin2, "second inbound", base + 210)?,
        vault.witness_connector_reply(
            agent,
            &origin2,
            CONNECTOR_REPLY_REF,
            "second reply",
            base + 220,
            base + 230,
        )?,
    ];
    for witness in &witnesses {
        assert!(
            witness.read_grant_repair.is_none(),
            "the witness issues the agent its read grant: {:?}",
            witness.read_grant_repair
        );
    }
    let conversation = thread_conversation(&origin1)?;
    let list = vault
        .memory(agent, EdgeActorClass::Agent)
        .conversation_list(ConversationListFilter::default(), None, 50, true)?;
    let row = list
        .value
        .rows
        .iter()
        .find(|row| row.row.id == conversation)
        .ok_or("the thread lists for its agent")?;
    let snippet = row
        .last_message_snippet
        .as_ref()
        .ok_or("the thread previews its latest message")?;
    assert!(!snippet.is_empty(), "the preview is non-empty");
    Ok(())
}

#[test]
fn a_connector_thread_log_forms_a_compaction_window() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open(directory.path())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let agent = define_agent(&vault, "connector-thread-agent")?;
    let identity = EntityId::from_bytes([0x21; 16])?;
    let base = 1_800_000_000u64;
    let origin1 = origin(agent, identity, "evt-1", base + 100);
    let origin2 = origin(agent, identity, "evt-2", base + 200);
    let origin3 = origin(agent, identity, "evt-3", base + 300);
    let current_inbound = "third inbound";
    let current_reply = "third reply";
    let inbound1 = vault.witness_connector_inbound(agent, &origin1, "first inbound", base + 110)?;
    vault.witness_connector_reply(
        agent,
        &origin1,
        CONNECTOR_REPLY_REF,
        "first reply",
        base + 120,
        base + 130,
    )?;
    vault.witness_connector_inbound(agent, &origin2, "second inbound", base + 210)?;
    vault.witness_connector_reply(
        agent,
        &origin2,
        CONNECTOR_REPLY_REF,
        "second reply",
        base + 220,
        base + 230,
    )?;
    vault.witness_connector_inbound(agent, &origin3, current_inbound, base + 310)?;
    vault.witness_connector_reply(
        agent,
        &origin3,
        CONNECTOR_REPLY_REF,
        current_reply,
        base + 320,
        base + 330,
    )?;
    let conversation = thread_conversation(&origin1)?;
    let session = thread_session(conversation)?;
    let first_turn = witness_turn(&inbound1.refs)?;
    let log = vault
        .connector_conversation_log(agent, &origin3, CONNECTOR_REPLY_REF, 1)?
        .ok_or("the thread reads as a log")?;
    assert_eq!(
        log.log.session,
        Some(session),
        "the log sits in the thread SESSION"
    );
    let window = log_window_turns(&log.log).ok_or("the log forms a window")?;
    assert_eq!(
        window.first(),
        Some(&first_turn),
        "the window starts with the thread first turn"
    );
    for line in &log.lines {
        if let ConnectorLogLine::Message(message) = line {
            assert_ne!(
                message.text.as_str(),
                current_inbound,
                "the current inbound stays out of the lines"
            );
            assert_ne!(
                message.text.as_str(),
                current_reply,
                "the current reply stays out of the lines"
            );
        }
    }
    Ok(())
}
