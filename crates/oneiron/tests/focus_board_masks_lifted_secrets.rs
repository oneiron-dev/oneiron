//! A focus board's PINNED tier is another view of lifted text, not a way
//! around its handle: a NOTE, a CLAIM value and a TURN message a non-owner
//! pins all render as the handle, while the owner's own owner-grade slip
//! still reads the stored value.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::claim::ScopedRead;
use oneiron::context_board::{
    BoardBlockHeader, BoardBudgetRequest, MemoriesSection, MemoryRow, MemoryTier,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::test_doors::lifted_text::mark_lifted_key;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
};

const SECRET: &str = "cedar-lantern-71";
const NOTE_TEXT: &str = "Quarterly handover: cedar-lantern-71";
const CLAIM_TEXT: &str = "The allotment marker is cedar-lantern-71";
const MESSAGE_TEXT: &str = "The observatory marker is cedar-lantern-71";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn open() -> TestResult<(tempfile::TempDir, Vault, EntityId)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    let vault = Vault::open_owned(dir.path(), config)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok((dir, vault, owner))
}

fn seed_note(vault: &Vault, owner: EntityId) -> TestResult<(EntityId, String)> {
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let note = vault.create_note("research", NOTE_TEXT, actor)?;
    vault.set_indexed_idle_delay_ms(0)?;
    let published = vault.refresh_staged_indexed_at_idle(u64::MAX)?;
    assert!(published.failed.is_empty(), "publish NOTE: {published:?}");
    Ok((note, mark_lifted_key(vault, note, NOTE_TEXT, SECRET)?))
}

fn reader(vault: &Vault, owner: EntityId) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": "focus-board-reader",
        "display_name": "Focus board reader",
        "desc": "Reads the focus board fixture",
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
    vault.install_read_permit_for_test(WriteActor::new(agent, EdgeActorClass::Agent))?;
    Ok(agent)
}

fn credential(vault: &Vault, actor: EntityId, class: EdgeActorClass) -> TestResult<VerifiedSlip> {
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-focus-board-lifted-render")?;
    let mut claims = vault.ensure_host_root_slip(&issuer)?.claims;
    let now = vault.capability_slip_now()?;
    claims.slip_id = [0x72; 32];
    claims.holder_ref = actor.to_hex();
    claims.issued_at = now;
    claims.expires_at = now + 3_600;
    claims.ttl_secs = 3_600;
    claims.actor_class = Some(match class {
        EdgeActorClass::Human => "human".to_owned(),
        EdgeActorClass::Agent => {
            claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
            "agent".to_owned()
        }
        _ => unreachable!(),
    });
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let challenge = b"oneiron-request:focus-board-lifted-render";
    let proof = issuer.binding_proof(&slip, challenge)?;
    Ok(vault.verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)?)
}

/// The focus board's PINNED rows for `ids`, rendered as a board.
fn pinned_board(read: &ScopedRead<'_>, ids: &[EntityId]) -> TestResult<(MemoriesSection, String)> {
    let mut section = MemoriesSection::pins_only(None);
    section.include_pinned_ids_with_disclosure(read, ids, None)?;
    let render = section.render_board(
        &BoardBlockHeader {
            epoch: 1,
            scope: "focus-board".to_owned(),
        },
        BoardBudgetRequest {
            harness_default_tok: 10_000,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )?;
    Ok((section, render.text))
}

fn pinned_row<'a>(section: &'a MemoriesSection, id: EntityId) -> TestResult<&'a MemoryRow> {
    section
        .rows
        .iter()
        .find(|row| row.id == id.to_hex())
        .ok_or_else(|| "the pin serves the fixture as a row".into())
}

fn assert_masked(read: &ScopedRead<'_>, id: EntityId, handle: &str) -> TestResult {
    let (section, rendered) = pinned_board(read, &[id])?;
    let row = pinned_row(&section, id)?;
    assert_eq!(row.tier, MemoryTier::Pinned);
    let snippet = row
        .snippet
        .as_deref()
        .ok_or("the pinned row carries its words")?;
    assert!(
        snippet.contains(handle),
        "the pinned row reads the fixture as its handle: {snippet:?}"
    );
    assert!(
        !snippet.contains(SECRET),
        "the pinned row rendered the raw value: {snippet:?}"
    );
    assert!(
        rendered.contains(handle),
        "the board did not render the handle: {rendered}"
    );
    assert!(
        !rendered.contains(SECRET),
        "the board rendered the raw value: {rendered}"
    );
    Ok(())
}

fn assert_owner_sees(read: &ScopedRead<'_>, id: EntityId, text: &str, handle: &str) -> TestResult {
    let (section, rendered) = pinned_board(read, &[id])?;
    let row = pinned_row(&section, id)?;
    assert_eq!(row.tier, MemoryTier::Pinned);
    let snippet = row
        .snippet
        .as_deref()
        .ok_or("the pinned row carries its words")?;
    assert!(
        snippet.contains(text),
        "the owner's pinned row did not keep the stored text: {snippet:?}"
    );
    assert!(
        !snippet.contains(handle),
        "the owner's pinned row masked the stored text: {snippet:?}"
    );
    assert!(
        rendered.contains(text),
        "the owner's board did not keep the stored text: {rendered}"
    );
    assert!(
        !rendered.contains(handle),
        "the owner's board masked the stored text: {rendered}"
    );
    Ok(())
}

#[test]
fn a_non_owner_focus_board_pin_renders_a_lifted_note_value_as_its_handle() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let (note, handle) = seed_note(&vault, owner)?;
    let agent = reader(&vault, owner)?;
    let proof = credential(&vault, agent, EdgeActorClass::Agent)?;
    let memory = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let key = memory.read_key()?;
    let read = vault.scoped_read(key);
    assert_masked(&read, note, &handle)
}

#[test]
fn a_non_owner_focus_board_pin_renders_a_lifted_claim_value_as_its_handle() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "test.allotment",
        ClaimSubject::Entity(owner),
        rmpv::Value::Map(vec![(CLAIM_TEXT.into(), CLAIM_TEXT.into())]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    vault.put_claim(
        &claim,
        &body,
        TimeRange {
            start: 900,
            end: 900,
        },
        900,
    )?;
    let handle = mark_lifted_key(&vault, claim, CLAIM_TEXT, SECRET)?;
    let agent = reader(&vault, owner)?;
    let proof = credential(&vault, agent, EdgeActorClass::Agent)?;
    let memory = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let key = memory.read_key()?;
    let read = vault.scoped_read(key);
    assert_masked(&read, claim, &handle)
}

#[test]
fn a_non_owner_focus_board_pin_renders_a_lifted_turn_message_as_its_handle() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let agent = reader(&vault, owner)?;
    let conversation = EntityId::now();
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let witness = owner_memory.witness(&WitnessTurn {
        conversation_ref: conversation.to_hex(),
        turn_ref: None,
        thread_audience: None,
        project: None,
        messages: ["Here is the handover.\nThere are updates.", MESSAGE_TEXT]
            .into_iter()
            .enumerate()
            .map(|(order, content)| WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: order as u32,
                quote: None,
            })
            .collect(),
        occurred_at: 900,
        assertions: WitnessAssertions::default(),
    })?;
    let message = EntityId::from_hex(&witness.messages[1].id)?;
    let handle = mark_lifted_key(&vault, message, MESSAGE_TEXT, SECRET)?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: agent,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: conversation,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: vault.now_recorded_at(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    let proof = credential(&vault, agent, EdgeActorClass::Agent)?;
    let memory = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    let key = memory.read_key()?;
    let read = vault.scoped_read(key);
    assert_masked(&read, witness.turn_id, &handle)
}

#[test]
fn the_owners_own_owner_grade_slip_renders_the_lifted_value_as_stored() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let (note, handle) = seed_note(&vault, owner)?;
    let proof = credential(&vault, owner, EdgeActorClass::Human)?;
    let memory = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let key = memory.read_key()?;
    let read = vault.scoped_read(key);
    assert_owner_sees(&read, note, NOTE_TEXT, &handle)
}
