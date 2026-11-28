//! Formatted recall is another view of lifted text, not a way around its handle.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    Effort, Memory, RecallScope, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
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
const FORMATS: [&str; 2] = ["yaml", "json"];

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
        "agent_id": "recall-reader",
        "display_name": "Recall reader",
        "desc": "Reads the recall fixture",
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
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-recall-lifted-render")?;
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
    let challenge = b"oneiron-request:recall-lifted-render";
    let proof = issuer.binding_proof(&slip, challenge)?;
    Ok(vault.verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)?)
}

fn assert_masked(memory: &Memory<'_>, query: &str, id: EntityId, handle: &str) -> TestResult {
    let id = id.to_hex();
    for format in FORMATS {
        let pack = memory.recall(
            query,
            Effort::Medium,
            &RecallScope::default(),
            5,
            Some(format),
            None,
        )?;
        assert!(
            pack.items.iter().any(|item| {
                item.record.as_ref().is_some_and(|record| record.id == id)
                    && item.value_text.contains(handle)
                    && !item.value_text.contains(SECRET)
            }),
            "{format}: the typed hit reads the fixture as its handle"
        );
        let rendered = pack.rendered.expect("an explicit format renders a pack");
        assert!(
            !rendered.contains(SECRET),
            "{format}: rendered the raw value"
        );
        assert!(
            rendered.contains(handle),
            "{format}: did not render the handle"
        );
    }
    Ok(())
}

#[test]
fn a_non_owner_recall_renders_a_lifted_note_value_as_its_handle() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let (note, handle) = seed_note(&vault, owner)?;
    let agent = reader(&vault, owner)?;
    let proof = credential(&vault, agent, EdgeActorClass::Agent)?;
    let memory = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    assert_masked(&memory, "quarterly handover", note, &handle)
}

#[test]
fn a_non_owner_recall_renders_a_lifted_claim_value_as_its_handle() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let claim = EntityId::now();
    let mut body = ClaimBody::new(
        "test.allotment",
        ClaimSubject::Entity(owner),
        rmpv::Value::from(CLAIM_TEXT),
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
    // A raw put writes no text postings, so the claim must be indexed as the claim writer
    // indexes its value (field "val") or no recall finds it and the mask is never asked.
    // Index before the mark, so the indexed input is the fixture's own value.
    vault
        .batch()
        .text(&claim, &[("val", CLAIM_TEXT)])
        .commit()?;
    let handle = mark_lifted_key(&vault, claim, CLAIM_TEXT, SECRET)?;
    let agent = reader(&vault, owner)?;
    let proof = credential(&vault, agent, EdgeActorClass::Agent)?;
    let memory = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_read_proof(&proof);
    assert_masked(&memory, "allotment", claim, &handle)
}

#[test]
fn a_non_owner_recall_renders_a_lifted_turn_message_as_its_handle() -> TestResult {
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
    assert_masked(&memory, "observatory", witness.turn_id, &handle)
}

#[test]
fn the_owners_own_owner_grade_slip_renders_the_lifted_value_as_stored() -> TestResult {
    let (_dir, vault, owner) = open()?;
    let (_, handle) = seed_note(&vault, owner)?;
    let proof = credential(&vault, owner, EdgeActorClass::Human)?;
    let memory = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    for format in FORMATS {
        let pack = memory.recall(
            "quarterly handover",
            Effort::Medium,
            &RecallScope::default(),
            5,
            Some(format),
            None,
        )?;
        let rendered = pack.rendered.expect("an explicit format renders a pack");
        assert!(
            rendered.contains(NOTE_TEXT),
            "{format}: did not retain the stored text"
        );
        assert!(
            !rendered.contains(&handle),
            "{format}: masked an owner-grade recall"
        );
    }
    Ok(())
}
