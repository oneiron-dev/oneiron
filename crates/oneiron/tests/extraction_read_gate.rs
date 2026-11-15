//! Extraction reads use native's relationship gate without opening general reads.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod gate_step_support;
#[path = "extraction_verdict/support.rs"]
mod gate_verdict_support;

use gate_verdict_support::{
    ExtractionVerdictTestResult, QUEUE_NOW, bind_extraction, extraction_attempt_hex,
    extraction_candidate, extraction_verdict_request, invoke_bound_verdict,
    native_resolution_options, open_extraction_verdict_vault, page_turns_with_versions,
    read_bound_extraction_page,
};
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_MODEL_UNAVAILABLE, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::snapshot_read::{
    EvidenceSourceStatus, EvidenceSpansRequest, ExtractionInputsPage, ExtractionInputsPageRequest,
    evidence_spans, extraction_inputs_page,
};
use oneiron::test_doors::extraction_inputs::{
    ExtractionConversation, enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{ExtractionStepFixture, attach_extraction_step_lender};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Reads the same queued inputs through the proven owner's public page.
fn owner_inputs(
    vault: &Vault,
    attempt: AttemptId,
) -> ExtractionVerdictTestResult<ExtractionInputsPage> {
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(extraction_inputs_page(
        &vault.memory(owner, EdgeActorClass::Human),
        &ExtractionInputsPageRequest {
            attempt: extraction_attempt_hex(attempt),
            cursor: None,
            limit: None,
        },
    )?
    .value)
}

/// Witnesses one MESSAGE with explicit metadata through the public witness path.
fn witness_metadata_turn(
    vault: &Vault,
    metadata: Value,
) -> ExtractionVerdictTestResult<ExtractionConversation> {
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let message = EntityId::now();
    let speaker = EntityId::now();
    seed_named_person(vault, &speaker, "owen", 1)?;
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: "owen likes tea".to_owned(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })?;
    Ok(ExtractionConversation {
        conversation,
        turns: vec![turn],
        messages: vec![message],
    })
}

/// Ordinary MESSAGE words produce two queued TURNs with pinned projections.
#[test]
fn bound_inputs_serve_ordinary_turn_projections() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "yuki likes coffee"])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    for ((turn, version), expected) in turns.iter().zip(&witnessed.turns) {
        assert_eq!(*turn, expected.to_hex());
        assert!(version["projection"].as_str().is_some());
    }
    Ok(())
}

/// The public page's live Steward branch uses the same extraction rule.
#[test]
fn public_steward_inputs_serve_ordinary_turns() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_extraction_verdict_vault(&dir)?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (attempt, _) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let page = extraction_inputs_page(
        &vault.memory(actor, EdgeActorClass::System),
        &ExtractionInputsPageRequest {
            attempt: extraction_attempt_hex(attempt),
            cursor: None,
            limit: None,
        },
    )?;
    assert_eq!(page.value.turns.len(), 1);
    assert!(page.value.turns[0].version.projection.is_some());
    Ok(())
}

/// A private MESSAGE withholds the whole TURN while the owner still reads it.
#[test]
fn private_message_turn_is_owner_only() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let witnessed = witness_metadata_turn(&vault, json!({"scope": {"private": true}}))?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    assert!(page_turns_with_versions(&page).is_empty());
    let owner = owner_inputs(&vault, attempt)?;
    assert_eq!(owner.turns.len(), 1);
    assert_eq!(owner.turns[0].turn, witnessed.turns[0].to_hex());
    assert!(owner.turns[0].version.projection.is_some());
    Ok(())
}

/// Relationship words require the Dreamer's live MessagesRead grant, checked anew per page.
#[test]
fn relationship_message_turn_requires_a_live_grant() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let relationship = EntityId::now();
    vault.put_entity(
        &relationship,
        oneiron::registry::ENTITY_TYPE_RELATIONSHIP,
        oneiron::TimeRange { start: 1, end: 1 },
        1,
        b"relationship",
    )?;
    let witnessed = witness_metadata_turn(&vault, json!({"rel": relationship.to_hex()}))?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    assert!(page_turns_with_versions(&page).is_empty());
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: actor,
            scope: AccessGrantScope::Messages {
                space_ref: relationship,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: vault.now_recorded_at(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    assert_eq!(turns[0].0, witnessed.turns[0].to_hex());
    assert!(turns[0].1["projection"].as_str().is_some());
    Ok(())
}

/// Bound spans accept an owner's ordinary pin; the general delegated spans verb stays closed.
#[test]
fn bound_spans_read_ordinary_words_without_opening_general_spans() -> ExtractionVerdictTestResult<()>
{
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let owner = owner_inputs(&vault, attempt)?;
    assert_eq!(owner.turns.len(), 1);
    let version = owner.turns[0].version.clone();
    let binding = bind_extraction(&vault, &admitted)?;
    let answer = binding.invoke(
        "vault.evidence.spans",
        json!({"source": witnessed.turns[0].to_hex(), "version": version}),
        None,
    )?;
    assert_eq!(answer["value"]["status"], json!("current"));
    assert_eq!(answer["value"]["spans"][0]["text"], json!("owen likes tea"));
    let general = evidence_spans(
        &vault.memory(actor, EdgeActorClass::System),
        &EvidenceSpansRequest {
            source: witnessed.turns[0],
            version: Some(version),
            ranges: vec![],
        },
    )?;
    assert_eq!(general.value.status, EvidenceSourceStatus::Withheld);
    let direct_message = binding.invoke(
        "vault.evidence.spans",
        json!({"source": witnessed.messages[0].to_hex()}),
        None,
    )?;
    assert_eq!(direct_message["value"]["status"], json!("withheld"));
    Ok(())
}

/// Step validation rereads the ordinary TURN before rendering its lent transcript.
#[test]
fn bound_step_reads_an_owner_pinned_ordinary_turn()
-> gate_step_support::ExtractionStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(gate_step_support::open_extraction_step_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (attempt, admitted) = enqueue_admitted_extraction_attempt(
        &vault,
        &witnessed.turns,
        gate_step_support::QUEUE_NOW,
    )?;
    let owner = owner_inputs(&vault, attempt)?;
    assert_eq!(owner.turns.len(), 1);
    let backend = Arc::new(gate_step_support::CapturingStepBackend::new(
        gate_step_support::step_plain_reply(),
        100,
        50,
    ));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(
        gate_step_support::bind_extraction(&vault, &admitted)?,
        &fixture,
    );
    let request = gate_step_support::extraction_step_request(json!([
        gate_step_support::extraction_step_evidence(
            &owner.turns[0].turn,
            serde_json::to_value(&owner.turns[0].version)?,
            None,
        ),
    ]));
    let answer = gate_step_support::invoke_bound_step(&binding, request)?;
    assert_eq!(answer["result"]["status"], json!("finished"));
    assert_eq!(backend.call_count(), 1);
    let transcripts = backend.request_transcripts();
    assert_eq!(transcripts.len(), 1);
    assert!(transcripts[0].contains("owen likes tea"));
    assert_eq!(backend.request_texts().len(), 1);
    let step_ref = answer["step_ref"].as_str().expect("finished step ref");
    let receipt = gate_step_support::invoke_bound_step_receipt(&binding, step_ref)?;
    assert_eq!(receipt["result"]["status"], json!("finished"));
    let page = gate_step_support::read_bound_extraction_page(
        &binding,
        &gate_step_support::extraction_attempt_hex(attempt),
    )?;
    let turns = gate_step_support::page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    assert_eq!(turns[0].1, serde_json::to_value(&owner.turns[0].version)?);
    Ok(())
}

/// Observations check ordinary TURN evidence independently of the bound inputs page.
#[test]
fn observations_read_an_owner_pinned_ordinary_turn() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let owner = owner_inputs(&vault, attempt)?;
    assert_eq!(owner.turns.len(), 1);
    let binding = bind_extraction(&vault, &admitted)?;
    let answer = binding.invoke(
        "vault.consolidation.extraction.observations.page",
        json!({
            "attempt": extraction_attempt_hex(attempt),
            "now_ms": 21_000,
            "candidates": [extraction_candidate(
                &subject.to_hex(), "profile.hobby", json!("tea"),
                &owner.turns[0].turn, serde_json::to_value(&owner.turns[0].version)?,
            )],
        }),
        None,
    )?;
    let candidates = answer["value"]["candidates"]
        .as_array()
        .expect("candidate facts");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["evidence_count"], json!(1));
    Ok(())
}

/// Verdict evidence rereads both ordinary TURNs and reaches the missing-lender refusal.
#[test]
fn verdict_evidence_reads_owner_pinned_ordinary_turns() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let owner = owner_inputs(&vault, attempt)?;
    assert_eq!(owner.turns.len(), 2);
    let turns = page_turns_with_versions(&serde_json::to_value(owner)?);
    let binding = bind_extraction(&vault, &admitted)?;
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [], "priors": [], "earlier": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
    });
    let error = invoke_bound_verdict(
        &binding,
        extraction_verdict_request("resolution", native_resolution_options(), pack),
    )
    .expect_err("checked evidence reaches the missing extraction loan");
    assert_eq!(error.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    Ok(())
}
