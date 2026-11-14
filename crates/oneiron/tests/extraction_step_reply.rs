//! Checks bound extraction replies without changing native extraction jobs.
#![cfg(oneiron_test_support)]

#[path = "extraction_steps/support.rs"]
mod support;

use std::sync::Arc;

use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{
    ExtractionStepFixture, attach_extraction_step_lender, fixture_step_charge_binding_count,
    fixture_step_charge_units, fixture_step_spent_observations,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use serde_json::{Value, json};
use support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    invoke_bound_step_receipt, open_extraction_step_vault, page_turns_with_versions,
    read_bound_extraction_page, step_plain_reply,
};

/// Keeps the vault directory alive with its binding, scripted backend and charge observations.
struct ReplyStepFixture {
    /// Owns the temporary directory for the lifetime of the bound attempt.
    _directory: tempfile::TempDir,
    /// Holds the live extraction binding with its loan attached.
    binding: DreamerAttemptBinding,
    /// Holds the source TURN and pinned version read through the inputs page.
    turns: Vec<(String, Value)>,
    /// Captures the generations and requests that actually reached the scripted backend.
    backend: Arc<CapturingStepBackend>,
    /// Holds the borrowed native charge tally.
    charges: Arc<ExtractionStepFixture>,
}

/// Prepares a bound attempt over one TURN with replies in generation order.
fn reply_step_fixture(
    words: &str,
    replies: Vec<String>,
) -> ExtractionStepTestResult<ReplyStepFixture> {
    let directory = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&directory)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &[words])?;
    let (attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(attempt))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let backend = Arc::new(match replies.as_slice() {
        [reply] => CapturingStepBackend::new(reply.clone(), 100, 50),
        _ => CapturingStepBackend::scripted(replies, 100, 50),
    });
    let charges = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(binding, &charges);
    Ok(ReplyStepFixture {
        _directory: directory,
        binding,
        turns,
        backend,
        charges,
    })
}

/// A declaration survives without minting, and a quote's range includes the served start.
#[test]
fn a_valid_bound_reply_decodes() -> ExtractionStepTestResult<()> {
    let fixture = reply_step_fixture("before owen likes tea after", vec![step_plain_reply()])?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        Some(json!({"start": 7, "end": 21}))
    ),]));
    let submit = invoke_bound_step(&fixture.binding, request.clone())?;
    assert_eq!(submit["result"]["status"], json!("finished"));
    let decoded = &submit["result"]["json"];
    assert_eq!(
        decoded["persons"],
        json!([{"declared": 1, "name": "owen", "turns": [turn]}])
    );
    assert_eq!(decoded["candidates"][0]["subject"], json!({"declared": 1}));
    assert_eq!(decoded["candidates"][0]["index"], json!(0));
    assert_eq!(decoded["candidates"][0]["predicate"], json!("likes"));
    assert_eq!(decoded["candidates"][0]["value"], json!("tea"));
    assert_eq!(
        decoded["candidates"][0]["evidence"],
        json!([{
            "turn": turn, "version": version, "span": {"start": 7, "end": 21},
        }])
    );
    assert_eq!(decoded["skipped"], json!([]));
    let step_ref = submit["step_ref"]
        .as_str()
        .ok_or("the submit has a step reference")?;
    let receipt = invoke_bound_step_receipt(&fixture.binding, step_ref)?;
    assert!(receipt["result"]["json"].is_null());
    let again = invoke_bound_step(&fixture.binding, request)?;
    assert_eq!(again["result"]["json"], *decoded);
    assert_eq!(again["result"]["memoized"], json!(true));
    assert_eq!(fixture.backend.call_count(), 1);
    let requests = fixture.backend.request_texts();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("owen likes tea"));
    assert!(!requests[0].contains("before owen"));
    assert!(!requests[0].contains("tea after"));
    Ok(())
}

/// A refused quote is paid once, a resubmit asks again, and only the valid reply is memoized.
#[test]
fn a_refused_reply_is_paid_and_a_resubmit_asks_again() -> ExtractionStepTestResult<()> {
    let bad = step_plain_reply().replace("owen likes tea", "owen likes coffee");
    let fixture = reply_step_fixture("owen likes tea", vec![bad, step_plain_reply()])?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]));
    let refused = invoke_bound_step(&fixture.binding, request.clone())?;
    assert_eq!(refused["result"]["status"], json!("failed"));
    assert!(
        refused["result"]["failure"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("cites outside its source"))
    );
    assert_eq!(fixture.backend.call_count(), 1);
    assert_eq!(
        refused["result"]["failure"]["validation_attempts"],
        json!(1)
    );
    assert_eq!(fixture_step_charge_units(&fixture.charges), 150);
    assert_eq!(fixture_step_charge_binding_count(&fixture.charges), 0);
    let spent = fixture_step_spent_observations(&fixture.charges);
    assert_eq!(spent.len(), 1);
    assert!(!spent[0].memoized);
    assert_eq!(spent[0].input_total, 100);
    assert_eq!(spent[0].output_total, 50);
    assert!(spent[0].step_hash_hex.is_none());
    let step_ref = refused["step_ref"]
        .as_str()
        .ok_or("the failed submit has a reference")?;
    let missing = invoke_bound_step_receipt(&fixture.binding, step_ref)
        .expect_err("a refused response has no terminal memo");
    assert_eq!(missing.code, oneiron::memory::MEMORY_CODE_NOT_FOUND);

    let accepted = invoke_bound_step(&fixture.binding, request.clone())?;
    assert_eq!(accepted["result"]["status"], json!("finished"));
    assert_eq!(accepted["result"]["memoized"], json!(false));
    assert_eq!(
        accepted["result"]["json"]["candidates"][0]["subject"],
        json!({"declared": 1})
    );
    assert_eq!(
        accepted["result"]["json"]["candidates"][0]["evidence"][0]["turn"],
        json!(turn)
    );
    assert_eq!(accepted["step_ref"], refused["step_ref"]);
    assert_eq!(fixture.backend.call_count(), 2);
    assert_eq!(fixture_step_charge_units(&fixture.charges), 300);
    assert_eq!(fixture_step_charge_binding_count(&fixture.charges), 1);
    let replayed = invoke_bound_step(&fixture.binding, request)?;
    assert_eq!(replayed["result"]["status"], json!("finished"));
    assert_eq!(replayed["result"]["memoized"], json!(true));
    assert_eq!(replayed["result"]["json"], accepted["result"]["json"]);
    assert_eq!(fixture.backend.call_count(), 2);
    assert_eq!(fixture_step_charge_units(&fixture.charges), 300);
    Ok(())
}

/// Non-JSON text fails paid without a terminal memo on each submit.
#[test]
fn a_non_json_reply_fails_once_per_submit() -> ExtractionStepTestResult<()> {
    let fixture = reply_step_fixture("owen likes tea", vec!["not JSON".to_owned()])?;
    let (turn, version) = &fixture.turns[0];
    let request = extraction_step_request(json!([extraction_step_evidence(
        turn,
        version.clone(),
        None
    ),]));
    let refused = invoke_bound_step(&fixture.binding, request.clone())?;
    assert_eq!(refused["result"]["status"], json!("failed"));
    assert_eq!(
        refused["result"]["failure"]["validation_attempts"],
        json!(1)
    );
    assert_eq!(fixture.backend.call_count(), 1);
    assert_eq!(fixture_step_charge_units(&fixture.charges), 150);
    assert_eq!(fixture_step_charge_binding_count(&fixture.charges), 0);
    let step_ref = refused["step_ref"]
        .as_str()
        .ok_or("the failed submit has a reference")?;
    assert!(invoke_bound_step_receipt(&fixture.binding, step_ref).is_err());
    let again = invoke_bound_step(&fixture.binding, request)?;
    assert_eq!(again["result"]["status"], json!("failed"));
    assert_eq!(again["result"]["failure"]["validation_attempts"], json!(1));
    assert_eq!(fixture.backend.call_count(), 2);
    assert_eq!(fixture_step_charge_units(&fixture.charges), 300);
    assert_eq!(fixture_step_charge_binding_count(&fixture.charges), 0);
    let spent = fixture_step_spent_observations(&fixture.charges);
    assert_eq!(spent.len(), 2);
    assert!(
        spent
            .iter()
            .all(|entry| !entry.memoized && entry.step_hash_hex.is_none())
    );
    assert!(invoke_bound_step_receipt(&fixture.binding, step_ref).is_err());
    Ok(())
}

/// Repeating a valid TURN refuses before any backend generation or charge.
#[test]
fn a_repeated_turn_refuses_before_generation() -> ExtractionStepTestResult<()> {
    let fixture = reply_step_fixture("owen likes tea", vec![step_plain_reply()])?;
    let (turn, version) = &fixture.turns[0];
    let evidence = extraction_step_evidence(turn, version.clone(), None);
    let request = extraction_step_request(json!([evidence.clone(), evidence]));
    let answer = invoke_bound_step(&fixture.binding, request);
    assert!(
        answer.is_err(),
        "a repeated TURN must refuse before generation"
    );
    let refused = answer.expect_err("the duplicate TURN was refused");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(refused.message, "an extraction step cites each TURN once");
    assert_eq!(fixture.backend.call_count(), 0);
    assert_eq!(fixture_step_charge_units(&fixture.charges), 0);
    assert!(fixture_step_spent_observations(&fixture.charges).is_empty());
    Ok(())
}
