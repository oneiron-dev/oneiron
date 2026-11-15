//! One bound merged-value step over a rebuilt conflict set.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test merged_value_steps`.
#![cfg(oneiron_test_support)]

#[allow(dead_code)]
#[path = "extraction_steps/support.rs"]
mod step_support;
#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE};
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{
    ExtractionStepFixture, attach_extraction_step_lender, extraction_step_state_present,
    fixture_step_charge_binding_count, fixture_step_charge_units,
};
use oneiron::test_doors::extraction_verdict::dreamer_extraction_verdict_source_version;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, TimeRange, Vault};
use rmpv::Value as RmpValue;
use serde_json::json;
use std::sync::Arc;
use step_support::{CapturingStepBackend, invoke_bound_step, invoke_bound_step_receipt};
use verdict_support::{
    QUEUE_NOW, bind_extraction, extraction_attempt_hex, extraction_candidate,
    open_extraction_verdict_vault, page_turns_with_versions, read_bound_extraction_page,
};

/// Returns a fixture or assertion error without hiding its source.
type MergedValueStepTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Lands one Active Auto UserStated `preference.food` claim about `subject` with `value`.
fn land_user_stated_food_prior(
    vault: &Vault,
    subject: EntityId,
    value: &str,
) -> MergedValueStepTestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(id)
}

/// A merge over two sibling candidates answers the fake model's value in the receipt, and the
/// request the model saw is native's: the `resolution merge` line, the set predicate, and one
/// member line per candidate in order under fresh claim labels, with no keeps or head line.
#[test]
fn a_merge_over_two_siblings_answers_the_fake_value_in_natives_request()
-> MergedValueStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let reply = json!({"value": "tea and coffee"}).to_string();
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let request = json!({
        "resolution": "merge",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let submit = invoke_bound_step(&binding, request).expect("the merged-value step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(submit["result"]["memoized"], json!(false));
    assert_eq!(submit["result"]["json"], json!({"value": "tea and coffee"}));
    let claim_ref = submit["result"]["claim_ref"]
        .as_str()
        .expect("the finished step claims its record");
    assert!(!claim_ref.is_empty());
    let step_ref = submit["step_ref"]
        .as_str()
        .expect("the submit answers its step ref");
    assert_eq!(submit["step_hash"], json!(step_ref));
    assert_eq!(step_ref.len(), 64);
    assert_eq!(backend.call_count(), 1);
    let texts = backend.request_transcripts();
    assert_eq!(texts.len(), 1);
    let text = &texts[0];
    assert!(
        text.contains("resolution merge\n"),
        "the request renders native's resolution line: {text}"
    );
    assert!(
        text.contains("predicate profile.hobby\n"),
        "the request renders the set predicate: {text}"
    );
    assert!(
        !text.contains("keeps candidate_ref"),
        "no kept member renders no keeps line: {text}"
    );
    assert!(
        !text.contains("prior_head"),
        "no prior head renders no head line: {text}"
    );
    let first = text
        .find("- candidate_ref: C1 predicate: profile.hobby value: \"tea\"\n")
        .expect("the first member renders under the first label");
    let second = text
        .find("- candidate_ref: C2 predicate: profile.hobby value: \"coffee\"\n")
        .expect("the second member renders under the second label");
    assert!(first < second, "members render in order: {text}");
    Ok(())
}

/// `kept` puts the `keeps candidate_ref` line with that member's label: the kept member takes
/// the first label and both members still render in candidate order.
#[test]
fn kept_puts_the_keeps_line_with_that_members_label() -> MergedValueStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let reply = json!({"value": "coffee"}).to_string();
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let request = json!({
        "resolution": "merge",
        "kept": 1,
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let submit = invoke_bound_step(&binding, request).expect("the kept step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(submit["result"]["json"], json!({"value": "coffee"}));
    assert_eq!(backend.call_count(), 1);
    let texts = backend.request_transcripts();
    assert_eq!(texts.len(), 1);
    let text = &texts[0];
    assert!(
        text.contains("keeps candidate_ref C1\n"),
        "the kept member takes the first label: {text}"
    );
    let first = text
        .find("- candidate_ref: C2 predicate: profile.hobby value: \"tea\"\n")
        .expect("the first member renders under the second label");
    let second = text
        .find("- candidate_ref: C1 predicate: profile.hobby value: \"coffee\"\n")
        .expect("the kept member renders under the first label");
    assert!(first < second, "members render in order: {text}");
    Ok(())
}

/// A set with a stored head sends that head's line with its stored value under the first label,
/// while `priors` that differ from the set's heads are refused: an empty list and a doubled pin
/// each answer bad request with no second generation.
#[test]
fn a_stored_head_sends_its_line_and_differing_priors_are_refused() -> MergedValueStepTestResult<()>
{
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let prior = land_user_stated_food_prior(&vault, subject, "green tea")?;
    let witnessed =
        witness_extraction_turns(&vault, &["owen drinks black tea", "owen drinks oolong tea"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let pin = dreamer_extraction_verdict_source_version(&vault, prior)?
        .unwrap_or_else(|| panic!("the Dreamer reads the prior head"));
    let pin = serde_json::to_value(pin)?;
    let reply = json!({"value": "black tea"}).to_string();
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let candidates = json!([
        extraction_candidate(
            &subject.to_hex(),
            "preference.food",
            json!("black tea"),
            &turns[0].0,
            turns[0].1.clone()
        ),
        extraction_candidate(
            &subject.to_hex(),
            "preference.food",
            json!("oolong tea"),
            &turns[1].0,
            turns[1].1.clone()
        ),
    ]);
    let headed = json!({
        "resolution": "merge",
        "candidates": candidates,
        "priors": [{"claim": prior.to_hex(), "version": pin.clone()}],
    });
    let submit = invoke_bound_step(&binding, headed).expect("the headed step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(submit["result"]["json"], json!({"value": "black tea"}));
    assert_eq!(backend.call_count(), 1);
    let texts = backend.request_transcripts();
    assert_eq!(texts.len(), 1);
    let text = &texts[0];
    assert!(
        text.contains("\"prior_head\":\"C1\""),
        "the stored head renders under the first label: {text}"
    );
    assert!(
        text.contains("green tea"),
        "the head line carries the stored value: {text}"
    );
    let head = text.find("prior_head").expect("the head line renders");
    let first = text
        .find("- candidate_ref: C2 predicate: preference.food value: \"black tea\"\n")
        .expect("the first member renders under the second label");
    let second = text
        .find("- candidate_ref: C3 predicate: preference.food value: \"oolong tea\"\n")
        .expect("the second member renders under the third label");
    assert!(
        head < first && first < second,
        "heads render before members: {text}"
    );
    let request = json!({
        "resolution": "merge",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "preference.food", json!("black tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "preference.food", json!("oolong tea"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let Err(emptied) = invoke_bound_step(&binding, request) else {
        panic!("priors that omit the set head are refused");
    };
    assert_eq!(emptied.code, MEMORY_CODE_BAD_REQUEST);
    let request = json!({
        "resolution": "merge",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "preference.food", json!("black tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "preference.food", json!("oolong tea"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [
            {"claim": prior.to_hex(), "version": pin.clone()},
            {"claim": prior.to_hex(), "version": pin},
        ],
    });
    let Err(doubled) = invoke_bound_step(&binding, request) else {
        panic!("priors that repeat the set head are refused");
    };
    assert_eq!(doubled.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(backend.call_count(), 1);
    Ok(())
}

/// A reply with no value answers `{"value": null}` as a finished step, and a second submit of
/// the same request answers it again with no second model call and no second charge.
#[test]
fn a_reply_with_no_value_answers_null_and_replays_it_without_a_second_call()
-> MergedValueStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let backend = Arc::new(CapturingStepBackend::new("{}".to_owned(), 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let request = json!({
        "resolution": "merge",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let submit = invoke_bound_step(&binding, request.clone()).expect("the valueless step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(submit["result"]["memoized"], json!(false));
    assert_eq!(submit["result"]["json"], json!({"value": null}));
    let again = invoke_bound_step(&binding, request).expect("the same submit replays its memo");
    assert_eq!(again["result"]["status"], json!("finished"));
    assert_eq!(again["result"]["memoized"], json!(true));
    assert_eq!(again["result"]["json"], json!({"value": null}));
    assert_eq!(again["step_ref"], submit["step_ref"]);
    assert_eq!(backend.call_count(), 1);
    assert_eq!(fixture_step_charge_units(&fixture), 150);
    assert_eq!(fixture_step_charge_binding_count(&fixture), 1);
    Ok(())
}

/// A `kept` index outside the set, candidates that are not one conflict, and a `resolution`
/// other than the two each answer bad request before the backend, with no durable state.
#[test]
fn bad_requests_for_an_outside_kept_index_a_non_conflict_and_another_resolution()
-> MergedValueStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let reply = json!({"value": "tea"}).to_string();
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let request = json!({
        "resolution": "merge",
        "kept": 7,
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let Err(outside) = invoke_bound_step(&binding, request) else {
        panic!("a kept index outside the set is refused");
    };
    assert_eq!(outside.code, MEMORY_CODE_BAD_REQUEST);
    assert!(
        outside.message.contains("kept index"),
        "the refusal names the kept index, not the request shape: {outside:?}"
    );
    let request = json!({
        "resolution": "merge",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let Err(single) = invoke_bound_step(&binding, request) else {
        panic!("candidates that are not one conflict are refused");
    };
    assert_eq!(single.code, MEMORY_CODE_BAD_REQUEST);
    let request = json!({
        "resolution": "accumulate",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let Err(other) = invoke_bound_step(&binding, request) else {
        panic!("a resolution other than the two is refused");
    };
    assert_eq!(other.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(backend.call_count(), 0);
    assert!(!extraction_step_state_present(&vault, id)?);
    Ok(())
}

/// Without a loan the merged-value submit refuses model unavailable with its park hint and no
/// generation.
#[test]
fn a_merged_value_step_without_a_loan_refuses_model_unavailable() -> MergedValueStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let reply = json!({"value": "tea and coffee"}).to_string();
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    fixture.lend_nothing();
    let request = json!({
        "resolution": "merge",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let Err(unlent) = invoke_bound_step(&binding, request) else {
        panic!("an unstaffed merged-value step refuses without a loan");
    };
    assert_eq!(unlent.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    assert_eq!(
        unlent.message.as_str(),
        "no extraction loan is lent to this attempt"
    );
    assert!(
        unlent
            .suggestions
            .iter()
            .any(|hint| hint.contains("parks until its host lends")),
        "the refusal carries its park hint: {unlent:?}"
    );
    assert_eq!(backend.call_count(), 0);
    Ok(())
}

/// The receipt read answers the saved step by its key: the finished receipt with its terminal
/// record, memoized, through the same receipt door as the extraction step.
#[test]
fn the_receipt_read_answers_the_saved_step_by_its_key() -> MergedValueStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let reply = json!({"value": "tea and coffee"}).to_string();
    let backend = Arc::new(CapturingStepBackend::new(reply, 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let request = json!({
        "resolution": "merge",
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", json!("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "priors": [],
    });
    let submit = invoke_bound_step(&binding, request).expect("the merged-value step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    let step_ref = submit["step_ref"]
        .as_str()
        .expect("the submit answers its step ref")
        .to_owned();
    let receipt =
        invoke_bound_step_receipt(&binding, &step_ref).expect("the receipt answers the step");
    let mut expected = submit.clone();
    expected["result"]["memoized"] = json!(true);
    expected["result"]["json"] = json!(null);
    assert_eq!(receipt, expected);
    assert_eq!(receipt["result"]["status"], json!("finished"));
    assert_eq!(receipt["progression"], json!("finished"));
    assert_eq!(backend.call_count(), 1);
    Ok(())
}
