//! One bound generative extraction step over served TURN spans.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_steps`.
#![cfg(oneiron_test_support)]

mod support;

use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE,
    MEMORY_CODE_NOT_FOUND,
};
use oneiron::test_doors::derive::{narrow_steward_grant_to_project, source_version};
use oneiron::test_doors::dreamer_attempt_binding::{
    admit_conflict_settle_attempt, enqueue_conflict_settle_attempt, enqueue_strength_attempt,
};
use oneiron::test_doors::extraction_inputs::{
    append_extraction_turn_words, enqueue_admitted_extraction_attempt,
    settle_extraction_rows_in_project, witness_extraction_turns,
};
use oneiron::test_doors::extraction_steps::{
    ExtractionStepFixture, attach_extraction_step_lender, extraction_step_state_present,
    fixture_step_charge_binding_count, fixture_step_charge_units, fixture_step_spent_observations,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::{EdgeActorClass, EntityId};
use serde_json::json;
use std::sync::Arc;
use support::{
    CapturingStepBackend, ExtractionStepTestResult, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_step_evidence, extraction_step_request, invoke_bound_step,
    invoke_bound_step_receipt, open_extraction_step_vault, page_turns_with_versions,
    read_bound_extraction_page, step_plain_reply,
};

/// Two served refs, one with a byte range, run on the served words only: the submit finishes with
/// the scripted output and a claim ref, the backend saw one request holding the cited spans and no
/// uncited word, the bound receipt replays the same result, and the same submit again replays its
/// memo with no second generation and one terminal charge. A key the attempt never ran answers
/// not-found.
#[test]
fn a_bound_step_runs_on_served_words_and_replays_its_memo() -> ExtractionStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(
        &vault,
        &["owen likes tea", "owen likes coffee", "yuki likes tea"],
    )?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 3);
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let request = extraction_step_request(json!([
        extraction_step_evidence(&turns[0].0, turns[0].1.clone(), None),
        extraction_step_evidence(
            &turns[1].0,
            turns[1].1.clone(),
            Some(json!({"start": 11, "end": 17})),
        ),
    ]));
    let submit = invoke_bound_step(&binding, request.clone()).expect("the served step finishes");
    assert_eq!(submit["result"]["status"], json!("finished"));
    assert_eq!(submit["result"]["memoized"], json!(false));
    let claim_ref = submit["result"]["claim_ref"]
        .as_str()
        .expect("the finished step claims its record");
    assert!(!claim_ref.is_empty());
    let response = serde_json::to_string(&submit["result"]["response"])?;
    assert!(
        response.contains(&step_plain_reply()),
        "the finished step answers its scripted output: {response}"
    );
    let step_ref = submit["step_ref"]
        .as_str()
        .expect("the submit answers its step ref");
    assert_eq!(submit["step_hash"], json!(step_ref));
    assert_eq!(step_ref.len(), 64);
    assert!(
        step_ref
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "the step ref is the lowercase request hash: {step_ref}"
    );
    assert!(submit.get("retry").is_some());
    assert_eq!(backend.call_count(), 1);
    let texts = backend.request_texts();
    assert_eq!(texts.len(), 1);
    assert!(
        texts[0].contains("owen likes tea"),
        "the cited whole words render: {}",
        texts[0]
    );
    assert!(
        texts[0].contains("coffee"),
        "the cited range renders: {}",
        texts[0]
    );
    assert!(
        !texts[0].contains("yuki likes tea"),
        "uncited words never render: {}",
        texts[0]
    );
    assert!(extraction_step_state_present(&vault, id)?);
    let receipt =
        invoke_bound_step_receipt(&binding, step_ref).expect("the bound receipt replays the step");
    let mut expected = submit.clone();
    expected["result"]["memoized"] = json!(true);
    assert_eq!(receipt, expected);
    assert_eq!(receipt["progression"], json!("finished"));
    let unknown_key = if step_ref == "0".repeat(64) {
        "f".repeat(64)
    } else {
        "0".repeat(64)
    };
    let Err(unknown) = invoke_bound_step_receipt(&binding, &unknown_key) else {
        panic!("a key the attempt never ran answers not-found");
    };
    assert_eq!(unknown.code, MEMORY_CODE_NOT_FOUND);
    let again = invoke_bound_step(&binding, request).expect("the same submit replays its memo");
    assert_eq!(again, expected);
    assert_eq!(backend.call_count(), 1);
    assert_eq!(backend.request_texts().len(), 1);
    let spent = fixture_step_spent_observations(&fixture);
    assert_eq!(spent.len(), 2);
    assert!(!spent[0].memoized);
    assert!(spent[1].memoized);
    assert_eq!(spent[0].request_hash_hex, spent[1].request_hash_hex);
    assert_eq!(spent[0].step_hash_hex, spent[1].step_hash_hex);
    assert!(spent[0].step_hash_hex.is_some());
    assert_eq!(spent[0].attempt_hex, spent[1].attempt_hex);
    for observation in &spent {
        assert_eq!(observation.input_total, 100);
        assert_eq!(observation.output_total, 50);
    }
    assert_eq!(fixture_step_charge_units(&fixture), 150);
    assert_eq!(fixture_step_charge_binding_count(&fixture), 1);
    Ok(())
}

/// A private TURN, a moved version and an unknown field are each refused before the backend: the
/// unserved row answers forbidden below the facet allow-list, the stale pin answers source moved,
/// and the unknown field answers bad request, with no generation and no durable state after all three.
#[test]
fn a_bound_step_refuses_unserved_inputs_before_the_backend() -> ExtractionStepTestResult<()> {
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let outside_dir = tempfile::tempdir()?;
    let outside_vault = Arc::new(open_extraction_step_vault(&outside_dir)?);
    let actor = dreamer(&outside_vault)?;
    let witnessed =
        witness_extraction_turns(&outside_vault, &["owen likes tea", "yuki likes tea"])?;
    let outside = witnessed.turns[1];
    let project = EntityId::now();
    settle_extraction_rows_in_project(&outside_vault, &[outside, witnessed.messages[1]], project)?;
    let grant = stand_steward_grant(&outside_vault, actor, &STEWARD_VERBS)?;
    narrow_steward_grant_to_project(&outside_vault, grant, oneiron::claim::default_project_id())?;
    let (outside_id, outside_admitted) =
        enqueue_admitted_extraction_attempt(&outside_vault, &witnessed.turns, QUEUE_NOW)?;
    let outside_binding = attach_extraction_step_lender(
        bind_extraction(&outside_vault, &outside_admitted)?,
        &fixture,
    );
    let page = read_bound_extraction_page(&outside_binding, &extraction_attempt_hex(outside_id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let owner = outside_vault.ensure_embedded_owner_actor()?;
    let unserved = source_version(&outside_vault, owner, EdgeActorClass::Human, outside)?
        .unwrap_or_else(|| panic!("the owner reads the outside turn"));
    let unserved = serde_json::to_value(unserved)?;
    let request = extraction_step_request(json!([
        extraction_step_evidence(&turns[0].0, turns[0].1.clone(), None),
        extraction_step_evidence(&outside.to_hex(), unserved, None),
    ]));
    let Err(withheld) = invoke_bound_step(&outside_binding, request) else {
        panic!("an unserved turn is refused");
    };
    assert_eq!(withheld.code, MEMORY_CODE_FORBIDDEN);
    assert!(
        !withheld.message.contains("facet does not admit"),
        "an unserved row refuses below the facet allow list: {withheld:?}"
    );
    let moved_dir = tempfile::tempdir()?;
    let moved_vault = Arc::new(open_extraction_step_vault(&moved_dir)?);
    let actor = dreamer(&moved_vault)?;
    stand_steward_grant(&moved_vault, actor, &STEWARD_VERBS)?;
    let witnessed =
        witness_extraction_turns(&moved_vault, &["owen likes tea", "owen likes coffee"])?;
    let (moved_id, moved_admitted) =
        enqueue_admitted_extraction_attempt(&moved_vault, &witnessed.turns, QUEUE_NOW)?;
    let moved_binding =
        attach_extraction_step_lender(bind_extraction(&moved_vault, &moved_admitted)?, &fixture);
    let page = read_bound_extraction_page(&moved_binding, &extraction_attempt_hex(moved_id))?;
    let turns = page_turns_with_versions(&page);
    append_extraction_turn_words(
        &moved_vault,
        witnessed.conversation,
        witnessed.turns[0],
        "and yuki joins owen",
    )?;
    let stale = extraction_step_request(json!([
        extraction_step_evidence(&turns[0].0, turns[0].1.clone(), None),
        extraction_step_evidence(&turns[1].0, turns[1].1.clone(), None),
    ]));
    let Err(moved) = invoke_bound_step(&moved_binding, stale) else {
        panic!("a moved pin is refused");
    };
    assert_eq!(moved.code, MEMORY_CODE_FORBIDDEN);
    let denial = moved
        .gate_denial
        .as_ref()
        .unwrap_or_else(|| panic!("a moved pin carries its gate denial"));
    assert!(
        denial
            .reason_codes
            .contains(&oneiron::derive::SOURCE_MOVED.to_owned())
    );
    let Err(unknown) = invoke_bound_step(&moved_binding, json!({"evidence": [], "messages": []}))
    else {
        panic!("an unknown field is refused");
    };
    assert_eq!(unknown.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(backend.call_count(), 0);
    assert!(backend.request_texts().is_empty());
    assert!(!extraction_step_state_present(&outside_vault, outside_id)?);
    assert!(!extraction_step_state_present(&moved_vault, moved_id)?);
    Ok(())
}

/// Without a loan the bound submit refuses model unavailable with its park hint and no new
/// generation, while the receipt of the earlier finished step still answers without a loan.
#[test]
fn a_bound_step_without_a_loan_refuses() -> ExtractionStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let backend = Arc::new(CapturingStepBackend::new(step_plain_reply(), 100, 50));
    let fixture = ExtractionStepFixture::new(backend.clone())?;
    let binding = attach_extraction_step_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let request = extraction_step_request(json!([
        extraction_step_evidence(&turns[0].0, turns[0].1.clone(), None),
        extraction_step_evidence(&turns[1].0, turns[1].1.clone(), None),
    ]));
    let submit = invoke_bound_step(&binding, request.clone()).expect("the lent step finishes");
    let step_ref = submit["step_ref"]
        .as_str()
        .expect("the submit answers its step ref")
        .to_owned();
    assert_eq!(backend.call_count(), 1);
    fixture.lend_nothing();
    let Err(unlent) = invoke_bound_step(&binding, request) else {
        panic!("an unstaffed step refuses without a loan");
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
    assert_eq!(backend.call_count(), 1);
    let receipt =
        invoke_bound_step_receipt(&binding, &step_ref).expect("the receipt answers without a loan");
    let mut expected = submit.clone();
    expected["result"]["memoized"] = json!(true);
    assert_eq!(receipt, expected);
    assert_eq!(receipt["result"]["status"], json!("finished"));
    assert_eq!(receipt["progression"], json!("finished"));
    Ok(())
}

/// Strength and conflict-settlement bindings refuse both step verbs below any check: each answers
/// forbidden naming its own facet.
#[test]
fn other_facets_refuse_the_step_verbs() -> ExtractionStepTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_step_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (extraction_id, _) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let strength_admitted = enqueue_strength_attempt(&vault, extraction_id, QUEUE_NOW)?;
    let strength = vault.bind_dreamer_attempt(&strength_admitted)?;
    enqueue_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    let settle_admitted = admit_conflict_settle_attempt(&vault, QUEUE_NOW)?;
    let settle = vault.bind_dreamer_attempt(&settle_admitted)?;
    let receipt_key = "0".repeat(64);
    for (binding, facet) in [
        (&strength, "strength facet does not admit"),
        (&settle, "conflict settlement facet does not admit"),
    ] {
        let Err(submit) = invoke_bound_step(binding, json!({"evidence": []})) else {
            panic!("{facet} admits no step submit");
        };
        assert_eq!(submit.code, MEMORY_CODE_FORBIDDEN);
        assert!(
            submit.message.contains(facet),
            "unexpected refusal: {submit:?}"
        );
        let Err(receipt) = invoke_bound_step_receipt(binding, &receipt_key) else {
            panic!("{facet} admits no step receipt");
        };
        assert_eq!(receipt.code, MEMORY_CODE_FORBIDDEN);
        assert!(
            receipt.message.contains(facet),
            "unexpected refusal: {receipt:?}"
        );
    }
    Ok(())
}
