//! Bound Extraction read layout refusals carry the rebuilt pages as a typed field.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_read_layout`.
#![cfg(oneiron_test_support)]

#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError};
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_verdict::{
    ExtractionVerdictFixture, attach_extraction_verdict_lender,
    dreamer_extraction_verdict_source_version, fixture_charge_binding_count, fixture_charge_units,
    land_extraction_verdict_listing_claim,
};
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, TimeRange, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::sync::Arc;
use verdict_support::{
    ExtractionVerdictTestResult, ParityReasoner, QUEUE_NOW, bind_extraction,
    extraction_attempt_hex, extraction_candidate, extraction_verdict_request, invoke_bound_verdict,
    native_resolution_options, open_extraction_verdict_vault, page_turns_with_versions,
    read_bound_extraction_page,
};

/// Builds an exactly 50,000-character value, the size the verdict tests use to force native paging.
fn big_candidate_value(prefix: &str) -> Value {
    json!(prefix.chars().cycle().take(50_000).collect::<String>())
}

/// Builds a pack reply the lender never reads: the layout refusal answers before any generation is
/// served.
fn unasked_pack_reply() -> String {
    json!({"Q1": {"merge": 1.0}}).to_string()
}

/// Reads the typed layout refusal field of `refused` as JSON, so this file compiles before the
/// read-layout variants exist.
fn refusal_layout_json(refused: &MemoryError) -> ExtractionVerdictTestResult<Value> {
    Ok(serde_json::to_value(refused)?["extraction_layout"].clone())
}

/// Lands the listing-claim fixture, enlarges its value and adds a second correctable claim.
/// Both stored values contain exactly 50,000 characters and share one learned clock, so the
/// native newest-first listing breaks the tie by ascending claim identifier.
fn land_two_big_listing_claims(
    vault: &Vault,
) -> ExtractionVerdictTestResult<(EntityId, EntityId, EntityId)> {
    let (subject, first) = land_extraction_verdict_listing_claim(vault)?;
    let mut body = vault
        .get_claim(&first)?
        .unwrap_or_else(|| panic!("the listing fixture landed its claim"));
    body.value = RmpValue::from("owen".chars().cycle().take(50_000).collect::<String>());
    let now = vault.now_recorded_at();
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    vault.put_claim(&first, &body, occurred, now)?;
    let second = EntityId::now();
    body.predicate = "profile.hobby".to_owned();
    body.value = RmpValue::from("yuki".chars().cycle().take(50_000).collect::<String>());
    vault.put_claim(&second, &body, occurred, now)?;
    let mut listed = [first, second];
    listed.sort();
    Ok((subject, listed[0], listed[1]))
}

/// A Resolution Whole over two 50,000-character candidates is refused with the rebuilt resolution
/// pages before any loan or charge: bad request with `[[0], [1]]` in the typed field, no backend
/// call, and the fixture's charge counters unchanged.
#[test]
fn a_resolution_whole_over_two_pages_refuses_with_its_layout() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let page_binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&page_binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 2);
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", big_candidate_value("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", big_candidate_value("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution"], "options": native_resolution_options()},
            {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
        ],
        "earlier": [],
    });
    let reasoner = Arc::new(ParityReasoner::new(unasked_pack_reply(), 100, 50));
    let fixture = ExtractionVerdictFixture::new(reasoner.clone())?;
    let binding = attach_extraction_verdict_lender(bind_extraction(&vault, &admitted)?, &fixture);
    let charges_before = (
        fixture_charge_units(&fixture),
        fixture_charge_binding_count(&fixture),
    );
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(refused) = invoke_bound_verdict(&binding, request) else {
        panic!("a whole over two pages refuses");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(
        refusal_layout_json(&refused)?,
        json!({"kind": "resolution_pages", "pages": [[0], [1]]}),
    );
    assert_eq!(reasoner.call_count(), 0);
    assert_eq!(
        (
            fixture_charge_units(&fixture),
            fixture_charge_binding_count(&fixture)
        ),
        charges_before,
    );
    Ok(())
}

/// The same pack's first native page passes the layout check and waits on its loan: model
/// unavailable with no lender. This control stays green before the typed field exists.
#[test]
fn a_matching_resolution_page_waits_on_its_loan() -> ExtractionVerdictTestResult<()> {
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
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "page", "page": 0, "pages": 2},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", big_candidate_value("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", big_candidate_value("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution", "page", "0"], "options": native_resolution_options()},
            {"key": ["identity", "0", "page", "0"], "options": ["none", "candidate:0"]},
        ],
        "earlier": [],
    });
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(unlent) = invoke_bound_verdict(&binding, request) else {
        panic!("a matching page without a loan waits on it");
    };
    assert_eq!(unlent.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    Ok(())
}

/// The same pack with a wrong page count is refused with the rebuilt resolution pages: bad request
/// with `[[0], [1]]` in the typed field. The count mismatches before any question is compared.
#[test]
fn a_miscounted_resolution_page_refuses_with_its_layout() -> ExtractionVerdictTestResult<()> {
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
    let pack = json!({
        "read": "resolution",
        "part": {"kind": "page", "page": 0, "pages": 3},
        "candidates": [
            extraction_candidate(&subject.to_hex(), "profile.hobby", big_candidate_value("tea"), &turns[0].0, turns[0].1.clone()),
            extraction_candidate(&subject.to_hex(), "profile.hobby", big_candidate_value("coffee"), &turns[1].0, turns[1].1.clone()),
        ],
        "listed": [],
        "priors": [],
        "questions": [
            {"key": ["resolution", "page", "0"], "options": native_resolution_options()},
            {"key": ["identity", "0", "page", "0"], "options": ["none", "candidate:0"]},
        ],
        "earlier": [],
    });
    let request = extraction_verdict_request("resolution", native_resolution_options(), pack);
    let Err(refused) = invoke_bound_verdict(&binding, request) else {
        panic!("a miscounted page refuses");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(
        refusal_layout_json(&refused)?,
        json!({"kind": "resolution_pages", "pages": [[0], [1]]}),
    );
    Ok(())
}

/// A Correction Whole over one candidate with two 50,000-character listed claims is refused with
/// the rebuilt correction pages, while the matching page passes to its loan: bad request with the
/// native pairs in the typed field, then model unavailable with no lender.
#[test]
fn a_correction_whole_over_two_pairs_refuses_with_its_layout() -> ExtractionVerdictTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_extraction_verdict_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let (subject, listed_zero, listed_one) = land_two_big_listing_claims(&vault)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_extraction(&vault, &admitted)?;
    let page = read_bound_extraction_page(&binding, &extraction_attempt_hex(id))?;
    let turns = page_turns_with_versions(&page);
    assert_eq!(turns.len(), 1);
    let zero_hex = listed_zero.to_hex();
    let one_hex = listed_one.to_hex();
    let pin_zero = dreamer_extraction_verdict_source_version(&vault, listed_zero)?
        .unwrap_or_else(|| panic!("the Dreamer reads the first listed claim"));
    let pin_zero = serde_json::to_value(pin_zero)?;
    let pin_one = dreamer_extraction_verdict_source_version(&vault, listed_one)?
        .unwrap_or_else(|| panic!("the Dreamer reads the second listed claim"));
    let pin_one = serde_json::to_value(pin_one)?;
    let candidate = extraction_candidate(
        &subject.to_hex(),
        "profile.name",
        json!("yuki"),
        &turns[0].0,
        turns[0].1.clone(),
    );
    let listed = json!([
        {"claim": zero_hex.clone(), "version": pin_zero},
        {"claim": one_hex.clone(), "version": pin_one},
    ]);
    let options = json!(["none", zero_hex.clone(), one_hex.clone()]);
    let whole = json!({
        "read": "correction",
        "part": {"kind": "whole"},
        "candidates": [candidate.clone()],
        "listed": listed.clone(),
        "priors": [],
        "questions": [{"key": ["0", "0"], "options": options.clone()}],
        "earlier": [],
    });
    let Err(refused) = invoke_bound_verdict(
        &binding,
        extraction_verdict_request("correction", options, whole),
    ) else {
        panic!("a whole over two pairs refuses");
    };
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST);
    let expected = json!({
        "kind": "correction_pages",
        "pages": [[{"candidate": 0, "listed": 0}], [{"candidate": 0, "listed": 1}]],
    });
    assert_eq!(refusal_layout_json(&refused)?, expected);
    let page_options = json!(["none", zero_hex.clone()]);
    let page_zero = json!({
        "read": "correction",
        "part": {"kind": "page", "page": 0, "pages": 2},
        "candidates": [candidate],
        "listed": listed,
        "priors": [],
        "questions": [{"key": ["0", "0", "page", "0"], "options": page_options.clone()}],
        "earlier": [],
    });
    let request = extraction_verdict_request("correction", page_options, page_zero);
    let Err(unlent) = invoke_bound_verdict(&binding, request) else {
        panic!("a matching correction page without a loan waits on it");
    };
    assert_eq!(unlent.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    Ok(())
}
