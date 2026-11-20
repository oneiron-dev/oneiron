//! These tests hold the run mode and model-free contract
//! (FIX [BROWSER-LIBRARY-PLAIN-FUNCTIONS-HELD-BY-NO-TEST]).
//! They build proofs and decisions from plain values, without a browser or a store.

use oneiron_browser::{
    BrowserEngine, LibraryRunMode, ReplayGuest, WorkflowProof, default_mode, effective_mode,
    model_free,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const FORM: &str = "https://shop.example/form";
const TITLE: &str = "Form";

/// A proof that held values out or not, with the given replay decisions.
fn proof(held_out: bool, replay_decisions: Vec<Value>) -> WorkflowProof {
    WorkflowProof {
        args: BTreeMap::new(),
        replay_args: BTreeMap::new(),
        held_out,
        seed: None,
        solved_url: FORM.to_owned(),
        solved_title: TITLE.to_owned(),
        replay_receipts: Vec::new(),
        replay_decisions,
        replay_url: FORM.to_owned(),
        replay_guest: ReplayGuest {
            engine: BrowserEngine::Chromium,
            carried: Vec::new(),
            not_carried: Vec::new(),
        },
    }
}

/// A strict denial that spent the given tokens.
fn strict_decision(tokens: u64) -> Value {
    json!({
        "strict_denied": {
            "denied": "rule_abstained",
            "question": "Does a rule answer?",
            "tokens": tokens,
        }
    })
}

/// A decision that holds a Fill writer call beside a ruled receipt.
fn writer_decision() -> Value {
    json!({
        "field_writer": {"role": "writer", "model": "writer", "usage": {}},
        "receipt": {"providers": [{"rung": "rule"}]},
    })
}

#[test]
fn an_asked_mode_wins_over_the_programs_default() {
    let plain = proof(false, vec![json!({"rung": "rule"})]);
    assert_eq!(
        effective_mode(Some(LibraryRunMode::Strict), &plain),
        LibraryRunMode::Strict
    );
    let strict = proof(true, vec![json!({"rung": "rule"})]);
    assert_eq!(
        effective_mode(Some(LibraryRunMode::Assisted), &strict),
        LibraryRunMode::Assisted
    );
}

#[test]
fn an_unasked_mode_uses_the_programs_default() {
    let strict = proof(true, vec![json!({"rung": "rule"})]);
    assert_eq!(effective_mode(None, &strict), LibraryRunMode::Strict);
    let assisted = proof(true, vec![json!({"rung": "big"})]);
    assert_eq!(effective_mode(None, &assisted), LibraryRunMode::Assisted);
}

#[test]
fn a_proof_that_held_values_out_and_took_no_decision_is_strict_by_default() {
    let held = proof(true, Vec::new());
    assert_eq!(default_mode(&held), LibraryRunMode::Strict);
}

#[test]
fn a_held_out_proof_whose_every_decision_a_rule_answered_is_strict_by_default() {
    let held = proof(true, vec![json!({"rung": "rule"}), json!({"rung": "rule"})]);
    assert_eq!(default_mode(&held), LibraryRunMode::Strict);
}

#[test]
fn a_proof_that_held_nothing_out_is_assisted_by_default_even_when_ruled() {
    let empty = proof(false, Vec::new());
    assert_eq!(default_mode(&empty), LibraryRunMode::Assisted);
    let ruled = proof(
        false,
        vec![json!({"rung": "rule"}), json!({"rung": "rule"})],
    );
    assert_eq!(default_mode(&ruled), LibraryRunMode::Assisted);
}

#[test]
fn one_decision_a_rule_did_not_answer_makes_the_proof_assisted_by_default() {
    let another = proof(true, vec![json!({"rung": "rule"}), json!({"rung": "big"})]);
    assert_eq!(default_mode(&another), LibraryRunMode::Assisted);
    let missing = proof(true, vec![json!({"rung": "rule"}), json!({})]);
    assert_eq!(default_mode(&missing), LibraryRunMode::Assisted);
}

#[test]
fn no_decision_is_model_free() {
    assert_eq!(model_free(&[]), Ok(true));
}

#[test]
fn a_rule_or_human_answer_with_rule_or_human_providers_is_model_free() {
    let rule = json!({
        "receipt": {"providers": [{"rung": "rule"}, {"rung": "human"}]},
        "rung": "rule",
    });
    assert_eq!(model_free(&[rule]), Ok(true));
    let human = json!({
        "receipt": {"providers": [{"rung": "human"}]},
        "rung": "human",
    });
    assert_eq!(model_free(&[human]), Ok(true));
}

#[test]
fn a_model_rung_among_receipt_providers_is_not_model_free() {
    let absent = json!({"receipt": {"providers": [{"rung": "rule"}, {"rung": "big"}]}});
    assert_eq!(model_free(&[absent]), Ok(false));
    let null = json!({"receipt": {"providers": [{"rung": "big"}]}, "rung": null});
    assert_eq!(model_free(&[null]), Ok(false));
}

#[test]
fn a_model_rung_in_a_paired_person_or_image_reading_is_not_model_free() {
    let paired = json!({
        "receipt": {
            "providers": [{"rung": "rule"}],
            "paired": [{"provider": {"rung": "big"}}],
        }
    });
    assert_eq!(model_free(&[paired]), Ok(false));
    let person = json!({
        "receipt": {
            "providers": [{"rung": "rule"}],
            "person": [{"provider": {"rung": "big"}}],
        }
    });
    assert_eq!(model_free(&[person]), Ok(false));
    let images = json!({
        "receipt": {
            "providers": [{"rung": "rule"}],
            "images": [{"provider": {"rung": "big"}}],
        }
    });
    assert_eq!(model_free(&[images]), Ok(false));
}

#[test]
fn a_model_rung_in_time_answered_is_not_model_free() {
    let rule = json!({
        "receipt": {"providers": [{"rung": "rule"}], "time": {"answered": "rule"}}
    });
    assert_eq!(model_free(&[rule]), Ok(true));
    let model = json!({
        "receipt": {"providers": [{"rung": "rule"}], "time": {"answered": "big"}}
    });
    assert_eq!(model_free(&[model]), Ok(false));
}

#[test]
fn a_model_rung_in_the_presence_receipt_is_not_model_free() {
    let rule = json!({
        "receipt": {"providers": [{"rung": "rule"}]},
        "presence": {"receipt": {"providers": [{"rung": "rule"}]}},
    });
    assert_eq!(model_free(&[rule]), Ok(true));
    let model = json!({
        "receipt": {"providers": [{"rung": "rule"}]},
        "presence": {"receipt": {"providers": [{"rung": "big"}]}},
    });
    assert_eq!(model_free(&[model]), Ok(false));
}

#[test]
fn a_strict_denial_at_zero_tokens_is_model_free_and_a_spent_one_is_unproven() {
    assert_eq!(model_free(&[strict_decision(0)]), Ok(true));
    assert_eq!(model_free(&[strict_decision(5)]), Err(0));
}

#[test]
fn a_decision_holding_a_fill_writer_call_is_not_model_free() {
    assert_eq!(model_free(&[writer_decision()]), Ok(false));
}

#[test]
fn a_decision_without_receipt_providers_or_rung_is_unproven_even_after_a_model() {
    let no_receipt = json!({"rung": "rule"});
    assert_eq!(model_free(&[no_receipt]), Err(0));
    let no_providers = json!({"receipt": {}});
    assert_eq!(model_free(&[no_providers]), Err(0));
    let no_rung = json!({"receipt": {"providers": [{}]}});
    assert_eq!(model_free(&[no_rung]), Err(0));
    let model = json!({"receipt": {"providers": [{"rung": "big"}]}});
    let unproven = json!({"receipt": {}});
    assert_eq!(model_free(&[model, unproven]), Err(1));
}
