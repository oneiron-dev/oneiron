//! FIX 22368: the Big rung's written reply (`reply = "json"` or `"lines"`,
//! the path without token scores) stores a yes/no's probability as P(yes), as
//! every other path does. The model writes how sure it is of its own answer,
//! so a "no, 0.9 sure" reply stores P(yes) = 0.1, and a "yes, 0.9 sure" reply
//! stores 0.9. Before the fix the no answer stored 0.9, a confident yes.
//!
//! Reaches the rung's own reply reader through `oneiron_server::test_doors`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --test big_rung_written_reply`.
#![cfg(oneiron_test_support)]

use oneiron::llm::decision::{AnswerContract, DecisionAnswer};
use oneiron_server::config::models::BigReply;
use oneiron_server::test_doors::big_rung::written_decision;

fn stored(reply: BigReply, contract: &AnswerContract, text: &str) -> (DecisionAnswer, f64) {
    written_decision(reply, contract, text).expect("the rung reads this reply")
}

fn assert_p(found: f64, expected: f64) {
    assert!(
        (found - expected).abs() < 1e-9,
        "stored probability {found}, expected {expected}"
    );
}

#[test]
fn json_no_answer_stores_p_yes_as_one_minus_sure() {
    let (answer, p) = stored(
        BigReply::Json,
        &AnswerContract::Noul,
        r#"{"answer": "no", "probability": 0.9}"#,
    );
    assert_eq!(answer, DecisionAnswer::Noul(false));
    assert_p(p, 0.1);
}

#[test]
fn json_yes_answer_stores_sure_as_p_yes() {
    let (answer, p) = stored(
        BigReply::Json,
        &AnswerContract::Noul,
        r#"{"answer": "yes", "probability": 0.9}"#,
    );
    assert_eq!(answer, DecisionAnswer::Noul(true));
    assert_p(p, 0.9);
}

#[test]
fn json_boolean_false_answer_stores_p_yes_as_one_minus_sure() {
    let (answer, p) = stored(
        BigReply::Json,
        &AnswerContract::Noul,
        r#"{"answer": false, "probability": 0.75}"#,
    );
    assert_eq!(answer, DecisionAnswer::Noul(false));
    assert_p(p, 0.25);
}

#[test]
fn lines_no_answer_stores_p_yes_as_one_minus_sure() {
    let (answer, p) = stored(
        BigReply::Lines,
        &AnswerContract::Noul,
        "answer: no\nprobability: 90%",
    );
    assert_eq!(answer, DecisionAnswer::Noul(false));
    assert_p(p, 0.1);
}

#[test]
fn lines_yes_answer_stores_sure_as_p_yes() {
    let (answer, p) = stored(
        BigReply::Lines,
        &AnswerContract::Noul,
        "answer: yes\nprobability: 0.9",
    );
    assert_eq!(answer, DecisionAnswer::Noul(true));
    assert_p(p, 0.9);
}

#[test]
fn choice_answer_keeps_the_probability_of_its_own_option() {
    let contract = AnswerContract::Choice {
        options: vec!["red".to_owned(), "blue".to_owned()],
    };
    let (answer, p) = stored(
        BigReply::Json,
        &contract,
        r#"{"answer": "blue", "probability": 0.7}"#,
    );
    assert_eq!(answer, DecisionAnswer::Choice("blue".to_owned()));
    assert_p(p, 0.7);
}

#[test]
fn reply_without_a_probability_abstains() {
    assert!(written_decision(BigReply::Lines, &AnswerContract::Noul, "answer: no").is_none());
}
