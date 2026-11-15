//! Census L1-06 (ARCH-0028:137, "a float in a write's input can decode
//! differently when its receipt is read back. That step never closes"): a
//! resumed write meets its receipt when its input holds a float.
//!
//! A write's receipt keeps the input's JSON text. A resumed step reads that
//! text back and compares its identity with the live input's
//! (`code_run/dispatcher/agent_verb/receipts.rs`, `records_call`). Without
//! serde_json's `float_roundtrip`, 2.0030397744267762e-253 reads back as
//! 2.003039774426776e-253: the identities differ and the step fails with "a
//! resumed step changed a write it already made". The served binary had the
//! feature only through oneiron-server; the oneiron crate now asks for it.
//!
//! The door compares the recorded input with the live one and never runs the
//! verb, so the float sits in a field of its own.
//!
//! Red on main (the crate without the feature): the float test fails at its
//! meet assert, after its FIXTURE assert; the two controls pass. Green: 3
//! passed.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test write_receipt_float_input`.
#![cfg(oneiron_test_support)]

use oneiron::code_run::SelfAgentVerbCall;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::test_doors::code_run_write_identity::resumed_write_meets_its_receipt;

/// A float whose shortest JSON text the default parser reads back one unit
/// in the last place off (the value of the answer-side repro in
/// `engine_executor/tests/agent_verb_regressions.rs`).
const FLOAT_THAT_MOVES: f64 = 2.0030397744267762e-253;

fn task_create(input: serde_json::Value) -> SelfAgentVerbCall {
    SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input,
    }
}

#[test]
fn a_resumed_write_whose_input_holds_a_float_meets_its_receipt() {
    let text = serde_json::to_string(&FLOAT_THAT_MOVES).expect("FIXTURE: the float encodes");
    assert!(
        text.starts_with("2.0030397744267762"),
        "FIXTURE: the receipt keeps the float's 17 significant digits: {text}"
    );
    let call = task_create(serde_json::json!({
        "spec": "summarize the open notes",
        "label": null,
        "weight": FLOAT_THAT_MOVES,
    }));
    assert!(
        resumed_write_meets_its_receipt(&call, &call).expect("the bridge records the write"),
        "a resumed write whose input holds a float meets the receipt its first making kept"
    );
}

#[test]
fn a_resumed_write_whose_input_holds_no_float_meets_its_receipt() {
    let call = task_create(serde_json::json!({
        "spec": "summarize the open notes",
        "label": null,
        "weight": 3,
    }));
    assert!(
        resumed_write_meets_its_receipt(&call, &call).expect("the bridge records the write"),
        "a resumed write with the same input meets its receipt"
    );
}

#[test]
fn a_resumed_write_with_a_changed_input_does_not_meet_its_receipt() {
    let first = task_create(serde_json::json!({
        "spec": "summarize the open notes",
        "label": null,
    }));
    let again = task_create(serde_json::json!({
        "spec": "summarize the closed notes",
        "label": null,
    }));
    assert!(
        !resumed_write_meets_its_receipt(&first, &again).expect("the bridge records the write"),
        "a resumed write whose input changed does not meet the receipt of the first"
    );
}
