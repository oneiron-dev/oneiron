//! Tests for the replay held-out check (FIX [BROWSER-LIBRARY-PLAIN-FUNCTIONS-HELD-BY-NO-TEST]).
//! They hold `validate_replay_args`: when replay arguments hold values out
//! from the solved run's, and what a refusal names.

use oneiron_browser::{
    AdmissionRefusal, BatchStep, ExpectInput, WorkflowProgram, validate_replay_args,
};
use std::collections::BTreeMap;

/// A program whose steps and checks use the slots `item` and `query`.
fn program() -> WorkflowProgram {
    WorkflowProgram {
        subgoal: "Find an item".to_owned(),
        params: vec!["extra".to_owned(), "item".to_owned(), "query".to_owned()],
        secret_params: vec![],
        steps: vec![
            BatchStep::Open {
                url: "https://shop.example/items/{{item}}".to_owned(),
            },
            BatchStep::Type {
                target: "e-search".to_owned(),
                text: Some("find {{query}}".to_owned()),
                secret: None,
                clear: false,
            },
        ],
        postcondition: vec![ExpectInput {
            role: Some("heading".to_owned()),
            name: Some("Shows {{query}}".to_owned()),
            value: Some("{{item}} in stock".to_owned()),
            ..Default::default()
        }],
    }
}

/// A program whose slots repeat across steps and checks, one with spaces inside its braces.
fn scattered_program() -> WorkflowProgram {
    WorkflowProgram {
        subgoal: "Read two notes".to_owned(),
        params: vec!["alpha".to_owned(), "mid".to_owned(), "zeta".to_owned()],
        secret_params: vec![],
        steps: vec![
            BatchStep::Open {
                url: "https://shop.example/{{zeta}}/again-{{ zeta }}".to_owned(),
            },
            BatchStep::Type {
                target: "e-note".to_owned(),
                text: Some("{{ alpha }} meets {{zeta}}".to_owned()),
                secret: None,
                clear: false,
            },
        ],
        postcondition: vec![ExpectInput {
            role: Some("heading".to_owned()),
            name: Some("{{mid}} greets {{alpha}}".to_owned()),
            ..Default::default()
        }],
    }
}

/// The solved run's arguments: values for both used slots and one unused parameter.
fn args() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("extra".to_owned(), "1".to_owned()),
        ("item".to_owned(), "lamp".to_owned()),
        ("query".to_owned(), "red".to_owned()),
    ])
}

/// The held-out refusal with these four lists.
fn held_out(used: &[&str], missing: &[&str], unknown: &[&str], same: &[&str]) -> AdmissionRefusal {
    let owned = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
    AdmissionRefusal::HeldOut {
        used: owned(used),
        missing: owned(missing),
        unknown: owned(unknown),
        same: owned(same),
    }
}

#[test]
fn no_replay_arguments_hold_nothing_out() {
    let got = validate_replay_args(&program(), &args(), &BTreeMap::new());
    assert_eq!(got, Ok(false));
}

#[test]
fn replay_arguments_with_another_value_for_one_used_slot_hold_out() {
    let mut replay = args();
    replay.insert("item".to_owned(), "chair".to_owned());
    let got = validate_replay_args(&program(), &args(), &replay);
    assert_eq!(got, Ok(true));
}

#[test]
fn replay_arguments_equal_to_the_solved_runs_are_refused() {
    let args = args();
    let got = validate_replay_args(&program(), &args, &args);
    assert_eq!(
        got,
        Err(held_out(&["item", "query"], &[], &[], &["item", "query"]))
    );
}

#[test]
fn a_difference_only_in_an_unused_parameter_holds_nothing_out() {
    let mut replay = args();
    replay.insert("extra".to_owned(), "2".to_owned());
    let got = validate_replay_args(&program(), &args(), &replay);
    assert_eq!(
        got,
        Err(held_out(&["item", "query"], &[], &[], &["item", "query"]))
    );
}

#[test]
fn missing_and_unknown_names_are_listed_in_name_order() {
    let replay = BTreeMap::from([
        ("alpha".to_owned(), "1".to_owned()),
        ("item".to_owned(), "lamp".to_owned()),
        ("zeta".to_owned(), "2".to_owned()),
    ]);
    let got = validate_replay_args(&program(), &args(), &replay);
    assert_eq!(
        got,
        Err(held_out(
            &["item", "query"],
            &["extra", "query"],
            &["alpha", "zeta"],
            &["item"]
        ))
    );
}

#[test]
fn a_missing_name_refuses_even_when_a_used_slot_differs() {
    let replay = BTreeMap::from([
        ("item".to_owned(), "chair".to_owned()),
        ("query".to_owned(), "red".to_owned()),
    ]);
    let got = validate_replay_args(&program(), &args(), &replay);
    assert_eq!(
        got,
        Err(held_out(&["item", "query"], &["extra"], &[], &["query"]))
    );
}

#[test]
fn used_names_step_and_check_slots_once_in_name_order_trimmed() {
    let args = BTreeMap::from([
        ("alpha".to_owned(), "1".to_owned()),
        ("mid".to_owned(), "2".to_owned()),
        ("zeta".to_owned(), "3".to_owned()),
    ]);
    let mut replay = args.clone();
    replay.insert("spare".to_owned(), "9".to_owned());
    let got = validate_replay_args(&scattered_program(), &args, &replay);
    assert_eq!(
        got,
        Err(held_out(
            &["alpha", "mid", "zeta"],
            &[],
            &["spare"],
            &["alpha", "mid", "zeta"]
        ))
    );
}
