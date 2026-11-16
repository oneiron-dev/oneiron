//! A repair leg's tool call is read by the input schema the leg declares
//! for each tool (census L1-20 PR D): an object whose only property is
//! `argument`. A call that breaks it (another property, no `argument`, or
//! no object) reads as no call, so a tool world never grades it as another
//! call. Before this, the measuring host kept the `argument` of a call with
//! other properties, and took a call with no `argument` whole.
//!
//! Run with: `cargo test --locked -p oneiron-verb-wire --all-features
//! --test eval_repair_tool_call`.

use oneiron_verb_wire::skill_optimize::eval_set::repair_task::EvalRepairToolCall;
use serde_json::json;

#[test]
fn a_call_with_only_its_argument_reads_as_that_call() {
    assert_eq!(
        EvalRepairToolCall::from_declared_input("set_city", &json!({ "argument": "Lyon" })),
        Some(EvalRepairToolCall {
            tool: "set_city".to_owned(),
            argument: json!("Lyon"),
        })
    );
    // Any JSON value is an argument, null included.
    assert_eq!(
        EvalRepairToolCall::from_declared_input("drop_note", &json!({ "argument": null })),
        Some(EvalRepairToolCall {
            tool: "drop_note".to_owned(),
            argument: json!(null),
        })
    );
}

#[test]
fn a_call_that_breaks_the_declared_schema_reads_as_no_call() {
    for input in [
        json!({ "argument": "Lyon", "unexpected": true }),
        json!({ "city": "Lyon" }),
        json!({}),
        json!("Lyon"),
        json!(["Lyon"]),
        json!(null),
    ] {
        assert_eq!(
            EvalRepairToolCall::from_declared_input("set_city", &input),
            None,
            "{input} breaks the declared schema"
        );
    }
}

#[test]
fn the_declared_schema_allows_only_the_argument() {
    let schema = EvalRepairToolCall::declared_input_schema();
    assert_eq!(schema["type"], json!("object"));
    assert_eq!(schema["required"], json!(["argument"]));
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]
            .as_object()
            .map(|properties| properties.keys().cloned().collect::<Vec<_>>()),
        Some(vec!["argument".to_owned()])
    );
}
