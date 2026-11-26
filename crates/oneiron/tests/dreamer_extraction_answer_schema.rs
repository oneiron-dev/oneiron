//! HOUSE-SCHEMA: the TURN extraction answer schema admits what the prompt's
//! contract describes and refuses what the engine's check refuses, and it
//! rides only on TURN extraction requests, as the own-server-only
//! `answer_schema` body field.
//! Reaches the engine through `oneiron::test_doors::dreamer_extraction_schema`,
//! built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use oneiron::llm::OWN_SERVER_ONLY_PARAM;
use oneiron::test_doors::dreamer_extraction_schema::{
    answer_schema, check_reply, note_params, turn_params,
};
use serde_json::{Value, json};

/// The shipped extraction prompt file, for its worked examples.
const PROMPT_JSON: &str =
    include_str!("../src/dreamer_consolidation/executor/extraction_prompt.json");

/// The compiled answer schema.
fn validator() -> jsonschema::Validator {
    jsonschema::validator_for(&answer_schema().expect("schema parses")).expect("schema compiles")
}

/// Both worked-example assistant texts from the prompt file.
fn worked_examples() -> Vec<Value> {
    let prompt: Value = serde_json::from_str(PROMPT_JSON).expect("prompt parses");
    prompt["examples"]
        .as_array()
        .expect("examples is an array")
        .iter()
        .map(|example| {
            let text = example["assistant"].as_str().expect("assistant is text");
            serde_json::from_str(text).expect("assistant is JSON")
        })
        .collect()
}

/// A reply is schema-valid and passes the engine's contract check.
fn assert_sound(reply: &Value) {
    assert!(validator().is_valid(reply), "schema admits: {reply}");
    check_reply(&reply.to_string()).expect("contract check passes");
}

/// A reply is refused by the schema.
fn assert_refused(reply: &Value) {
    assert!(!validator().is_valid(reply), "schema refuses: {reply}");
}

/// One minimal valid candidate.
fn candidate() -> Value {
    json!({
        "subject": "P1",
        "predicate": "placeholder.attribute",
        "value": "VALUE-TWO",
        "confidence": 0.95,
        "evidence_refs": [{"source": "T1", "quote": "my placeholder attribute is VALUE-TWO now"}],
    })
}

#[test]
fn turn_params_carry_the_answer_schema_listed_own_server_only() {
    let params = turn_params().expect("turn params");
    assert_eq!(
        params.get("answer_schema"),
        Some(&answer_schema().expect("schema")),
        "the sent schema equals the schema file"
    );
    // No wire schema: a provider set to `response_format = "none"` strips a
    // `response_format` field, and every rung would need JsonResponse for it.
    assert_eq!(params.get("response_format"), None);
    let own_only = params
        .get(OWN_SERVER_ONLY_PARAM)
        .and_then(Value::as_array)
        .expect("own-server-only list");
    assert!(
        own_only.iter().any(|name| name == "answer_schema"),
        "answer_schema is own-server-only: {own_only:?}"
    );
}

#[test]
fn note_params_carry_no_answer_schema() {
    let params = note_params().expect("note params");
    assert_eq!(params.get("answer_schema"), None);
    assert_eq!(params.get("response_format"), None);
}

#[test]
fn both_worked_examples_validate_against_the_answer_schema() {
    let examples = worked_examples();
    assert_eq!(examples.len(), 2, "the prompt ships two examples");
    for (index, reply) in examples.iter().enumerate() {
        assert!(
            validator().is_valid(reply),
            "example {index} validates: {reply}"
        );
    }
}

#[test]
fn schema_valid_empty_candidates_pass_the_contract_check() {
    assert_sound(&json!({"candidates": []}));
}

#[test]
fn schema_valid_claim_only_ref_passes_the_contract_check() {
    assert_sound(&json!({"candidates": [{
        "subject": "P1",
        "predicate": "placeholder.colour",
        "value": "VALUE-RED",
        "confidence": 0.9,
        "evidence_refs": [{"claim": "C2"}],
    }]}));
}

#[test]
fn schema_valid_persons_pass_the_contract_check() {
    assert_sound(&json!({
        "candidates": [{
            "subject": "new:P1",
            "predicate": "placeholder.collects",
            "value": "placeholder tokens",
            "confidence": 0.85,
            "evidence_refs": [{"source": "T4", "quote": "They collect placeholder tokens"}],
        }],
        "persons": [{
            "id": "new:P1",
            "name": "Placeholder Person E",
            "evidence_turn_refs": ["T4"],
        }],
    }));
}

#[test]
fn schema_valid_eight_max_length_cjk_queries_pass_the_contract_check() {
    let queries: Vec<Value> = (0..8)
        .map(|index: u32| Value::String(format!("{}{index:02}", "あ".repeat(62))))
        .collect();
    assert!(queries.iter().all(|query| {
        let text = query.as_str().expect("string");
        text.chars().count() == 64 && text.len() <= 256
    }));
    let mut first = candidate();
    first["prospective_queries"] = Value::Array(queries);
    assert_sound(&json!({"candidates": [first]}));
}

#[test]
fn schema_valid_256_byte_ascii_query_passes_the_contract_check() {
    let mut first = candidate();
    first["prospective_queries"] = json!(["q".repeat(256)]);
    assert_sound(&json!({"candidates": [first]}));
}

#[test]
fn schema_valid_japanese_queries_up_to_255_bytes_pass_the_contract_check() {
    // REVIEW-10538 round 2: 65 Japanese characters are 195 bytes, past the 64-character
    // branch yet inside the prompt's 256-byte limit; 85 are 255 bytes.
    for count in [65, 85] {
        let query = "あ".repeat(count);
        assert_eq!(query.len(), count * 3);
        let mut first = candidate();
        first["prospective_queries"] = json!([query]);
        assert_sound(&json!({"candidates": [first]}));
    }
}

#[test]
fn schema_refuses_86_japanese_characters_as_the_contract_check_does() {
    let mut first = candidate();
    first["prospective_queries"] = json!(["あ".repeat(86)]);
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(
        check_reply(&reply.to_string()).is_err(),
        "258 bytes is past the 256-byte limit"
    );
}

#[test]
fn schema_valid_128_cyrillic_characters_pass_the_contract_check() {
    let mut first = candidate();
    first["prospective_queries"] = json!(["д".repeat(128)]);
    assert_sound(&json!({"candidates": [first]}));
}

#[test]
fn schema_refuses_a_query_over_256_bytes() {
    let mut first = candidate();
    first["prospective_queries"] = json!(["q".repeat(257)]);
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_err());
}

#[test]
fn schema_valid_rel_and_topic_key_pass_the_contract_check() {
    let mut first = candidate();
    first["value"] = json!(7);
    first["rel"] = json!("R1");
    first["topic_key"] = json!("placeholder.count");
    assert_sound(&json!({"candidates": [first]}));
}

#[test]
fn schema_valid_mixed_value_types_pass_the_contract_check() {
    let values = vec![
        json!("text"),
        json!(7),
        json!(true),
        json!(["a", "b"]),
        json!({"k": "v"}),
    ];
    let candidates: Vec<Value> = values
        .into_iter()
        .map(|value| {
            let mut item = candidate();
            item["value"] = value;
            item
        })
        .collect();
    assert_sound(&json!({"candidates": candidates}));
}

#[test]
fn schema_refuses_a_null_value() {
    let mut first = candidate();
    first["value"] = Value::Null;
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_err());
}

#[test]
fn schema_refuses_confidence_above_one() {
    let mut first = candidate();
    first["confidence"] = json!(1.5);
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_err());
}

#[test]
fn schema_refuses_empty_evidence_refs() {
    let mut first = candidate();
    first["evidence_refs"] = json!([]);
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_err());
}

#[test]
fn schema_refuses_a_ref_with_both_source_and_claim() {
    let mut first = candidate();
    first["evidence_refs"] = json!([{"source": "T1", "quote": "words", "claim": "C1"}]);
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_err());
}

#[test]
fn schema_refuses_an_empty_quote() {
    let mut first = candidate();
    first["evidence_refs"] = json!([{"source": "T1", "quote": ""}]);
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_err());
}

#[test]
fn schema_refuses_a_person_with_no_evidence_turn_refs() {
    let reply = json!({
        "candidates": [],
        "persons": [{"id": "new:P1", "name": "E", "evidence_turn_refs": []}],
    });
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_err());
}

#[test]
fn schema_refuses_an_extra_top_level_key_the_contract_ignores() {
    // Tighter than the check: the engine's serde reply ignores unknown keys,
    // but the prompt never describes one, so the grammar refuses it.
    let reply = json!({"candidates": [], "extra": 1});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_ok());
}

#[test]
fn schema_refuses_a_claim_label_subject_the_decode_would_skip() {
    // Tighter than the check (any label parses there), matching decode, which
    // takes only a listed entity or a declared person as the subject.
    let mut first = candidate();
    first["subject"] = json!("C1");
    let reply = json!({"candidates": [first]});
    assert_refused(&reply);
    assert!(check_reply(&reply.to_string()).is_ok());
}

#[test]
fn schema_bounds_label_numbers_to_what_the_label_parser_reads() {
    // A label's number parses as a usize (call_labels.rs CallLabel::numbered). Nine digits
    // always fit, so the schema admits them. A longer number past usize would match an
    // unbounded pattern and fail the check (REVIEW-10538 P1-7), so every label stops at
    // nine digits, a bound no call's labels reach.
    let mut nine = candidate();
    nine["subject"] = json!("P999999999");
    nine["evidence_refs"] = json!([{"source": "T999999999", "quote": "Ada"}]);
    assert_sound(&json!({"candidates": [nine]}));
    let mut past = candidate();
    past["subject"] = json!("P18446744073709551616");
    let reply = json!({"candidates": [past]});
    assert_refused(&reply);
    assert!(
        check_reply(&reply.to_string()).is_err(),
        "the check refuses a label past usize"
    );
    let mut ten = candidate();
    ten["evidence_refs"] = json!([{"source": "T1000000000", "quote": "Ada"}]);
    assert_refused(&json!({"candidates": [ten]}));
}
