//! The parity bar compares relations and mood windows as it compares spans
//! and links (FIX ENGINE-PARITY-IGNORES-RELATIONS): an engine that reads
//! another relation or window does not clear. An engine with no relation
//! head (every in-process engine today; its card says so) is held to the
//! heads it has.

use oneiron::memory::extraction::EncoderOutput;
use serde_json::{Value, json};

use super::{Bar, clears};

const BAR: Bar = Bar {
    max_confidence_delta: 0.05,
    max_vad_delta: 0.1,
};

/// Two spans, as every answer below holds them, plus the given fields.
fn answer(extra: Value) -> EncoderOutput {
    let mut fields = json!({
        "spans": [
            {"message": 0, "start": 0, "end": 3, "label": "person", "confidence": 0.9},
            {"message": 0, "start": 13, "end": 18, "label": "organization", "confidence": 0.8},
        ],
    });
    let (Some(fields), Value::Object(extra)) = (fields.as_object_mut(), extra) else {
        panic!("answer fields are an object");
    };
    fields.extend(extra);
    serde_json::from_value(Value::Object(fields.clone())).expect("a well-formed answer")
}

fn relation(tail: usize, label: &str, confidence: f32) -> Value {
    json!({"head": 0, "tail": tail, "label": label, "confidence": confidence})
}

fn window(end: usize, valence: f32) -> Value {
    json!({
        "message": 0, "start": 0, "end_message": 0, "end": end,
        "vad": {"valence": valence, "arousal": 0.2, "dominance": 0.1},
    })
}

#[test]
fn an_answer_equal_to_the_reference_clears() {
    let reference = answer(json!({
        "relations": [relation(1, "works_at", 0.7)],
        "mood_parts": [window(18, 0.4)],
    }));
    assert!(clears(BAR, &reference, &reference));
}

#[test]
fn an_engine_with_no_relation_head_is_held_to_its_other_heads() {
    let reference = answer(json!({"relations": [relation(1, "works_at", 0.7)]}));
    let got = answer(json!({}));
    assert_eq!(got.relations, None);
    assert!(clears(BAR, &reference, &got));
    let mut moved = got;
    moved.spans[1].end = 17;
    assert!(!clears(BAR, &reference, &moved));
}

#[test]
fn an_answer_with_relations_the_reference_lacks_does_not_clear() {
    let reference = answer(json!({}));
    let got = answer(json!({"relations": []}));
    assert!(!clears(BAR, &reference, &got));
}

#[test]
fn a_relation_with_another_label_tail_or_count_does_not_clear() {
    let reference = answer(json!({"relations": [relation(1, "works_at", 0.7)]}));
    for got in [
        json!({"relations": [relation(1, "founded", 0.7)]}),
        json!({"relations": [relation(0, "works_at", 0.7)]}),
        json!({"relations": []}),
        json!({"relations": [relation(1, "works_at", 0.7), relation(1, "founded", 0.6)]}),
    ] {
        assert!(!clears(BAR, &reference, &answer(got)));
    }
}

#[test]
fn a_relation_confidence_clears_within_the_bar_only() {
    let reference = answer(json!({"relations": [relation(1, "works_at", 0.7)]}));
    let near = answer(json!({"relations": [relation(1, "works_at", 0.73)]}));
    let far = answer(json!({"relations": [relation(1, "works_at", 0.8)]}));
    assert!(clears(BAR, &reference, &near));
    assert!(!clears(BAR, &reference, &far));
}

#[test]
fn a_mood_window_clears_at_the_same_offsets_within_the_bar_only() {
    let reference = answer(json!({"mood_parts": [window(18, 0.4)]}));
    let near = answer(json!({"mood_parts": [window(18, 0.45)]}));
    let far = answer(json!({"mood_parts": [window(18, 0.6)]}));
    let moved = answer(json!({"mood_parts": [window(13, 0.4)]}));
    let none = answer(json!({}));
    assert!(clears(BAR, &reference, &near));
    for got in [far, moved, none] {
        assert!(!clears(BAR, &reference, &got));
    }
}
