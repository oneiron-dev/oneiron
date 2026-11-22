//! The bound extraction step's layout refusal carries its native slices as the
//! typed `extraction_layout` field, never as prose a client parses. Bound
//! read part refusals carry their rebuilt pages through the same field.

use oneiron_contracts::memory::{
    ExtractionCorrectionPair, ExtractionLayout, ExtractionStepSlice, MEMORY_CODE_BAD_REQUEST,
    MemoryError,
};

#[test]
fn extraction_layout_is_a_typed_refusal_field() {
    let mut error = MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        "the cited turns are not one native slice",
        &["Resubmit once per slice, naming the slice's page."],
    );
    error.extraction_layout = Some(Box::new(ExtractionLayout::StepSlices {
        slices: vec![
            ExtractionStepSlice {
                evidence: vec![0, 2],
                pages: 1,
            },
            ExtractionStepSlice {
                evidence: vec![1],
                pages: 2,
            },
        ],
    }));
    let wire = serde_json::to_value(&error).expect("a refusal serializes");
    assert_eq!(
        wire,
        serde_json::json!({
            "code": "BAD_REQUEST",
            "message": "the cited turns are not one native slice",
            "suggestions": ["Resubmit once per slice, naming the slice's page."],
            "extraction_layout": {
                "kind": "step_slices",
                "slices": [
                    {"evidence": [0, 2], "pages": 1},
                    {"evidence": [1], "pages": 2},
                ],
            },
        }),
    );
    let back: MemoryError = serde_json::from_value(wire).expect("the pinned shape deserializes");
    assert_eq!(back, error);

    let mut correction = MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        "extraction pack part does not match its read",
        &["Fix the request shape and retry."],
    );
    correction.extraction_layout = Some(Box::new(ExtractionLayout::CorrectionPages {
        pages: vec![
            vec![ExtractionCorrectionPair {
                candidate: 0,
                listed: 0,
            }],
            vec![ExtractionCorrectionPair {
                candidate: 0,
                listed: 1,
            }],
        ],
    }));
    let correction_wire = serde_json::to_value(&correction).expect("a refusal serializes");
    assert_eq!(
        correction_wire,
        serde_json::json!({
            "code": "BAD_REQUEST",
            "message": "extraction pack part does not match its read",
            "suggestions": ["Fix the request shape and retry."],
            "extraction_layout": {
                "kind": "correction_pages",
                "pages": [
                    [{"candidate": 0, "listed": 0}],
                    [{"candidate": 0, "listed": 1}],
                ],
            },
        }),
    );
    let correction_back: MemoryError =
        serde_json::from_value(correction_wire).expect("the pinned shape deserializes");
    assert_eq!(correction_back, correction);

    let mut resolution = MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        "extraction pack part does not match its read",
        &["Fix the request shape and retry."],
    );
    resolution.extraction_layout = Some(Box::new(ExtractionLayout::ResolutionPages {
        pages: vec![vec![0], vec![1]],
    }));
    let resolution_wire = serde_json::to_value(&resolution).expect("a refusal serializes");
    assert_eq!(
        resolution_wire,
        serde_json::json!({
            "code": "BAD_REQUEST",
            "message": "extraction pack part does not match its read",
            "suggestions": ["Fix the request shape and retry."],
            "extraction_layout": {
                "kind": "resolution_pages",
                "pages": [[0], [1]],
            },
        }),
    );
    let resolution_back: MemoryError =
        serde_json::from_value(resolution_wire).expect("the pinned shape deserializes");
    assert_eq!(resolution_back, resolution);

    assert!(
        serde_json::from_value::<ExtractionCorrectionPair>(
            serde_json::json!({"candidate": 0, "listed": 0, "shown": "C1"})
        )
        .is_err(),
        "an unknown pair field refuses",
    );

    let plain = MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        "the cited turns are not one native slice",
        &["Resubmit once per slice, naming the slice's page."],
    );
    let plain_wire = serde_json::to_value(&plain).expect("a refusal serializes");
    assert!(
        !plain_wire
            .as_object()
            .expect("a refusal serializes as an object")
            .contains_key("extraction_layout"),
        "an absent layout leaves no key: {plain_wire}",
    );
    let plain_back: MemoryError =
        serde_json::from_value(plain_wire).expect("a keyless refusal deserializes");
    assert_eq!(plain_back, plain);
}
