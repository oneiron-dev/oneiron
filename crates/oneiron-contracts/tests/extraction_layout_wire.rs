//! The bound extraction step's layout refusal carries its native slices as the
//! typed `extraction_layout` field, never as prose a client parses. A later
//! leaf (e2f.3) extends this file with the bound read's page-layout variant.

use oneiron_contracts::memory::{
    ExtractionLayout, ExtractionStepSlice, MEMORY_CODE_BAD_REQUEST, MemoryError,
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
