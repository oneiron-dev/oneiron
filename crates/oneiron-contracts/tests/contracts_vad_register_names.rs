//! The names of `VadAnnotationSource` in `oneiron-contracts`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only crates/oneiron-contracts/src/affect/vad.rs`
//! before the list became a Register (Fable pass 25, the Register wave; FIX
//! REGISTER-WAVE-B-HELD-FILES): the names its hand table wrote. Green on the hand table and on the
//! derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one serde
//! reads and writes.
//!
//! - `crates/oneiron-contracts/src/affect/vad.rs`

use oneiron_contracts::affect::VadAnnotationSource;
use serde_json::Value;

/// Every row of `VadAnnotationSource`, as its hand table spelled it.
const VAD_ANNOTATION_SOURCE_ROWS: [(VadAnnotationSource, &str); 2] = [
    (VadAnnotationSource::ModelInference, "model_inference"),
    (VadAnnotationSource::UserSelfReport, "user_self_report"),
];

#[test]
fn every_vad_annotation_source_keeps_its_name() {
    assert_eq!(
        VadAnnotationSource::ModelInference.as_str(),
        "model_inference"
    );
    assert_eq!(
        VadAnnotationSource::UserSelfReport.as_str(),
        "user_self_report"
    );
}

#[test]
fn every_vad_annotation_source_name_is_its_serde_name() {
    for (row, name) in VAD_ANNOTATION_SOURCE_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: VadAnnotationSource =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn vad_annotation_source_names_are_usable_in_const_context() {
    const MODEL_INFERENCE: &str = VadAnnotationSource::ModelInference.as_str();
    assert_eq!(MODEL_INFERENCE, "model_inference");
}
