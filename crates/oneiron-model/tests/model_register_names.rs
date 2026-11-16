//! The names of 3 name lists in `oneiron-model`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-model/src/llm/call.rs`
//! - `crates/oneiron-model/src/llm/media/caps.rs`

use oneiron_model::llm::ModelLocality;
use oneiron_model::llm::media::AiOperation;
use oneiron_model::llm::media::Modality;
use serde_json::Value;

/// Every row of `ModelLocality`, as its hand table spelled it.
const MODEL_LOCALITY_ROWS: [(ModelLocality, &str); 3] = [
    (ModelLocality::OnDevice, "on_device"),
    (ModelLocality::OwnServer, "own_server"),
    (ModelLocality::ThirdParty, "third_party"),
];

#[test]
fn every_model_locality_keeps_its_name() {
    assert_eq!(ModelLocality::OnDevice.as_str(), "on_device");
    assert_eq!(ModelLocality::OwnServer.as_str(), "own_server");
    assert_eq!(ModelLocality::ThirdParty.as_str(), "third_party");
}

#[test]
fn every_model_locality_name_is_its_serde_name() {
    for (row, name) in MODEL_LOCALITY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: ModelLocality =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

/// Every row of `AiOperation`, as its hand table spelled it.
const AI_OPERATION_ROWS: [(AiOperation, &str); 6] = [
    (AiOperation::Text, "text"),
    (AiOperation::Image, "image"),
    (AiOperation::Video, "video"),
    (AiOperation::Speech, "speech"),
    (AiOperation::Transcribe, "transcribe"),
    (AiOperation::Embed, "embed"),
];

#[test]
fn every_ai_operation_keeps_its_name() {
    assert_eq!(AiOperation::Text.as_str(), "text");
    assert_eq!(AiOperation::Image.as_str(), "image");
    assert_eq!(AiOperation::Video.as_str(), "video");
    assert_eq!(AiOperation::Speech.as_str(), "speech");
    assert_eq!(AiOperation::Transcribe.as_str(), "transcribe");
    assert_eq!(AiOperation::Embed.as_str(), "embed");
}

#[test]
fn every_ai_operation_name_is_its_serde_name() {
    for (row, name) in AI_OPERATION_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: AiOperation =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}

#[test]
fn ai_operation_parse_reads_each_name_back() {
    for (row, name) in AI_OPERATION_ROWS {
        assert_eq!(AiOperation::parse(name), Some(row), "{name}");
    }
    assert_eq!(AiOperation::parse("not.a.row"), None);
}

/// Every row of `Modality`, as its hand table spelled it.
const MODALITY_ROWS: [(Modality, &str); 5] = [
    (Modality::Text, "text"),
    (Modality::Image, "image"),
    (Modality::Audio, "audio"),
    (Modality::Video, "video"),
    (Modality::Embedding, "embedding"),
];

#[test]
fn every_modality_keeps_its_name() {
    assert_eq!(Modality::Text.as_str(), "text");
    assert_eq!(Modality::Image.as_str(), "image");
    assert_eq!(Modality::Audio.as_str(), "audio");
    assert_eq!(Modality::Video.as_str(), "video");
    assert_eq!(Modality::Embedding.as_str(), "embedding");
}

#[test]
fn every_modality_name_is_its_serde_name() {
    for (row, name) in MODALITY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String(name.to_owned()), "{row:?}");
        let read: Modality =
            serde_json::from_value(Value::String(name.to_owned())).expect("serde reads the name");
        assert_eq!(read, row, "{name}");
    }
}
