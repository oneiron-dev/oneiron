//! The names of 4 name lists in `oneiron-model`, one line per row, generated from
//! `scripts/ratchet/hand_name_tables.py --names --only <file>` before each list became a Register
//! (Fable pass 25, the Register wave): the names each hand table wrote. Green on the hand tables and
//! on the derive, so no stored or sent name changed (M-1 keep). Each name is also pinned to the one
//! serde reads and writes, and each kept reverse fn to its rows.
//!
//! - `crates/oneiron-model/src/llm/call.rs`
//! - `crates/oneiron-model/src/llm/catalog.rs`
//! - `crates/oneiron-model/src/llm/media/caps.rs`

use oneiron_contracts::register::Register;
use oneiron_model::llm::LlmCapability;
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

/// Every row of `LlmCapability`, as its hand table spelled it.
const LLM_CAPABILITY_ROWS: [(LlmCapability, &str); 12] = [
    (LlmCapability::Streaming, "streaming"),
    (LlmCapability::ToolCalling, "tool_calling"),
    (LlmCapability::ToolResults, "tool_results"),
    (LlmCapability::ImageInput, "image_input"),
    (LlmCapability::JsonResponse, "json_response"),
    (LlmCapability::Reasoning, "reasoning"),
    (LlmCapability::Voice, "voice"),
    (LlmCapability::AssistantPrefill, "assistant_prefill"),
    (LlmCapability::AudioInput, "audio_input"),
    (
        LlmCapability::ReasoningContentHistory,
        "reasoning_content_history",
    ),
    (LlmCapability::TokenLogprobs, "token_logprobs"),
    (LlmCapability::ReasoningSummary, "reasoning_summary"),
];

#[test]
fn every_llm_capability_keeps_its_name() {
    assert_eq!(LlmCapability::Streaming.as_str(), "streaming");
    assert_eq!(LlmCapability::ToolCalling.as_str(), "tool_calling");
    assert_eq!(LlmCapability::ToolResults.as_str(), "tool_results");
    assert_eq!(LlmCapability::ImageInput.as_str(), "image_input");
    assert_eq!(LlmCapability::JsonResponse.as_str(), "json_response");
    assert_eq!(LlmCapability::Reasoning.as_str(), "reasoning");
    assert_eq!(LlmCapability::Voice.as_str(), "voice");
    assert_eq!(
        LlmCapability::AssistantPrefill.as_str(),
        "assistant_prefill"
    );
    assert_eq!(LlmCapability::AudioInput.as_str(), "audio_input");
    assert_eq!(
        LlmCapability::ReasoningContentHistory.as_str(),
        "reasoning_content_history"
    );
    assert_eq!(LlmCapability::TokenLogprobs.as_str(), "token_logprobs");
    assert_eq!(
        LlmCapability::ReasoningSummary.as_str(),
        "reasoning_summary"
    );
}

/// The hand table, serde and `Display` spell each row alike. The rows are read by reference, so
/// the same lines run before and after the enum becomes `Copy`.
#[test]
fn every_llm_capability_name_is_its_serde_and_display_name() {
    for (row, name) in &LLM_CAPABILITY_ROWS {
        let written = serde_json::to_value(row).expect("a row serializes");
        assert_eq!(written, Value::String((*name).to_owned()), "{row:?}");
        let read: LlmCapability = serde_json::from_value(Value::String((*name).to_owned()))
            .expect("serde reads the name");
        assert_eq!(&read, row, "{name}");
        assert_eq!(row.to_string(), *name, "{row:?}");
    }
}

/// The derive's table is the hand table: the Register's name, its rows in declaration order, and
/// each row's name read both ways.
#[test]
fn llm_capability_is_the_llm_capability_register() {
    assert_eq!(LlmCapability::NAME, "llm.capability");
    let rows = LLM_CAPABILITY_ROWS.map(|(row, _)| row);
    assert_eq!(LlmCapability::ROWS, rows.as_slice());
    for (row, name) in LLM_CAPABILITY_ROWS {
        assert_eq!(row.name(), name, "{row:?}");
        assert_eq!(LlmCapability::named(name), Some(row), "{name}");
    }
    assert_eq!(LlmCapability::named("not.a.row"), None);
}
