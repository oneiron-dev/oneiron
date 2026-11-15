//! A door that files one compaction step as a compaction flight's pass files
//! its paid call (COMPACTION-STEP-CLAIM-READS-WITHOUT-SOURCES): the step's
//! claim, and a response artifact when the answer is above the inline bound,
//! under the run's writer, derived from every record the call read. A run
//! bound to a live off-record session stages them in its room's overlay
//! instead (STEPREAD-OVERLAY-RESPONSE-ASSET).

use crate::code_run::ExecutorStorage;
use crate::compaction::{CompactionCall, CompactionStepRef};
use crate::error::{Error, Result};
use crate::write_envelope::WriteActor;
use crate::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, EdgeActorClass, EntityId, FinishReason,
    LlmInputUsage, LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmUsage,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};

/// Files one compaction step of the run `run_ref` (`job` its id) under the
/// agent `writer`: a call that read `sources` and answered `answer`, stamped
/// at the wall milliseconds a pass files at. Returns the step's claim.
pub fn file_compaction_step(
    vault: &Vault,
    run_ref: &str,
    job: EntityId,
    writer: EntityId,
    sources: Vec<EntityId>,
    answer: &str,
) -> Result<EntityId> {
    file_compaction_step_at(
        vault,
        run_ref,
        job,
        writer,
        sources,
        answer,
        vault.now_recorded_ms(),
    )
}

/// [`file_compaction_step`] stamped at `filed_at`, the time its rows are
/// learned at. A pass files at wall milliseconds, which no month window's
/// scan reaches (FIX COMPACTION-STEP-LEARNED-AT-MILLISECONDS); a step filed at
/// a window's Unix seconds rides that window beside its sources.
pub fn file_compaction_step_at(
    vault: &Vault,
    run_ref: &str,
    job: EntityId,
    writer: EntityId,
    sources: Vec<EntityId>,
    answer: &str,
    filed_at: u64,
) -> Result<EntityId> {
    let call = compaction_call(sources, answer)?;
    filed_claim(ExecutorStorage::Canonical(vault).file_compaction_steps(
        run_ref,
        job,
        WriteActor::new(writer, EdgeActorClass::Agent),
        &[call],
        filed_at,
    )?)
}

/// A compaction step a run bound to a live off-record session staged in its
/// room's overlay: its claim, and the content ASSET its response's bytes
/// take above the inline bound.
pub struct StagedCompactionStep {
    pub claim: EntityId,
    pub content: EntityId,
}

/// [`file_compaction_step`] by a run bound to the live off-record session
/// `session_ref` as its participant `writer`, as a session-bound compaction
/// pass files: the step's claim, and a response artifact with its version
/// and content ASSET when the answer is above the inline bound, stage in the
/// room's overlay and never reach base (FIX 4818).
pub fn file_compaction_step_in_session(
    vault: &Vault,
    session_ref: &str,
    run_ref: &str,
    job: EntityId,
    writer: EntityId,
    sources: Vec<EntityId>,
    answer: &str,
) -> Result<StagedCompactionStep> {
    let call = compaction_call(sources, answer)?;
    let content = crate::blob_artifact::blob_artifact_asset_entity_id(
        blake3::hash(&call.response).as_bytes(),
    )?;
    let session = vault.off_record_session_vault().bind(session_ref)?;
    let storage = ExecutorStorage::for_session(&session, writer)?;
    let claim = filed_claim(storage.file_compaction_steps(
        run_ref,
        job,
        WriteActor::new(writer, EdgeActorClass::Agent),
        &[call],
        vault.now_recorded_ms(),
    )?)?;
    Ok(StagedCompactionStep { claim, content })
}

/// The claim of the one step a filing filed.
fn filed_claim(filed: Vec<CompactionStepRef>) -> Result<EntityId> {
    filed
        .first()
        .map(|step| step.claim)
        .ok_or(Error::InvariantViolation(
            "the compaction step was not filed",
        ))
}

/// One compaction call that read `sources` and answered `answer`.
fn compaction_call(sources: Vec<EntityId>, answer: &str) -> Result<CompactionCall> {
    let request = LlmRequest {
        model: ModelId::new("test/model@r1")
            .map_err(|error| Error::InvalidConfig(error.to_string()))?,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "You compact the conversation's window.".to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
        host_segments: None,
    };
    let response = LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: answer.to_owned(),
                signature: None,
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 40,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 10,
                text: 10,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    };
    let encode = |error: serde_json::Error| Error::InvalidConfig(error.to_string());
    Ok(CompactionCall {
        request: serde_json::to_vec(&request).map_err(encode)?,
        response: serde_json::to_vec(&response).map_err(encode)?,
        sources: Some(sources),
    })
}
