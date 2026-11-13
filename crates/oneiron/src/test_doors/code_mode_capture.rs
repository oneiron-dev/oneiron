//! Doors for `tests/code_mode_step_capture.rs` (OPUS-E2E-1, FIX row
//! [AGENT-RUN-START-LATENCY-4S]): a code-mode step's request with the
//! executor's own system prompt, its replay capture as a saved-workflow
//! step's capsule, and the capsule's request read back, as a request and as
//! the bytes the capsule stores.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::collections::BTreeMap;

use crate::WriteActor;
use crate::attempt_queue::AttemptId;
use crate::code_run::StepReplayCapsule;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, Scope, TierPrecedence,
};
use crate::vault::Vault;

/// A request shaped as a code-mode step sends it: the executor's system
/// prompt (the build's whole declarations text at its end), then `task`.
///
/// # Panics
///
/// Never: the model id is a fixed valid one.
#[must_use]
pub fn code_mode_request(system: String, task: &str) -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/executor@v1").expect("a fixed valid model id"),
        envelope: CallEnvelope {
            scope: Scope::default(),
            purpose: CallPurpose::AutoCheck,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AutoCheck,
                ModelTierRef("standard".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: system,
                    signature: None,
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: format!("Run id: 00\nTask:\n{task}"),
                    signature: None,
                }],
            },
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    }
}

/// The executor's system prompt as a code-mode step sends it.
#[must_use]
pub fn executor_system_prompt() -> String {
    crate::engine_executor::executor_system_prompt("Reply with the step's source.")
}

/// Captures `request` as the first call of a saved-workflow step of a new
/// run, `attempt`, made for `actor`, the way a step does before its model
/// call: whether a capsule was staged.
#[must_use]
pub fn capture_step(
    vault: &Vault,
    attempt: AttemptId,
    actor: WriteActor,
    request: &LlmRequest,
) -> bool {
    crate::code_run::capture_workflow_step(vault, attempt, 1, actor, request, None, 0).is_some()
}

/// The one capsule run `attempt` captured.
///
/// # Errors
///
/// None or more than one capsule, and the store's.
pub fn only_capsule(vault: &Vault, attempt: AttemptId) -> Result<StepReplayCapsule> {
    let run = EntityId::from_bytes(*attempt.as_bytes())?;
    let mut capsules = crate::code_run::step_replay_capsules(vault, run)?;
    if capsules.len() != 1 {
        return Err(Error::InvariantViolation(
            "the run did not capture exactly one capsule",
        ));
    }
    Ok(capsules.remove(0))
}

/// The capsule's request as its one reader reads it back.
///
/// # Errors
///
/// The store's.
pub fn captured_request(vault: &Vault, capsule: &StepReplayCapsule) -> Result<Option<LlmRequest>> {
    crate::code_run::capsule_request(vault, capsule)
}

/// The capsule's request as the capsule stores it: its pieces put together,
/// before any read of them as a request.
///
/// # Errors
///
/// The store's.
pub fn stored_request_bytes(vault: &Vault, capsule: &StepReplayCapsule) -> Result<Option<Vec<u8>>> {
    crate::code_run::capsule_stored_request_bytes(vault, capsule)
}
