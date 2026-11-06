//! A workflow step's final answer: its text, the step's durable result, and
//! the best-effort model-call record of the call that gave it (FIX 12516).

use oneiron::attempt_queue::AttemptRecord;
use oneiron::code_run::model_call::model_call_digests;
use oneiron::{ContentPart, EntityId, LlmRequest, LlmResponse, Vault, WriteActor};

use crate::models::ModelCallBinding;

pub(super) fn response_text(response: &LlmResponse) -> Vec<u8> {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<String>()
        .into_bytes()
}

/// Best-effort final-answer capture for FIX 12516. Intermediate self.use
/// rounds are explicitly marked truncated and get their own later slice.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_workflow_response(
    vault: &Vault,
    source_rows: Option<Vec<EntityId>>,
    request: &LlmRequest,
    response: &LlmResponse,
    binding: &ModelCallBinding,
    attempt: &AttemptRecord,
    actor: WriteActor,
    tool_rounds: bool,
    no_record: bool,
) {
    if no_record {
        tracing::debug!("workflow model-call record skipped: off-record room");
        return;
    }
    let digests = match model_call_digests(request) {
        Ok(digests) => digests,
        Err(error) => {
            tracing::warn!(%error, "workflow model-call digests failed");
            return;
        }
    };
    super::super::model_call_capture::record_generated_response(
        vault,
        source_rows,
        digests,
        !request.tools.is_empty(),
        response,
        binding,
        attempt,
        actor,
        tool_rounds,
    );
}
