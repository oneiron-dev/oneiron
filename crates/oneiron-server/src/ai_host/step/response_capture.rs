//! A workflow step's final answer: its text, the step's durable result, and
//! the best-effort model-call record of the call that gave it (FIX 12516).

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord};
use oneiron::code_run::ReadWorldUnknown;
use oneiron::code_run::model_call::{
    MODEL_CALL_SCHEMA, ModelCallInputPart, ModelCallKind, ModelCallReasoningPart, ModelCallRecord,
    model_call_digests, record_model_call_in_txn,
};
use oneiron::{ContentPart, EntityId, LlmRequest, LlmResponse, Vault, WriteActor};

use crate::models::ModelCallBinding;

pub(super) fn response_text(response: &LlmResponse) -> Vec<u8> {
    response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
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
    let Ok(attempt_entity) = oneiron::EntityId::from_bytes(*attempt.id.as_bytes()) else {
        tracing::warn!("workflow model-call record skipped: attempt id is not an entity");
        return;
    };
    // The record stamps the exact rung that answered, threaded with the
    // final answer (FIX 12743), not the one requested.
    let rung = binding.rung.clone();
    let route = binding.route.clone();
    // The parent try's own fence, read from its row and never guessed: a
    // retry's attempt_count does not count logical retries.
    let replay_of = attempt.retry_of.and_then(|parent| {
        let parent_row = AttemptQueue::new(vault).get(parent).ok()??;
        let parent_entity = oneiron::EntityId::from_bytes(*parent.as_bytes()).ok()?;
        Some((parent_entity, u64::from(parent_row.attempt_count)))
    });
    let input_parts = if source_rows.is_none() {
        vec![ModelCallInputPart::Unknown {
            reason: "workflow-step sources are unknown".to_owned(),
        }]
    } else {
        Vec::new()
    };
    let call_metadata = response.usage.call_metadata.as_ref();
    let record = ModelCallRecord {
        schema: MODEL_CALL_SCHEMA,
        attempt: attempt_entity,
        lease_generation: u64::from(attempt.attempt_count),
        // Index 1 is the try's first call; a tool-rounds step's final answer
        // follows its truncated rounds and takes index 2.
        call_index: u64::from(tool_rounds) + 1,
        kind: ModelCallKind::Generate {
            digests,
            usage: response.usage.clone(),
            finish_reason: response.finish_reason.clone(),
        },
        route,
        rung,
        issuing_login: None,
        organization: None,
        project: None,
        credential_id: None,
        response_id: call_metadata.and_then(|metadata| metadata.response_id.clone()),
        thread_id: None,
        previous_response_id: call_metadata
            .and_then(|metadata| metadata.previous_response_id.clone()),
        store: call_metadata.and_then(|metadata| metadata.store),
        endpoint: call_metadata.map(|metadata| metadata.endpoint),
        captured_at: vault.now_recorded_at(),
        receipt_ref: None,
        actor: Some(actor.entity_ref()),
        produced_pending: response.reply_assertions.created.is_empty(),
        tool_rounds,
        rounds_truncated: tool_rounds,
        replay_of,
        source_rows: source_rows.unwrap_or_default(),
        produced_rows: response
            .reply_assertions
            .created
            .iter()
            .map(|record| record.id)
            .collect(),
        input_parts,
        reasoning: response
            .message
            .content
            .iter()
            .filter_map(|part| ModelCallReasoningPart::from_terminal(part, None, None))
            .collect(),
        read_world_epoch: None,
        read_worlds: None,
        read_world_unknown: vec![ReadWorldUnknown::Uncaptured],
        tools_present: !request.tools.is_empty(),
        summary_requested: false,
        erased: false,
    };
    if let Err(error) =
        vault.with_write_txn_grouped(|txn| record_model_call_in_txn(vault, txn, &record))
    {
        tracing::warn!(%error, "workflow model-call record failed");
    }
}
