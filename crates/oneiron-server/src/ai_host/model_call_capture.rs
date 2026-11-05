//! Terminal model-call evidence shared by native workflow executors.

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord};
use oneiron::code_run::ReadWorldUnknown;
use oneiron::code_run::model_call::{
    MODEL_CALL_SCHEMA, ModelCallDigests, ModelCallInputPart, ModelCallKind, ModelCallReasoningPart,
    ModelCallRecord, record_model_call_in_txn,
};
use oneiron::{EntityId, LlmResponse, Vault, WriteActor};

use crate::models::ModelCallBinding;

/// Callers apply their actual execution's arrival and terminal retention policy.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_generated_response(
    vault: &Vault,
    source_rows: Option<Vec<EntityId>>,
    digests: ModelCallDigests,
    tools_present: bool,
    response: &LlmResponse,
    binding: &ModelCallBinding,
    attempt: &AttemptRecord,
    actor: WriteActor,
    tool_rounds: bool,
) {
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
        tools_present,
        summary_requested: false,
        erased: false,
    };
    if let Err(error) =
        vault.with_write_txn_grouped(|txn| record_model_call_in_txn(vault, txn, &record))
    {
        tracing::warn!(%error, "workflow model-call record failed");
    }
}
