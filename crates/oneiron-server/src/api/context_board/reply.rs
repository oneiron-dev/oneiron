//! The actual context-bearing text emit behind the generated `ai.reply` door.
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use oneiron::prompt::{PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION, PromptRecompileStamp};
use oneiron::receipt::ContextReceiptFields;
use oneiron::task_verb::sdk::{AiReply, AiReplyL2Base, AiReplyRequest};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, EdgeActorClass, EntityId, LlmMessage,
    LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use serde_json::json;

use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The host door has checked the owner's proof. All context reads still use
/// this caller's own credential, narrowed to the model's locality and room.
pub(crate) async fn generate_reply(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    input: AiReplyRequest,
) -> (MemoryResult<AiReply>, Vec<EntityId>) {
    let mut rows = Vec::new();
    let answer = reply(server, auth, caller, input, &mut rows).await;
    (answer, rows)
}

async fn reply(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    input: AiReplyRequest,
    rows: &mut Vec<EntityId>,
) -> MemoryResult<AiReply> {
    if input.message.trim().is_empty() {
        return Err(MemoryError::bad_request("message must be non-empty"));
    }
    let conversation = EntityId::from_hex(&input.conversation_id)
        .map_err(|_| MemoryError::bad_request("conversation_id must be an entity id"))?;
    let model = ModelId::new(&input.model)
        .map_err(|_| MemoryError::bad_request("model must be provider/name@revision"))?;
    let router = server.ai.model_runtime().router().ok_or_else(unavailable)?;
    let (locality, configured) = router.served(&model).ok_or_else(unavailable)?;
    // One exact row means its prompt and locality cannot change beneath this
    // assembly through a fallback to another model or another device.
    let route_prompt = configured
        .exact_prompt()
        .ok_or_else(|| {
            MemoryError::bad_request("ai.reply requires an exact configured model row, not a seat")
        })?
        .map(str::to_owned);
    let effort = input
        .reasoning_effort
        .as_ref()
        .map(|effort| {
            serde_json::from_value::<oneiron::llm::ReasoningEffort>(json!(effort)).map_err(|_| {
                MemoryError::bad_request("reasoning_effort is none, low, medium, high or xhigh")
            })
        })
        .transpose()?;
    let purpose = CallPurpose::AnswerGen;
    let mut request = LlmRequest {
        model: model.clone(),
        envelope: CallEnvelope {
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("ai.reply".to_owned())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality,
            seat_effort: effort,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    // The same inference policy and metered run as the existing text door.
    let (ladder, run) = super::super::llm::admit(server, auth, &mut request)
        .map_err(|refused| status_refusal("inference admission", refused.status()))?;
    let reads_at = if auth.locality() == oneiron::claim::CallerLocality::OnDevice
        && request.envelope.locality == ModelLocality::OnDevice
    {
        oneiron::claim::CallerLocality::OnDevice
    } else {
        oneiron::claim::CallerLocality::OffDevice
    };
    let read_auth = auth.clone().at(reads_at);
    let board_request: super::ContextBoardRequest = serde_json::from_value(json!({
        "retrieval": {
            "conversation_id": input.conversation_id,
            "query": input.message,
            "reader": input.reader,
            "budget": input.budget,
            "limit": input.limit.unwrap_or_else(super::super::default_limit),
        },
        "session": {"session_id": input.session_id},
        "memories": {"pinned_refs": input.pinned_refs},
        "standing": input.standing,
        "companion": input.companion,
    }))
    .map_err(|_| MemoryError::bad_request("invalid reply context controls"))?;
    let (served, Json(context)) = super::context_board_hydrate(
        read_auth,
        State(Arc::clone(server)),
        Ok(Json(board_request)),
    )
    .await
    .map_err(|refused| status_refusal("context assembly", refused.into_response().status()))?;
    rows.extend(served.0.rows);

    // The provider receives the standing prefix, then the score-free L2
    // evidence, then the dynamic board. The structured MEMORIES rows ride
    // the dynamic context too, so the stamp describes exactly the selection
    // sent, including rows the compact board renders as index-only.
    let mut dynamic = serde_json::to_value(&context).map_err(|_| internal())?;
    let standing = context
        .standing
        .as_ref()
        .map(|prefix| prefix.compiled.as_str())
        .unwrap_or("");
    dynamic
        .as_object_mut()
        .ok_or_else(internal)?
        .remove("standing");
    let l2_base: Option<AiReplyL2Base> = dynamic
        .get_mut("pack")
        .and_then(|pack| pack.as_object_mut())
        .and_then(|pack| pack.remove("l2_base"))
        .map(serde_json::from_value)
        .transpose()
        .map_err(|_| internal())?;
    dynamic.as_object_mut().ok_or_else(internal)?.remove("pack");
    let evidence = l2_base
        .as_ref()
        .map(|base| base.body.as_str())
        .unwrap_or("");
    let prefix = [standing, evidence].join("\n\n");
    let system = format!(
        "{prefix}\n\n{}",
        serde_json::to_string(&dynamic).map_err(|_| internal())?
    );
    request.messages = vec![
        text_message(LlmMessageRole::System, system.clone()),
        text_message(LlmMessageRole::User, input.message),
    ];
    // Include the configured route prompt in the fingerprint without sending
    // it twice: the exact ladder prepends this same message itself.
    let mut actual = request.clone();
    if let Some(prompt) = route_prompt {
        actual
            .messages
            .insert(0, text_message(LlmMessageRole::System, prompt));
    }
    let request_digest = actual.canonical_hash_hex().map_err(|_| internal())?;
    let system_messages: Vec<_> = actual
        .messages
        .iter()
        .filter(|message| message.role == LlmMessageRole::System)
        .collect();
    let assembled = oneiron::receipt::call_json_digest(&json!(system_messages));
    let prefix_hash = blake3::hash(prefix.as_bytes()).to_hex().to_string();
    let stamp = PromptRecompileStamp {
        schema_version: PROMPT_RECOMPILE_STAMP_SCHEMA_VERSION.to_owned(),
        prompt_path: String::new(),
        compiled_at_secs: super::super::params::unix_seconds_now(),
        source_fingerprint: prefix_hash.clone(),
        resolved_fingerprint: prefix_hash,
        assembled_fingerprint: Some(assembled),
        source_paths: Vec::new(),
    };
    let empty = oneiron::MemoriesSection::pins_only(None);
    let memories = context.memories.as_ref().unwrap_or(&empty);
    let mut frozen = ContextReceiptFields::from_assembly(&stamp, memories)?
        .model(model.to_string())
        .prompt_input_ref(request_digest.clone());
    if let Some(effort) = request.envelope.seat_effort {
        frozen = frozen.reasoning_effort(
            serde_json::to_value(effort)
                .map_err(|_| internal())?
                .as_str()
                .ok_or_else(internal)?,
        );
    }
    if let Some(disclosure) = &memories.disclosure {
        frozen = frozen.disclosure_stamp(&disclosure.emit_stamp);
    }
    // The prompt goes to the model and its answer to the caller: a row a
    // world withholds from either keeps it here, and the refusal says why,
    // content-free (FIX 4937, 4939).
    let prompt_for =
        crate::device_local::prompt_destination(auth.destination(), request.envelope.locality);
    if let Some(hold) =
        crate::device_local::retained_hold(&server.vault, &prompt_for, rows, system.as_bytes())
            .map_err(MemoryError::from)?
    {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("reply context is kept on this device: {}", hold.reason()),
            &[],
        ));
    }
    if !auth.credential_is_live(&server.vault) {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "reply credential is no longer live",
            &[],
        ));
    }
    let response = ladder
        .generate_exact(&run, request, None)
        .await
        .map_err(|error| {
            MemoryError::new(
                if matches!(error, oneiron::LlmError::BudgetDenied(_)) {
                    MEMORY_CODE_BUDGET_SPENT
                } else {
                    MEMORY_CODE_MODEL_UNAVAILABLE
                },
                format!("ai.reply: {error}"),
                &[],
            )
        })?;
    if !auth.credential_is_live(&server.vault) {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "reply credential is no longer live",
            &[],
        ));
    }
    let reply: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("");
    if reply.is_empty() {
        return Err(unavailable());
    }
    let result_digest = oneiron::receipt::call_bytes_digest(reply.as_bytes());
    let (server, auth) = (Arc::clone(server), auth.clone());
    let receipt_ref = tokio::task::spawn_blocking(move || {
        let substrate = server.vault.ensure_model_substrate(
            &format!("{}/{}", model.provider(), model.name()),
            model.revision(),
            super::super::params::unix_seconds_now(),
        )?;
        let frozen = frozen.substrate_ref(substrate.to_hex());
        super::super::credential_memory(&server.vault, Some(&auth), caller.0, caller.1)
            .at(auth.locality())
            .record_context_reply(conversation, &frozen, request_digest, result_digest)
    })
    .await
    .map_err(|_| internal())??;
    Ok(AiReply {
        reply,
        model: input.model,
        receipt_refs: vec![receipt_ref],
        l2_base,
    })
}

fn text_message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}
fn unavailable() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        "no configured text model answered ai.reply",
        &[],
    )
}
fn internal() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "reply context could not be retained",
        &[],
    )
}
fn status_refusal(stage: &str, status: StatusCode) -> MemoryError {
    let code = match status {
        StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => MEMORY_CODE_FORBIDDEN,
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::CONFLICT => {
            MEMORY_CODE_BAD_REQUEST
        }
        StatusCode::SERVICE_UNAVAILABLE => MEMORY_CODE_MODEL_UNAVAILABLE,
        _ => MEMORY_CODE_INTERNAL,
    };
    MemoryError::new(code, format!("ai.reply {stage} refused ({status})"), &[])
}
