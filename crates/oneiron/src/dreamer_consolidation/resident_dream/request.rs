//! The one model request a resident dreaming sends: the host's
//! instruction, its craft and its cut, admitted on its role's route or as
//! raw inference, and the hash its durable step keys on.

use std::collections::BTreeMap;

use super::{CRAFT_ASK, DreamCut, ResidentDreamModel, invalid};
use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::dreamer_wake::WakeAttemptContext;
use crate::error::Result;
use crate::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelTierRef, ResponseFormat, TierPrecedence,
};

/// The dreaming's admitted request, its step hash and the craft note claims
/// its craft message was read from (FIX 6998).
pub(super) fn dream_request(
    ctx: &WakeAttemptContext<'_>,
    attempt_id: AttemptId,
    resident_id: EntityId,
    model: &ResidentDreamModel<'_>,
    cut: &DreamCut,
) -> Result<(LlmRequest, [u8; 32], Vec<EntityId>)> {
    let locality = model
        .inference
        .selected_locality()
        .ok_or_else(|| invalid("the host binding names no locality"))?;
    // OF-490: it dreams knowing its own craft, every note, loaded on this
    // attempt so its manifest names them: fixed input beside its cut, never
    // diary progress, so no cut defers or consumes it. A craft that does not
    // read leaves the dreaming as it was.
    let (craft, craft_rows) = match ctx.vault.load_resident_craft(
        attempt_id,
        &resident_id,
        ctx.now_ms / 1_000,
    ) {
        Ok(notes) => (
            crate::actor_claims::craft_message_text(&notes),
            notes
                .iter()
                .filter(|note| crate::actor_claims::craft_note_line(&note.body).is_some())
                .map(|note| note.claim)
                .collect(),
        ),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), ?attempt_id, "a resident's craft did not read; it dreams without it");
            (None, Vec::new())
        }
    };
    let mut messages = vec![LlmMessage {
        role: LlmMessageRole::System,
        content: vec![ContentPart::Text {
            text: model.instruction.to_owned(),
        }],
    }];
    if let Some(text) = craft {
        messages.push(LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text { text }],
        });
    }
    messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: format!("{}\n\n{CRAFT_ASK}", cut.text()),
        }],
    });
    let request = LlmRequest {
        model: model.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: crate::llm::Scope::default(),
            // Its dreaming is its own time (FIX 4453). Its own records leave
            // the vault as an extraction's do, so the call is admitted, gated
            // and routed as extraction: the tier below reads that row too.
            purpose: CallPurpose::AutonomyOwnTime,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("dreaming".into()),
            ),
            response_format: ResponseFormat::Text,
            locality,
        }
        .with_purpose_defaults(),
        messages,
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let authorized = match model.role {
        Some(role) => ctx
            .vault
            .authorize_model_role(role, request, &model.inference)?,
        None => ctx
            .vault
            .authorize_raw_inference(request, &model.inference)?,
    };
    let mut request = authorized.into_request();
    super::super::roles::bind_reasoning(ctx.vault, model.backend, &mut request)?;
    let step_hash = request
        .canonical_hash()
        .map_err(|_| invalid("the dreaming request did not hash"))?;
    Ok((request, step_hash, craft_rows))
}
