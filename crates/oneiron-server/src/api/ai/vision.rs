//! `POST /v1/ai/ask_image` (OF-329's `ask_image(handle, question)`): a small
//! vision model in the Local-vision slot (`[models.roles.local_vision]`)
//! reads an image's full pixels through its view handle and answers the
//! caller's question about them in text, so a reader served the image's
//! thumbnail or its description need not pull the pixels into its own
//! context. The pixels are read through the caller's own lane and recorded
//! as an `ask_image` pull before the model is called; the call is admitted
//! through its role and runs on the caller's budget line, as a chat turn
//! does.
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use oneiron::llm::decision::DecisionAnswer;
use oneiron::llm::manifest::ModelRole;
use oneiron::memory::{ImageViewRequest, PixelRegion};
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EdgeActorClass,
    EntityId, FinishReason, ImageContent, LlmMessage, LlmMessageRole, LlmRequest, LlmUsage,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, WriteActor,
};
use serde::{Deserialize, Serialize};

use super::refusal;
use crate::auth::{CoreAuth, CoreScope};
use crate::models::RoleRefusal;
use crate::server::SyncServer;

/// The role whose seat reads the pixels.
const VISION_ROLE: ModelRole = ModelRole::LocalVision;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AskImageBody {
    /// The view handle the image was served with (`<asset>@<hash>`).
    handle: String,
    /// What to ask about its pixels.
    question: String,
    /// A region to ask about, in the image's own pixels; the whole image
    /// when absent.
    #[serde(default)]
    region: Option<PixelRegion>,
}

/// The vision model's answer, and the receipt of the call that made it.
#[derive(Serialize)]
struct AskImageAnswer {
    /// 32-hex ASSET id.
    asset_ref: String,
    /// The answer, in text.
    text: String,
    /// A typed answer beside the text, for a question asked under an answer
    /// contract the Local-vision slot answers (a Box, say); none for a text
    /// question.
    #[serde(skip_serializing_if = "Option::is_none")]
    typed: Option<DecisionAnswer>,
    receipt: AskImageReceipt,
}

/// What the call was: the pull its served-form record names, its run, the
/// seat's model and where it ran, and what it spent.
#[derive(Serialize)]
struct AskImageReceipt {
    pull: String,
    run: String,
    model: ModelId,
    locality: ModelLocality,
    usage: LlmUsage,
    finish_reason: FinishReason,
}

pub(super) async fn ask_image(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(body): Json<AskImageBody>,
) -> Response {
    match asked(&server, &auth, body).await {
        Ok(answer) => Json(answer).into_response(),
        Err(refused) => refused,
    }
}

async fn asked(
    server: &SyncServer,
    auth: &CoreAuth,
    body: AskImageBody,
) -> Result<AskImageAnswer, Response> {
    auth.require(CoreScope::Read)
        .map_err(IntoResponse::into_response)?;
    if body.question.trim().is_empty() {
        return Err(refusal(
            StatusCode::BAD_REQUEST,
            "empty_question",
            "ask_image asks a question",
        ));
    }
    let seat = server.ai.seat(VISION_ROLE).cloned().ok_or_else(|| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_model_configured",
            "no [models.roles.local_vision] rung serves ask_image",
        )
    })?;
    let vault = Arc::clone(server.vault());
    let (actor, class) = principal(auth, &vault)?;
    // The pixels are read, and the pull recorded, through the caller's own
    // lane before any model is called.
    let pulled = {
        let lane = crate::api::scoped_auth::scoped_read_for_core_auth(&vault, auth)
            .map_err(IntoResponse::into_response)?;
        let request = ImageViewRequest {
            handle: body.handle,
            region: body.region,
            edge: None,
        };
        oneiron::memory::pull_image(&lane, &request, true)
            .map_err(|error| {
                let status = match error.code.as_str() {
                    oneiron::memory::MEMORY_CODE_NOT_FOUND => StatusCode::NOT_FOUND,
                    oneiron::memory::MEMORY_CODE_BAD_REQUEST => StatusCode::BAD_REQUEST,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };
                refusal(status, &error.code, error.message)
            })?
            .value
    };
    let Some(image) = pulled.image else {
        return Err(refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "pixels_missing",
            "the pull returned no pixels",
        ));
    };
    let purpose = CallPurpose::Other {
        name: "ai.ask_image".to_owned(),
    };
    let request = LlmRequest {
        model: seat.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("local-vision".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: seat.locality,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![
                ContentPart::Image {
                    media_type: image.media_type,
                    image: ImageContent::Base64 {
                        data: pulled.bytes,
                    },
                },
                ContentPart::Text {
                    text: body.question,
                },
            ],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    };
    let admitted = server
        .ai
        .admit_role(&vault, VISION_ROLE, request)
        .map_err(|refused| {
            let (status, code) = match refused {
                RoleRefusal::NoSeat => (StatusCode::SERVICE_UNAVAILABLE, "no_model_configured"),
                RoleRefusal::RouteNotServed { .. } => {
                    (StatusCode::SERVICE_UNAVAILABLE, "model_route_not_served")
                }
                RoleRefusal::Refused(_) => (StatusCode::PAYMENT_REQUIRED, "call_not_admitted"),
            };
            refusal(status, code, refused.to_string())
        })?;
    let model = admitted.request.model.clone();
    let locality = admitted.request.envelope.locality;
    let run_id = format!("ask_image:{}:{}", pulled.asset_ref, vault.now_recorded_at());
    let settings = server.ai.chat_settings();
    let meter = vault
        .policy_budget_guard(
            run_id.clone(),
            settings.turn_budget_units,
            oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS.min(settings.turn_budget_units),
            BudgetExhaustionPolicy::Suspend,
            WriteActor::new(actor, class),
        )
        .map_err(|error| {
            refusal(
                StatusCode::PAYMENT_REQUIRED,
                "call_not_admitted",
                error.to_string(),
            )
        })?;
    let run = server.ai.undeclared_run(run_id.clone(), meter);
    let response = admitted
        .ladder
        .generate(&run, admitted.request, None)
        .await
        .map_err(|error| super::media::failure(&error))?;
    let text = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("");
    Ok(AskImageAnswer {
        asset_ref: pulled.asset_ref,
        text,
        typed: None,
        receipt: AskImageReceipt {
            pull: pulled.pull,
            run: run_id,
            model,
            locality,
            usage: response.usage,
            finish_reason: response.finish_reason,
        },
    })
}

/// The caller the call spends for: the credential's principal, or the
/// embedded owner for an owner-grade credential that names none.
fn principal(
    auth: &CoreAuth,
    vault: &oneiron::Vault,
) -> Result<(EntityId, EdgeActorClass), Response> {
    let denied = || {
        refusal(
            StatusCode::FORBIDDEN,
            "principal_required",
            "ask_image spends for an authenticated principal",
        )
    };
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(|_| denied())?,
        None if auth.is_owner_grade() => {
            vault.ensure_embedded_owner_actor().map_err(|_| denied())?
        }
        None => return Err(denied()),
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    Ok((actor, class))
}
