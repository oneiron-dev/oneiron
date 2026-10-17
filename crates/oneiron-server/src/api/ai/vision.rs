//! `POST /v1/ai/ask_image` (OF-329's `ask_image(handle, question)`): a small
//! vision model in the Local-vision slot (`[models.roles.local_vision]`)
//! reads an image's full pixels through its view handle and answers the
//! caller's question about them in text, so a reader served the image's
//! thumbnail or its description need not pull the pixels into its own
//! context. The pixels are read through the caller's own lane and recorded
//! as an `ask_image` pull before the model is called; the call is admitted
//! through its role and runs on the caller's budget line, as a chat turn
//! does.
//!
//! Asked under a Box or Point contract (`"contract": {"kind": "box"}`), the
//! slot answers as the decision ladder's Local rung instead
//! (`LocalVisionModel`): where the question's target is in the whole
//! image, or that it is absent, with its confidence and the decision's
//! receipt. The host's presence question, when its decision read words one,
//! is asked first, and an answer still in the band steps up to the host's
//! System One seat when one is bound.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use oneiron::llm::decision::catalogue::QuestionFamily;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionClass, DecisionDial,
    DecisionImage, DecisionLadder, DecisionProvider, DecisionRung, EvidenceVersion,
    HumanDecisionQueue, HumanDecisionRequest, ProviderPin, Reversibility, TypedDecision,
};
use oneiron::llm::image::ImageBytes;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{ImageViewRequest, PixelRegion, PulledImage};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{
    BudgetExhaustionPolicy, CallClass, CallEnvelope, CallPurpose, ContentPart, EdgeActorClass,
    EntityId, FinishReason, ImageContent, LlmMessage, LlmMessageRole, LlmRequest, LlmUsage,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, WriteActor,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::refusal;
use crate::ai_host::LocalVisionModel;
use crate::auth::{CoreAuth, CoreScope};
use crate::models::RoleRefusal;
use crate::server::SyncServer;

/// The role whose seat reads the pixels.
const VISION_ROLE: ModelRole = ModelRole::LocalVision;
/// A Box ask's question, keyed by the asset it reads.
const ASK_IMAGE_BOX: QuestionFamily = QuestionFamily {
    name: "ai.ask_image.box",
    version: 1,
    class: DecisionClass::Judgment,
};
/// A Point ask's question, keyed by the asset it reads.
const ASK_IMAGE_POINT: QuestionFamily = QuestionFamily {
    name: "ai.ask_image.point",
    version: 1,
    class: DecisionClass::Judgment,
};
/// The state field the image fills, and the name its question reads it by.
const BOX_IMAGE: &str = "image";
/// A Box or Point ask starts at the Local rung and steps up to the host's
/// System One seat; the asker, not a person queue, takes an answer still in
/// doubt there.
const BOX_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Local,
    ceiling: DecisionRung::SystemOne,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};
/// A Box ask's one clock; the seat's call waits no longer than its work
/// time.
const BOX_BUDGET: Duration = Duration::from_secs(60);

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
    /// The answer contract to ask under; a text answer when absent. The
    /// Local-vision slot answers a Box or a Point, over the whole image.
    #[serde(default)]
    contract: Option<AnswerContract>,
}

/// The vision model's answer, and the receipt of the call that made it.
#[derive(Serialize)]
struct AskImageAnswer {
    /// 32-hex ASSET id.
    asset_ref: String,
    /// The answer, in text, for a text question.
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    /// The answer on the contract, for a question asked under one: a Box or
    /// a Point, `null` inside it for an absent target, or an abstention.
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<DecisionAnswer>,
    /// The decision that stands, for a question asked under an answer
    /// contract: the coordinates', or the presence step's when it found
    /// the target absent or stayed in doubt, with its confidence and
    /// receipt (the rungs' pins, the image's evidence version, its clock).
    #[serde(skip_serializing_if = "Option::is_none")]
    typed: Option<TypedDecision>,
    /// The presence step, when the coordinates stand on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    presence: Option<TypedDecision>,
    receipt: AskImageReceipt,
}

/// What the call was: the pull its served-form record names, its run, the
/// seat's model and where it ran, and what it spent. A typed question that
/// abstained before the seat answered has no spend.
#[derive(Serialize)]
struct AskImageReceipt {
    pull: String,
    run: String,
    model: ModelId,
    locality: ModelLocality,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage: Option<LlmUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finish_reason: Option<FinishReason>,
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
    let located = match &body.contract {
        None => None,
        Some(AnswerContract::Box | AnswerContract::Point) if body.region.is_some() => {
            return Err(refusal(
                StatusCode::BAD_REQUEST,
                "box_reads_whole_image",
                "a Box or a Point is found in the whole image, so its fractions place it on the image",
            ));
        }
        Some(contract @ (AnswerContract::Box | AnswerContract::Point)) => Some(contract.clone()),
        Some(_) => {
            return Err(refusal(
                StatusCode::BAD_REQUEST,
                "contract_not_answered",
                "the Local-vision slot answers a Box or a Point contract",
            ));
        }
    };
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
    let mut pulled = {
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
    let Some(image) = pulled.image.take() else {
        return Err(refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "pixels_missing",
            "the pull returned no pixels",
        ));
    };
    let run_id = format!("ask_image:{}:{}", pulled.asset_ref, vault.now_recorded_at());
    let run = || {
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
        Ok::<_, Response>(server.ai.undeclared_run(run_id.clone(), meter))
    };
    if let Some(contract) = located {
        let run = run()?;
        return box_answer(
            server,
            vault,
            actor,
            (body.question, contract),
            pulled,
            image,
            run,
            run_id,
        )
        .await;
    }
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
                    image: ImageContent::Base64 { data: pulled.bytes },
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
    let run = run()?;
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
        text: Some(text),
        answer: None,
        typed: None,
        presence: None,
        receipt: AskImageReceipt {
            pull: pulled.pull,
            run: run_id,
            model,
            locality,
            usage: Some(response.usage),
            finish_reason: Some(response.finish_reason),
        },
    })
}

/// A Box or Point ask: the host's presence question first, when it words
/// one, then the coordinates. The Local-vision seat at the ladder's Local
/// rung reads the whole image, named `image`, on the caller's run, and an
/// answer still in the band steps up to the host's System One seat. The
/// ladder runs on a blocking thread, since its seats block on this runtime.
#[expect(
    clippy::too_many_arguments,
    reason = "the asker, the question and the pulled pixels join the run they spend on"
)]
async fn box_answer(
    server: &SyncServer,
    vault: Arc<oneiron::Vault>,
    actor: EntityId,
    (question, contract): (String, AnswerContract),
    pulled: PulledImage,
    image: ImageBytes,
    run: RunAdmission,
    run_id: String,
) -> Result<AskImageAnswer, Response> {
    let asset = EntityId::from_hex(&pulled.asset_ref).map_err(|_| {
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "pixels_missing",
            "the pull named no asset",
        )
    })?;
    let family = match contract {
        AnswerContract::Point => ASK_IMAGE_POINT,
        _ => ASK_IMAGE_BOX,
    };
    let question = family
        .question(&[pulled.asset_ref.as_bytes()], question, contract)
        .map_err(|error| {
            refusal(
                StatusCode::BAD_REQUEST,
                "invalid_question",
                error.to_string(),
            )
        })?;
    let images = vec![DecisionImage {
        name: BOX_IMAGE.to_owned(),
        evidence: EvidenceVersion {
            id: asset,
            body_hash: *blake3::hash(&image.bytes).as_bytes(),
        },
        image,
        frame: None,
    }];
    let seat = LocalVisionModel::new(&server.ai, vault, run, tokio::runtime::Handle::current())
        .ok_or_else(|| {
            refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "no_model_configured",
                "no [models.roles.local_vision] rung serves ask_image",
            )
        })?;
    let rung = seat.rung().map_err(|error| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "model_route_not_served",
            error.to_string(),
        )
    })?;
    let host = server.decision_host().ladder().clone();
    let decided = tokio::task::spawn_blocking(move || {
        let ladder = DecisionLadder {
            rule: None,
            local: Some(&rung as &dyn DecisionProvider),
            system_one: host.system_one.as_deref(),
            escalation: None,
            big: None,
            human: &NoPerson,
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: family.name.to_owned(),
                version: family.version.to_string(),
            },
            ask_to: None,
            paired: None,
            person: None,
            presence: host.presence.as_ref(),
            correlation: None,
        };
        ladder.run_located(
            &question,
            actor,
            &[asset],
            &images,
            &json!({}),
            BOX_DIAL,
            &DecisionBandPolicy::default(),
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), BOX_BUDGET),
        )
    })
    .await
    .map_err(|_| {
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "decision_failed",
            "the located ask stopped before it answered",
        )
    })?;
    let last = seat.last_call();
    let decision = decided.map_err(|error| match &last {
        Some(Err(failure)) => super::media::failure(failure),
        _ => refusal(
            StatusCode::BAD_GATEWAY,
            "decision_failed",
            error.to_string(),
        ),
    })?;
    let (usage, finish_reason) = match last {
        Some(Ok((usage, finish_reason))) => (Some(usage), Some(finish_reason)),
        _ => (None, None),
    };
    let answer = decision.answer.clone();
    let (decision, presence) = decision.split();
    Ok(AskImageAnswer {
        asset_ref: pulled.asset_ref,
        text: None,
        answer: Some(answer),
        typed: Some(decision),
        presence,
        receipt: AskImageReceipt {
            pull: pulled.pull,
            run: run_id,
            model: seat.model().clone(),
            locality: seat.locality(),
            usage,
            finish_reason,
        },
    })
}

/// A located ask's person slot: its dial ends below the person, so no
/// person is ever queued.
struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _request: HumanDecisionRequest) -> oneiron::Result<()> {
        Err(oneiron::Error::InvalidConfig(
            "a located ask queues no person".into(),
        ))
    }
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
