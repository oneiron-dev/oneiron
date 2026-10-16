//! The Local-vision seat as the decision ladder's Local rung (OF-329 over
//! OF-600): the small vision model bound as `[models.roles.local_vision]`
//! answers a Box question over a call's images ("where is `mug` in
//! `camera`?"). [`LocalVisionModel::rung`] wraps it with
//! `ModelDecisionProvider` at `DecisionRung::Local`, so a host's ladder can
//! seat it.
//!
//! A call is one admitted request of the role, on the caller's run: each
//! image, downscaled to the ladder's long edge, after a line with the
//! reference its state field holds, then the question and the state as JSON,
//! under a schema shaped as System One's Box answer (`{"box": {top, bottom,
//! left, right} | null, "confidence"}`). Any other contract, or a call with
//! no image, abstains, so the ladder takes it on. An answer outside the
//! schema is refused whole, never read as an absent target.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use oneiron::llm::decision::{
    AnswerContract, DECISION_IMAGE_EDGE, DecisionAnswer, DecisionCall, DecisionImage,
    DecisionModel, DecisionRung, ImageBox, ModelDecisionProvider, ProviderDecision, ProviderPin,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, Error, FinishReason, ImageContent, LlmError,
    LlmMessage, LlmMessageRole, LlmRequest, LlmUsage, ModelId, ModelLocality, ModelTierRef,
    ResponseFormat, RetryableLlmError, TierPrecedence, Vault,
};
use serde_json::{Value, json};

use super::AiHandle;

/// The role whose seat answers.
const ROLE: ModelRole = ModelRole::LocalVision;
/// The purpose each call is budgeted and audited under.
const PURPOSE: &str = "decision.local_vision";

/// What the seat's last call spent and how it ended, or why it failed.
pub(crate) type VisionCall = Result<(LlmUsage, FinishReason), LlmError>;

/// The Local-vision seat as a [`DecisionModel`] that reads images.
pub(crate) struct LocalVisionModel {
    ai: AiHandle,
    vault: Arc<Vault>,
    run: RunAdmission,
    runtime: tokio::runtime::Handle,
    model: ModelId,
    locality: ModelLocality,
    last: Mutex<Option<VisionCall>>,
}

impl LocalVisionModel {
    /// The seat, spending on `run`; none when no `[models.roles.local_vision]`
    /// seat is bound. `runtime` is the server's: a call blocks on it.
    pub(crate) fn new(
        ai: &AiHandle,
        vault: Arc<Vault>,
        run: RunAdmission,
        runtime: tokio::runtime::Handle,
    ) -> Option<Arc<Self>> {
        let seat = ai.seat(ROLE)?;
        Some(Arc::new(Self {
            model: seat.model.clone(),
            locality: seat.locality,
            ai: ai.clone(),
            vault,
            run,
            runtime,
            last: Mutex::new(None),
        }))
    }

    /// This seat at the Local rung, its pin naming the seat's model and
    /// revision.
    pub(crate) fn rung(self: &Arc<Self>) -> oneiron::Result<ModelDecisionProvider> {
        let pin = ProviderPin {
            rung: DecisionRung::Local,
            model: format!("{}/{}", self.model.provider(), self.model.name()),
            version: self.model.revision().to_owned(),
        };
        ModelDecisionProvider::new(pin, Arc::clone(self) as Arc<dyn DecisionModel>)
    }

    pub(crate) fn model(&self) -> &ModelId {
        &self.model
    }

    pub(crate) fn locality(&self) -> ModelLocality {
        self.locality
    }

    /// The last call's spend and finish, or its failure; none before one ran.
    pub(crate) fn last_call(&self) -> Option<VisionCall> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn request(&self, call: &DecisionCall<'_>) -> oneiron::Result<LlmRequest> {
        let mut state = call.state.clone();
        let mut content = Vec::with_capacity(call.images.len() * 2 + 1);
        for image in call.images {
            let fitted = image
                .fitted(DECISION_IMAGE_EDGE)
                .map_err(|_| failed("an unreadable decision image"))?;
            // The state field holds the reference the line before the image
            // names, as System One's state holds its asset's.
            let reference = format!("image:{}", image.name);
            state[image.name.as_str()] = json!(reference);
            content.push(ContentPart::Text { text: reference });
            content.push(ContentPart::Image {
                media_type: fitted.media_type.clone(),
                image: ImageContent::Base64 {
                    data: DecisionImage::base64(&fitted),
                },
            });
        }
        content.push(ContentPart::Text {
            text: json!({"question": call.question.text, "state": state}).to_string(),
        });
        let purpose = CallPurpose::Other {
            name: PURPOSE.to_owned(),
        };
        Ok(LlmRequest {
            model: self.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("local-vision".into())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Json {
                    schema: box_schema(),
                },
                locality: self.locality,
            },
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content,
            }],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }
}

impl DecisionModel for LocalVisionModel {
    fn reads_images(&self) -> bool {
        true
    }

    /// Blocks on the server's runtime until the seat answers, so it runs on
    /// a blocking thread, never on one of that runtime's workers. The call
    /// waits no longer than the decision's work time.
    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        if call.question.contract != AnswerContract::Box || call.images.is_empty() {
            return Ok(ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
            });
        }
        let request = self.request(call)?;
        let admitted = self
            .ai
            .admit_role(&self.vault, ROLE, request)
            .map_err(|refused| failed(&format!("local vision call refused: {refused}")))?;
        // The pin names this seat's model; a route that binds another is not
        // this rung's answer.
        if admitted.request.model != self.model {
            return Err(failed("the local vision route serves another model"));
        }
        let time_left = call.deadline.decision_time_left();
        let response = self.runtime.block_on(async {
            tokio::time::timeout(
                time_left,
                admitted.ladder.generate(&self.run, admitted.request, None),
            )
            .await
            .unwrap_or_else(|_| Err(RetryableLlmError::Timeout.into()))
        });
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some(
            response
                .as_ref()
                .map(|response| (response.usage.clone(), response.finish_reason.clone()))
                .map_err(Clone::clone),
        );
        let response =
            response.map_err(|error| failed(&format!("local vision call failed: {error}")))?;
        let text = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>();
        box_answer(&text).ok_or_else(|| failed("malformed local vision answer"))
    }
}

/// The answer's shape: System One's Box answer without its `type`.
fn box_schema() -> Value {
    let edge = |what: &str| json!({"type": "number", "minimum": 0, "maximum": 1, "description": what});
    json!({
        "type": "object",
        "properties": {
            "box": {
                "description": "Where the question's target is in the image, as fractions of the image from its top-left corner; null when the target is not in the image.",
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "properties": {
                            "top": edge("The box's top edge, as a fraction of the image's height."),
                            "bottom": edge("The box's bottom edge, as a fraction of the image's height."),
                            "left": edge("The box's left edge, as a fraction of the image's width."),
                            "right": edge("The box's right edge, as a fraction of the image's width.")
                        },
                        "required": ["top", "bottom", "left", "right"],
                        "additionalProperties": false
                    }
                ]
            },
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "How sure the answer is, from 0 to 1."
            }
        },
        "required": ["box", "confidence"],
        "additionalProperties": false
    })
}

/// The seat's answer: its outermost JSON object (a seat may fence it), with
/// a box whose edges are in order inside the image, or null, and a
/// confidence in 0–1.
fn box_answer(text: &str) -> Option<ProviderDecision> {
    let object = text.get(text.find('{')?..=text.rfind('}')?)?;
    let value: Value = serde_json::from_str(object).ok()?;
    let found = match value.get("box")? {
        Value::Null => None,
        edges => Some(
            serde_json::from_value::<ImageBox>(edges.clone())
                .ok()
                .filter(|found| found.is_valid())?,
        ),
    };
    let confidence = value
        .get("confidence")?
        .as_f64()
        .filter(|p| p.is_finite() && (0.0..=1.0).contains(p))?;
    Some(ProviderDecision {
        answer: DecisionAnswer::Box(found),
        probability: Some(confidence),
        paired: None,
        person: None,
    })
}

fn failed(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
