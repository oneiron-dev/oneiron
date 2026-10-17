//! The big model on the decision ladder's Big rung (ARCH-0076, OF-495). A
//! typed question goes to the seat `[models.decisions.big]` names as one
//! admitted model call: routed against the vault's live model policy, sent
//! under its own run on the rung's meter, worded by the host's
//! configuration and answered in its reply format. The answer and its
//! probability are parsed out of the generated text. A reply that names
//! nothing the question takes, or no probability, abstains. The rung hears
//! a call's audio clips when the model its seat routes to is bound as
//! hearing them. The same rung can be asked of one configured model alone
//! (OF-184), with no owner's fallback, so the model that answers is the one
//! named.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::decision::questions::QuestionCriteria;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionCall, DecisionModel, DecisionRung, ProviderCapability,
    ProviderDecision, ProviderPin,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    EntityId, Error, LlmCapability, LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};
use serde_json::{Value, json};

use crate::config::models::{BigReply, BigSettings};
use crate::models::{ModelRuntime, OfferLadder};

/// The purpose a Big-rung call stamps, and the tier it asks for by default.
const PURPOSE: &str = "decision.big";

fn failed(what: impl std::fmt::Display) -> Error {
    Error::InvalidConfig(format!("big rung: {what}"))
}

fn message(role: LlmMessageRole, text: String) -> LlmMessage {
    LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    }
}

/// What answers the rung's questions.
enum Answerer {
    /// The seat a role names, routed against the vault's live model policy.
    Seat(ModelRole),
    /// One configured chat model by its own id, under the policy a raw call
    /// meets, with no owner's fallback.
    Model(ModelId),
}

/// The big model, answering typed questions on its seat.
pub(crate) struct BigModel {
    models: Arc<ModelRuntime>,
    vault: Arc<Vault>,
    answerer: Answerer,
    wording: String,
    reply: BigReply,
    meter: BudgetGuard,
    runtime: tokio::runtime::Handle,
    pin: ProviderPin,
}

impl BigModel {
    /// The rung over `models`' seat for the settings' role; `None` when no
    /// rung of that seat can serve.
    pub(crate) fn bind(
        settings: &BigSettings,
        models: Arc<ModelRuntime>,
        vault: Arc<Vault>,
        default_units: u64,
        runtime: tokio::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let seat = models.seat(settings.role).ok_or_else(|| {
            anyhow::anyhow!("no [models] rung serves the {:?} seat", settings.role)
        })?;
        let pin = ProviderPin {
            rung: DecisionRung::Big,
            model: seat.model.to_string(),
            version: settings.version.clone(),
        };
        Ok(Self {
            meter: BudgetGuard::new(
                PURPOSE,
                settings.budget_units.unwrap_or(default_units),
                BudgetExhaustionPolicy::Suspend,
            ),
            answerer: Answerer::Seat(settings.role),
            wording: settings.wording.clone(),
            reply: settings.reply,
            models,
            vault,
            runtime,
            pin,
        })
    }

    /// This rung asked of `model` alone (OF-184): a chat model the router
    /// serves by its own id, framed, worded and metered as this rung is, its
    /// pin naming that model. Its calls take no owner's fallback, so an
    /// answer is that model's or none.
    pub(crate) fn for_model(&self, model: &ModelId) -> anyhow::Result<Self> {
        let served = self
            .models
            .router()
            .is_some_and(|router| router.chat_models().any(|chat| chat == model));
        if !served {
            anyhow::bail!("no chat model {model} is served alone by its own id");
        }
        Ok(Self {
            models: Arc::clone(&self.models),
            vault: Arc::clone(&self.vault),
            answerer: Answerer::Model(model.clone()),
            wording: self.wording.clone(),
            reply: self.reply,
            meter: self.meter.clone(),
            runtime: self.runtime.clone(),
            pin: ProviderPin {
                rung: DecisionRung::Big,
                model: model.to_string(),
                version: self.pin.version.clone(),
            },
        })
    }

    /// This rung asked of `role`'s seat (OF-568): framed, worded and
    /// metered as this rung is, routed against the vault's live model policy
    /// as the configured seat is, its pin naming that seat's model.
    pub(crate) fn for_role(&self, role: ModelRole) -> anyhow::Result<Self> {
        let seat = self
            .models
            .seat(role)
            .ok_or_else(|| anyhow::anyhow!("no [models] rung serves the {role:?} seat"))?;
        Ok(Self {
            models: Arc::clone(&self.models),
            vault: Arc::clone(&self.vault),
            answerer: Answerer::Seat(role),
            wording: self.wording.clone(),
            reply: self.reply,
            meter: self.meter.clone(),
            runtime: self.runtime.clone(),
            pin: ProviderPin {
                rung: DecisionRung::Big,
                model: seat.model.to_string(),
                version: self.pin.version.clone(),
            },
        })
    }

    pub(crate) fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    /// Whether the model the seat routes to hears audio: the vault
    /// manifest's binding of the role says so (with no manifest the seat is
    /// the binding, and its provider's explicit `audio_input` capability is
    /// the declaration), and every rung serving that model admits
    /// [`LlmCapability::AudioInput`]. One model alone hears audio when its
    /// provider's capability says so.
    fn hears_audio(&self) -> bool {
        let role = match &self.answerer {
            Answerer::Seat(role) => *role,
            Answerer::Model(model) => {
                return self
                    .models
                    .router()
                    .and_then(|router| router.served(model))
                    .is_some_and(|(_, ladder)| ladder.supports(model, &LlmCapability::AudioInput));
            }
        };
        let Some(seat) = self.models.seat(role) else {
            return false;
        };
        let declared = match self.vault.model_manifest() {
            Ok(Some(manifest)) => manifest
                .binding(role)
                .is_ok_and(|binding| binding.reads_audio),
            Ok(None) => true,
            Err(_) => false,
        };
        declared
            && self
                .models
                .route_role(&self.vault, role, seat)
                .is_ok_and(|route| {
                    route
                        .ladder
                        .supports(&route.model, &LlmCapability::AudioInput)
                })
    }

    /// The model a call names and where it runs: the seat's, or the one
    /// model's as the router serves it.
    fn target(&self) -> oneiron::Result<(ModelId, ModelLocality)> {
        match &self.answerer {
            Answerer::Seat(role) => self
                .models
                .seat(*role)
                .map(|seat| (seat.model.clone(), seat.locality))
                .ok_or_else(|| failed("the seat is gone")),
            Answerer::Model(model) => self
                .models
                .router()
                .and_then(|router| router.locality(model))
                .map(|locality| (model.clone(), locality))
                .ok_or_else(|| failed("the model is gone")),
        }
    }

    /// `request` admitted, and the ladder that serves it: the seat's route
    /// under the vault's live model policy, or the one model under the
    /// policy a raw call naming it meets.
    fn admit(&self, request: LlmRequest) -> oneiron::Result<(Arc<OfferLadder>, LlmRequest)> {
        match &self.answerer {
            Answerer::Seat(role) => {
                let admitted = self
                    .models
                    .admit_role(&self.vault, *role, request)
                    .map_err(|refusal| failed(format!("refused: {refusal}")))?;
                Ok((admitted.ladder, admitted.request))
            }
            Answerer::Model(model) => {
                let (locality, ladder) = self
                    .models
                    .router()
                    .and_then(|router| router.served(model))
                    .ok_or_else(|| failed("the model is gone"))?;
                let authorized = self
                    .vault
                    .authorize_raw_inference(
                        request,
                        &HostInferenceContext {
                            binding: HostInferenceBinding::Advertised {
                                model: model.clone(),
                                locality,
                            },
                            extraction_egress: None,
                        },
                    )
                    .map_err(|error| failed(format!("refused: {error}")))?;
                Ok((ladder, authorized.into_request()))
            }
        }
    }

    fn request(&self, call: &DecisionCall<'_>) -> oneiron::Result<LlmRequest> {
        let (model, locality) = self.target()?;
        let purpose = CallPurpose::Other {
            name: PURPOSE.to_owned(),
        };
        // Each clip goes in as audio after the line naming it; its state
        // field holds that name, as Local vision's image fields do.
        let mut state = call.state.clone();
        let mut content = Vec::with_capacity(call.audio.len() * 2 + 1);
        for clip in call.audio {
            let reference = format!("audio:{}", clip.name);
            state[clip.name.as_str()] = json!(reference);
            content.push(ContentPart::Text { text: reference });
            content.push(ContentPart::Audio {
                media_type: clip.media_type.clone(),
                data: clip.base64(),
            });
        }
        let state = serde_json::to_string(&state).map_err(failed)?;
        // A yes/no question's criteria triple, as the rubric it is judged by.
        let rubric = QuestionCriteria::for_call(call)
            .map(|criteria| format!("{}\n", criteria.rubric()))
            .unwrap_or_default();
        content.push(ContentPart::Text {
            text: format!(
                "Question: {}\n{}\n{rubric}State (JSON): {state}\n{}",
                call.question.text,
                contract_line(&call.question.contract),
                self.reply.instructions(),
            ),
        });
        Ok(LlmRequest {
            model,
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality,
            },
            messages: vec![
                message(LlmMessageRole::System, self.wording.clone()),
                LlmMessage {
                    role: LlmMessageRole::User,
                    content,
                },
            ],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        })
    }
}

/// What the question takes, in one line for the model.
fn contract_line(contract: &AnswerContract) -> String {
    match contract {
        AnswerContract::Noul => "Answer yes or no.".to_owned(),
        AnswerContract::Choice { options } => {
            format!("Answer with exactly one of: {}.", options.join(", "))
        }
        AnswerContract::Score { min, max } => {
            format!("Answer with one number from {min} to {max}.")
        }
        AnswerContract::Box => "Answer with a box.".to_owned(),
        AnswerContract::Point => "Answer with a point.".to_owned(),
    }
}

impl BigReply {
    fn instructions(self) -> &'static str {
        match self {
            Self::Json => {
                "Reply with one JSON object and nothing else: {\"answer\": <your answer>, \"probability\": <how sure you are, from 0 to 1>}."
            }
            Self::Lines => {
                "Reply with two lines and nothing else:\nanswer: <your answer>\nprobability: <how sure you are, from 0 to 1>"
            }
        }
    }

    /// The reply's answer and probability, as the model wrote them.
    fn read(self, text: &str) -> Option<(Value, f64)> {
        match self {
            Self::Json => {
                let start = text.find('{')?;
                let end = text.rfind('}')?;
                let reply: Value = serde_json::from_str(text.get(start..=end)?).ok()?;
                Some((
                    reply.get("answer")?.clone(),
                    probability(reply.get("probability")?)?,
                ))
            }
            Self::Lines => {
                let (mut answer, mut sure) = (None, None);
                for line in text.lines() {
                    let Some((key, value)) = line.split_once(':') else {
                        continue;
                    };
                    let value = value.trim();
                    match key.trim().to_ascii_lowercase().as_str() {
                        "answer" => answer = Some(Value::String(value.to_owned())),
                        "probability" => sure = probability(&Value::String(value.to_owned())),
                        _ => {}
                    }
                }
                Some((answer?, sure?))
            }
        }
    }
}

/// A probability written as a number or a string, `0.8` or `80%`.
fn probability(value: &Value) -> Option<f64> {
    let p = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => match text.trim().strip_suffix('%') {
            Some(percent) => percent.trim().parse::<f64>().ok()? / 100.0,
            None => text.trim().parse().ok()?,
        },
        _ => return None,
    };
    (p.is_finite() && (0.0..=1.0).contains(&p)).then_some(p)
}

/// The written answer as one the contract takes.
fn typed(contract: &AnswerContract, answer: &Value) -> Option<DecisionAnswer> {
    let text = answer
        .as_str()
        .map(|text| text.trim().trim_matches(['"', '\'', '.']).to_owned());
    match contract {
        AnswerContract::Choice { options } => {
            let text = text?;
            options
                .iter()
                .find(|option| option.eq_ignore_ascii_case(&text))
                .map(|option| DecisionAnswer::Choice(option.clone()))
        }
        AnswerContract::Noul => match answer {
            Value::Bool(yes) => Some(DecisionAnswer::Noul(*yes)),
            _ => match text?.to_ascii_lowercase().as_str() {
                "yes" | "true" => Some(DecisionAnswer::Noul(true)),
                "no" | "false" => Some(DecisionAnswer::Noul(false)),
                _ => None,
            },
        },
        AnswerContract::Score { min, max } => {
            let score = match answer {
                Value::Number(number) => number.as_f64()?,
                _ => text?.parse().ok()?,
            };
            (score.is_finite() && score >= *min && score <= *max)
                .then_some(DecisionAnswer::Score(score))
        }
        AnswerContract::Box | AnswerContract::Point => None,
    }
}

fn abstained() -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Abstain,
        probability: None,
        paired: None,
        person: None,
    }
}

impl DecisionModel for BigModel {
    fn capability(&self) -> ProviderCapability {
        ProviderCapability::default()
    }

    fn reads_audio(&self) -> bool {
        self.hears_audio()
    }

    /// The seat routes to, or the one model is, a third party's model.
    fn leaves_host(&self) -> bool {
        self.target()
            .is_ok_and(|(_, locality)| locality == ModelLocality::ThirdParty)
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        if call.question.contract.locates() {
            return Ok(abstained());
        }
        let request = self.request(call)?;
        // A route the vault narrowed past what this server serves ends the
        // call here, before anything leaves.
        let (ladder, request) = self.admit(request)?;
        let left = call.deadline.decision_time_left();
        if left.is_zero() {
            return Err(failed("admitted after the work time"));
        }
        // Inside a verdict, the caller's own line (FIX 1123).
        let run = self.models.undeclared_run(
            format!("{PURPOSE}:{}", EntityId::now().to_hex()),
            crate::decision_verdict::rung_meter(&self.meter),
        );
        let response = self
            .runtime
            .block_on(async {
                match &self.answerer {
                    Answerer::Seat(_) => {
                        ladder
                            .generate_within(&run, request, None, &|| true, left)
                            .await
                    }
                    Answerer::Model(_) => {
                        ladder
                            .generate_exact_within(&run, request, None, &|| true, left)
                            .await
                    }
                }
            })
            .map_err(|error| failed(format!("the seat failed: {error}")))?;
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let Some((answer, probability)) = self.reply.read(&text) else {
            return Ok(abstained());
        };
        Ok(match typed(&call.question.contract, &answer) {
            Some(answer) => ProviderDecision {
                answer,
                probability: Some(probability),
                paired: None,
                person: None,
            },
            None => abstained(),
        })
    }
}
