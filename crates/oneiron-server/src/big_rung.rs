//! The big model on the decision ladder's Big rung (ARCH-0076, OF-495). A
//! typed question goes to the seat `[models.decisions.big]` names as one
//! admitted model call: routed against the vault's live model policy, sent
//! under its own run on the rung's meter, worded by the host's
//! configuration and answered in its reply format. The answer and its
//! probability are parsed out of the generated text. A reply that names
//! nothing the question takes, or no probability, abstains. The rung hears
//! a call's audio clips when the model its seat routes to is bound as
//! hearing them.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionCall, DecisionModel, DecisionRung, ProviderCapability,
    ProviderDecision, ProviderPin,
};
use oneiron::llm::manifest::ModelRole;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    EntityId, Error, LlmCapability, LlmMessage, LlmMessageRole, LlmRequest, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault,
};
use serde_json::{Value, json};

use crate::config::models::{BigReply, BigSettings};
use crate::models::ModelRuntime;

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

/// The big model, answering typed questions on its seat.
pub(crate) struct BigModel {
    models: Arc<ModelRuntime>,
    vault: Arc<Vault>,
    role: ModelRole,
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
            role: settings.role,
            wording: settings.wording.clone(),
            reply: settings.reply,
            models,
            vault,
            runtime,
            pin,
        })
    }

    pub(crate) fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    /// Whether the model the seat routes to hears audio: the vault
    /// manifest's binding of the role says so (with no manifest the seat is
    /// the binding, and its provider's explicit `audio_input` capability is
    /// the declaration), and every rung serving that model admits
    /// [`LlmCapability::AudioInput`].
    fn hears_audio(&self) -> bool {
        let Some(seat) = self.models.seat(self.role) else {
            return false;
        };
        let declared = match self.vault.model_manifest() {
            Ok(Some(manifest)) => manifest
                .binding(self.role)
                .is_ok_and(|binding| binding.reads_audio),
            Ok(None) => true,
            Err(_) => false,
        };
        declared
            && self
                .models
                .route_role(&self.vault, self.role, seat)
                .is_ok_and(|route| {
                    route
                        .ladder
                        .supports(&route.model, &LlmCapability::AudioInput)
                })
    }

    fn request(&self, call: &DecisionCall<'_>) -> oneiron::Result<LlmRequest> {
        let seat = self
            .models
            .seat(self.role)
            .ok_or_else(|| failed("the seat is gone"))?;
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
        content.push(ContentPart::Text {
            text: format!(
                "Question: {}\n{}\nState (JSON): {state}\n{}",
                call.question.text,
                contract_line(&call.question.contract),
                self.reply.instructions(),
            ),
        });
        Ok(LlmRequest {
            model: seat.model.clone(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, ModelTierRef(PURPOSE.to_owned())),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: seat.locality,
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

    /// The seat routes to a third party's model.
    fn leaves_host(&self) -> bool {
        self.models
            .seat(self.role)
            .is_some_and(|seat| seat.locality == ModelLocality::ThirdParty)
    }

    fn decide(&self, call: &DecisionCall<'_>) -> oneiron::Result<ProviderDecision> {
        if call.question.contract.locates() {
            return Ok(abstained());
        }
        let request = self.request(call)?;
        // A route the vault narrowed past what this server serves ends the
        // call here, before anything leaves.
        let admitted = self
            .models
            .admit_role(&self.vault, self.role, request)
            .map_err(|refusal| failed(format!("refused: {refusal}")))?;
        let left = call.deadline.decision_time_left();
        if left.is_zero() {
            return Err(failed("admitted after the work time"));
        }
        let run = self.models.undeclared_run(
            format!("{PURPOSE}:{}", EntityId::now().to_hex()),
            self.meter.clone(),
        );
        let response = self
            .runtime
            .block_on(
                admitted
                    .ladder
                    .generate_within(&run, admitted.request, None, &|| true, left),
            )
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
