//! Moved from `crates/oneiron/src/llm/step/public.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::model_step_submission::ModelStepRetryPolicy;
pub use crate::store::model_step_submission::ModelStepSubmit;
use oneiron_model::llm::LlmRequest;
use oneiron_store::model_step_record::DREAMER_STEP_RETRY_BACKOFF_MS;
pub use oneiron_store::model_step_record::ModelStepCheckpoint;
pub use oneiron_store::model_step_record::SettledStepRequest;
pub use oneiron_store::model_step_record::SettledStepView;
use oneiron_store::model_step_record::StepProgression;
pub use oneiron_store::model_step_submission::ModelStepFailure;
pub use oneiron_store::model_step_submission::ModelStepFailureClass;
pub use oneiron_store::model_step_submission::ModelStepResult;
pub use oneiron_store::model_step_submission::StepBudgetRefusal;
use serde::Deserialize;
use serde::Serialize;

impl Default for ModelStepRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: (DREAMER_STEP_RETRY_BACKOFF_MS.len() + 1) as u8,
        }
    }
}

/// What `ai.steps.submit` takes: one step, and the live run a run's own
/// actor submits it on. The vault owner names no run. The step is a model
/// request, or a run's typed decision (FIX RUN-STEP-TYPED-DECISION-MODE):
/// exactly one of `request` and `decision`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepSubmitRequest {
    /// The handle of the caller's attached live run. Absent: the call is
    /// the vault owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_run: Option<String>,
    pub step_key: String,
    /// A model step's request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<LlmRequest>,
    /// A live run's typed question, in place of `request`: the host's
    /// decision ladder writes the step's request and reads its answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionStepQuestion>,
    #[serde(default)]
    pub retry: ModelStepRetryPolicy,
}

/// A live run's typed question, asked as a step of its own: the ladder's
/// generated read (ARCH-0076 decide()), its one generation the run's own
/// model step on `model`. The answer is a yes or no, one of the options, or
/// a score in the range, as the contract says.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionStepQuestion {
    /// The model the generation asks: one the run's definition lists.
    pub model: super::super::ModelId,
    /// The question, as the model reads it.
    pub question: String,
    /// What the answer is: `{"kind": "noul"}`, yes or no with P(yes), when
    /// absent; `{"kind": "choice", "options": [...]}`, one of its labels;
    /// `{"kind": "score", "min": 1, "max": 5}`, one number in that range.
    #[serde(default = "yes_no")]
    pub contract: oneiron_store::model_decision::AnswerContract,
    /// What the question reads, as the run gives it. It is part of the
    /// step's request: a retry of the key names the same state, its keys in
    /// the same order, or it is refused as another request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<serde_json::Value>,
}

fn yes_no() -> oneiron_store::model_decision::AnswerContract {
    oneiron_store::model_decision::AnswerContract::Noul
}

/// One step `ai.steps.submit` asks for.
#[derive(Debug, Clone)]
pub enum StepSubmit {
    /// A model step, as it freezes.
    Model(ModelStepSubmit),
    /// A live run's typed decision step.
    Decision(DecisionStepSubmit),
}

/// A typed decision step: its key, its question and the attempts its one
/// generation may make.
#[derive(Debug, Clone)]
pub struct DecisionStepSubmit {
    pub step_key: String,
    pub decision: DecisionStepQuestion,
    pub retry: ModelStepRetryPolicy,
}

impl ModelStepSubmitRequest {
    /// The live run the call names, and the step it asks for. `None` when
    /// it names both a request and a decision, or neither.
    #[must_use]
    pub fn into_parts(self) -> Option<(Option<String>, StepSubmit)> {
        let step = match (self.request, self.decision) {
            (Some(request), None) => StepSubmit::Model(ModelStepSubmit {
                step_key: self.step_key,
                request,
                retry: self.retry,
            }),
            (None, Some(decision)) => StepSubmit::Decision(DecisionStepSubmit {
                step_key: self.step_key,
                decision,
                retry: self.retry,
            }),
            _ => return None,
        };
        Some((self.live_run, step))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelStepReceiptRequest {
    /// The handle of the caller's attached live run, for a step that run
    /// submitted. Absent: the call is the vault owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_run: Option<String>,
    pub step_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStepReceipt {
    pub step_ref: String,
    pub step_hash: String,
    pub model: super::super::ModelId,
    pub retry: ModelStepRetryPolicy,
    pub progression: Option<StepProgression>,
    /// None while an admitted request is running or recovering.
    pub result: Option<ModelStepResult>,
}

/// What `ai.steps.submit` answers: the step's receipt, and beside it a
/// decision step's typed answer, as the ladder read the step's generation
/// on the submit that asked it or on a retry of its key. A retry reads the
/// same answer and probability; its decision receipt's clock is the retry's
/// own. No decision when the step kept no reply (its receipt says why) or
/// its reply did not read as an answer, and none for a model step;
/// `ai.steps.receipt` reads the receipt alone.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StepSubmitAnswer {
    #[serde(flatten)]
    pub receipt: ModelStepReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<oneiron_wake_contract::llm::decision::types::TypedDecision>,
}

impl From<ModelStepReceipt> for StepSubmitAnswer {
    fn from(receipt: ModelStepReceipt) -> Self {
        Self {
            receipt,
            decision: None,
        }
    }
}
