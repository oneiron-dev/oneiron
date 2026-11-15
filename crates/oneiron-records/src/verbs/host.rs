//! Moved from `crates/oneiron/src/verbs/host.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::verbs::host::ask_image::*;
pub use crate::verbs::host::pack_setup::*;
use oneiron_model::llm::media::AiOperation;
use oneiron_model::llm::media::MediaJobState;
pub use oneiron_verb_wire::memory::hook_regen_doors::PackPutOutcome;
pub use oneiron_verb_wire::receipt::questions::AI_VERDICT_DEADLINE_MS;
pub use oneiron_verb_wire::verbs::host::AiAnswer;
pub use oneiron_verb_wire::verbs::host::AiCallRequest;
pub use oneiron_verb_wire::verbs::host::AiImageMask;
pub use oneiron_verb_wire::verbs::host::AiOptionsRequest;
pub use oneiron_verb_wire::verbs::host::AiPart;
pub use oneiron_verb_wire::verbs::host::AiVideoJobRequest;
pub use oneiron_verb_wire::verbs::host::AiVoice;
pub use oneiron_verb_wire::verbs::host::ChannelSubscriptionRequest;
pub use oneiron_verb_wire::verbs::host::ChannelSubscriptionRevokeRequest;
pub use oneiron_verb_wire::verbs::host::ChannelSubscriptionsRequest;
pub use oneiron_verb_wire::verbs::host::PackBytesFile;
pub use oneiron_verb_wire::verbs::host::PackFileDecodeError;
pub use oneiron_verb_wire::verbs::host::PackFileInput;
pub use oneiron_verb_wire::verbs::host::PackPutRequest;
pub use oneiron_verb_wire::verbs::host::PackRemoveRequest;
pub use oneiron_verb_wire::verbs::host::PackTextFile;
pub use oneiron_verb_wire::verbs::host::decode_pack_files;
use serde::Deserialize;
use serde::Serialize;

/// One connector event subscription of an agent, standing or revoked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSubscriptionRow {
    pub subscription: String,
    pub connector_key: String,
    pub connector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    pub active: bool,
}

/// `vault.connectors.subscriptions.list`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSubscriptions {
    pub agent: String,
    pub subscriptions: Vec<ChannelSubscriptionRow>,
}

/// `vault.connectors.subscriptions.revoke`'s answer: the subscription wakes
/// nothing more; its key stays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSubscriptionRevoked {
    pub subscription: String,
}

/// `ai.options`'s answer: each text seat's rungs and each media row that
/// serves the operation over those inputs, and what the media meter has left.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiOptions {
    pub options: Vec<serde_json::Value>,
    pub media_units_left: Option<u64>,
}

/// `ai.video`'s answer: the provider job its clip renders as.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVideoTicket {
    pub job: String,
    pub model: String,
    pub operation: AiOperation,
}

/// Where a video job stands; a finished one answers with its clip on every
/// poll until `ai.video.cancel` deletes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AiVideoJob {
    Queued,
    Running {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        progress: Option<u8>,
    },
    Done {
        answer: AiAnswer,
    },
    Failed {
        error: oneiron_model::llm::LlmError,
    },
}

impl From<MediaJobState> for AiVideoJob {
    fn from(state: MediaJobState) -> Self {
        match state {
            MediaJobState::Queued => Self::Queued,
            MediaJobState::Running { progress } => Self::Running { progress },
            MediaJobState::Done { response } => Self::Done {
                answer: response.into(),
            },
            MediaJobState::Failed { error } => Self::Failed { error },
        }
    }
}

/// `ai.video.cancel`'s answer: the job its provider was told to stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVideoCancelled {
    pub job: String,
}

/// `ai.verdict`'s answer: the ladder's answer on the request's contract, its
/// probability (P(yes) for a yes/no, else the answer's confidence; none for a
/// Box or a Point whose coordinates were not read), the rung whose answer
/// stands (none when the call abstained), and the decision's receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiVerdict {
    pub answer: oneiron_store::model_decision::DecisionAnswer,
    pub p: Option<f64>,
    pub rung: Option<oneiron_store::model_decision::DecisionRung>,
    pub receipt: oneiron_wake_contract::llm::decision::types::DecisionReceipt,
    /// A Box or Point call's presence step, when the host asked it: its own
    /// P(yes) and receipt. The receipt above is the coordinates' when they
    /// were read, else this step's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<oneiron_wake_contract::llm::decision::types::TypedDecision>,
    /// A routine step's outcome: act on a candidate or at a point, NONE,
    /// reobserve, or ask up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<crate::llm::decision::routine::RoutineOutcome>,
    /// A routine step's screenshot trigger: the subgoal's steps gave NONE or
    /// reobserve twice in a row, so the next observation takes a screenshot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub screenshot: bool,
    /// The Unix milliseconds this call's clock ended at: a routine program
    /// passes it on as the next step's `until_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    /// The bytes every text in the evidence views was cut to, when the views
    /// did not fit the ladder's state whole: the ladder read them cut. The
    /// refs, kinds and the caller's own state are never cut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_cut_at_bytes: Option<u64>,
}

impl From<oneiron_wake_contract::llm::decision::types::TypedDecision> for AiVerdict {
    fn from(decision: oneiron_wake_contract::llm::decision::types::TypedDecision) -> Self {
        Self {
            answer: decision.answer,
            p: decision.probability,
            rung: decision.receipt.time.and_then(|time| time.answered),
            receipt: decision.receipt,
            presence: None,
            outcome: None,
            screenshot: false,
            until_ms: None,
            evidence_cut_at_bytes: None,
        }
    }
}
pub mod ask_image;
pub mod pack_setup;
