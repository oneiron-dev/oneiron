//! The anonymous-chat wire contract (OF-500, PRIVACY-08), shared by the
//! standalone HTTP handler, OpenAPI and the generated SDK. These are the
//! existing route's shapes: one text in, one reply or policy block out.
//! Neither notice channel is a durable receipt or a conversation turn.

use serde::{Deserialize, Serialize};

use crate::ModelId;
use crate::off_record::anonymous_chat::{
    AnonymousChatBlockReason, AnonymousChatSkippedCheck, AnonymousChatTarget, AnonymousChatTurn,
};
use crate::policy_model::PolicySkipReason;
use crate::store::GateSystemNoticeRecord;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnonymousChatRequestTarget {
    #[default]
    HouseMind,
    PlainModel,
}

impl From<AnonymousChatRequestTarget> for AnonymousChatTarget {
    fn from(target: AnonymousChatRequestTarget) -> Self {
        match target {
            AnonymousChatRequestTarget::HouseMind => Self::HouseMind,
            AnonymousChatRequestTarget::PlainModel => Self::PlainModel,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnonymousChatRequest {
    pub text: String,
    #[serde(default)]
    pub target: AnonymousChatRequestTarget,
    /// A configured provider model id, required only for plain_model.
    pub model: Option<ModelId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnonymousChatResponse {
    Reply {
        content: String,
        notices: Vec<GateSystemNoticeRecord>,
        skipped_checks: Vec<AnonymousChatSkippedCheckView>,
        /// The same notices, in the same order, for the model's notice
        /// channel. Neither channel is a chat message or a retained turn.
        model_notices: Vec<GateSystemNoticeRecord>,
    },
    Blocked {
        input: bool,
        notice: Box<GateSystemNoticeRecord>,
        preceding_notices: Vec<GateSystemNoticeRecord>,
        reason: AnonymousChatBlockReasonView,
        model_notices: Vec<GateSystemNoticeRecord>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AnonymousChatSkippedCheckView {
    pub input: bool,
    pub reason: PolicySkipReason,
}

impl From<AnonymousChatSkippedCheck> for AnonymousChatSkippedCheckView {
    fn from(check: AnonymousChatSkippedCheck) -> Self {
        Self {
            input: check.input,
            reason: check.reason,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnonymousChatBlockReasonView {
    Policy,
    HumanReviewUnavailable,
}

impl From<AnonymousChatTurn> for AnonymousChatResponse {
    fn from(turn: AnonymousChatTurn) -> Self {
        match turn {
            AnonymousChatTurn::Reply {
                content,
                notices,
                skipped_checks,
            } => Self::Reply {
                content,
                model_notices: notices.clone(),
                notices,
                skipped_checks: skipped_checks
                    .into_iter()
                    .map(AnonymousChatSkippedCheckView::from)
                    .collect(),
            },
            AnonymousChatTurn::Blocked {
                input,
                notice,
                preceding_notices,
                reason,
            } => {
                let mut model_notices = preceding_notices.clone();
                model_notices.push((*notice).clone());
                Self::Blocked {
                    input,
                    notice,
                    preceding_notices,
                    reason: match reason {
                        AnonymousChatBlockReason::Policy => AnonymousChatBlockReasonView::Policy,
                        AnonymousChatBlockReason::HumanReviewUnavailable => {
                            AnonymousChatBlockReasonView::HumanReviewUnavailable
                        }
                    },
                    model_notices,
                }
            }
        }
    }
}
