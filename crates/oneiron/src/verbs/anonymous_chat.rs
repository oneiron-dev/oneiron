//! The anonymous-chat wire contract (OF-500, PRIVACY-08), shared by the
//! standalone HTTP handler, OpenAPI and the generated SDK. These are the
//! existing route's shapes: one text in, one reply or policy block out.
//! Neither notice channel is a durable receipt or a conversation turn.

use crate::off_record::anonymous_chat::{
    AnonymousChatBlockReason, AnonymousChatSkippedCheck, AnonymousChatTarget, AnonymousChatTurn,
};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::anonymous_chat::{
    AnonymousChatBlockReasonView, AnonymousChatRequest, AnonymousChatRequestTarget,
    AnonymousChatResponse, AnonymousChatSkippedCheckView,
};

impl From<AnonymousChatRequestTarget> for AnonymousChatTarget {
    fn from(target: AnonymousChatRequestTarget) -> Self {
        match target {
            AnonymousChatRequestTarget::HouseMind => Self::HouseMind,
            AnonymousChatRequestTarget::PlainModel => Self::PlainModel,
        }
    }
}

impl From<AnonymousChatSkippedCheck> for AnonymousChatSkippedCheckView {
    fn from(check: AnonymousChatSkippedCheck) -> Self {
        Self {
            input: check.input,
            reason: check.reason,
        }
    }
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
