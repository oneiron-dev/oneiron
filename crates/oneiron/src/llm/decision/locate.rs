//! Presence before coordinates (owner point 4). A Box or Point question first asks the
//! host's presence question ("is the target in the image?") over the same images, evidence,
//! dial and clock, with the coordinate question's wording in the [`LOCATE_FIELD`] state
//! field. Only a confident yes, with no person asked, starts the coordinates. A confident
//! no is the found absence (`Box(None)`, `Point(None)`), and anything else abstains. Both
//! decisions come back together, each with its own receipt.

use super::policy::{DecisionBandPolicy, Reversibility};
use super::types::invalid;
use super::{
    AnswerContract, DecisionAnswer, DecisionDial, DecisionImage, DecisionLadder, DecisionQuestion,
    HumanAskReason, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The state field the presence question reads the coordinate question's wording from.
pub const LOCATE_FIELD: &str = "locate";

#[doc(hidden)]
pub use oneiron_records::llm::decision::locate::LocatedDecision;

impl DecisionLadder<'_> {
    /// One Box or Point question over `images`, presence first ([`Self::presence`]). With
    /// no presence question the coordinates are asked directly, as [`Self::run_images`]
    /// asks them.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's images, state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run_located(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<LocatedDecision> {
        let Some(absent) = question.contract.absent() else {
            return Err(invalid("not a Box or Point question"));
        };
        let locate = |state: &Value| {
            self.run_images(
                question,
                principal,
                evidence,
                images,
                state,
                dial,
                policy,
                reversibility,
                deadline,
            )
        };
        let Some(presence) = self.presence else {
            let location = locate(state)?;
            return Ok(LocatedDecision {
                presence: None,
                answer: location.answer.clone(),
                location: Some(location),
            });
        };
        if presence.contract != AnswerContract::Noul || presence.id == question.id {
            return Err(invalid("invalid presence question"));
        }
        let mut asked = state.clone();
        let fields = asked
            .as_object_mut()
            .ok_or_else(|| invalid("invalid decision state"))?;
        if fields
            .insert(
                LOCATE_FIELD.to_owned(),
                Value::String(question.text.clone()),
            )
            .is_some()
        {
            return Err(invalid("the state fills the presence question's field"));
        }
        let found = self.run_images(
            presence,
            principal,
            evidence,
            images,
            &asked,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        let confident = !found.in_band && found.human_ask.is_none();
        let (location, answer) = match found.answer {
            DecisionAnswer::Noul(true) if confident => {
                let location = locate(state)?;
                let answer = location.answer.clone();
                (Some(location), answer)
            }
            DecisionAnswer::Noul(false) if confident => (None, absent),
            _ => (None, DecisionAnswer::Abstain),
        };
        Ok(LocatedDecision {
            presence: Some(found),
            location,
            answer,
        })
    }
}
