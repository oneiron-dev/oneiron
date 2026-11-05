//! Typed Arc line-versus-claim questions over one complete narrative input.

use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::support::invalid_consolidation;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::model_decision::catalogue::ARC_OPEN_TURN;
use crate::model_decision::{AnswerContract, DecisionQuestion, MAX_DECISION_STATE_BYTES};

pub(super) struct OpenQuestion {
    pub(super) turn: EntityId,
    pub(super) question: DecisionQuestion,
    pub(super) state: serde_json::Value,
    pub(super) labels: CallLabelMap,
}

impl OpenQuestion {
    /// An oversized whole context remains the narrative reader's; no value is cut.
    pub(super) fn of(
        wording: &str,
        work: &[u8],
        turn: EntityId,
        input: &serde_json::Value,
        labels: &CallLabelMap,
    ) -> Result<Option<Self>> {
        let Some(turn_label) = labels.label(LabelKind::Turn, turn) else {
            return Ok(None);
        };
        let question = ARC_OPEN_TURN.question(
            &[work, turn.as_bytes()],
            wording.to_owned(),
            AnswerContract::Noul,
        )?;
        let mut labels = labels.clone();
        let question_label = labels.assign(LabelKind::Question, question.id);
        let state = serde_json::json!({
            "input": input,
            "opening": {"question": question_label.to_string(), "turn": turn_label.to_string()},
        });
        let bytes = serde_json::to_vec(&state)
            .map_err(|_| invalid_consolidation("arc opening input encoding"))?;
        if bytes.len() > MAX_DECISION_STATE_BYTES {
            return Ok(None);
        }
        Ok(Some(Self {
            turn,
            question,
            state,
            labels,
        }))
    }
}
