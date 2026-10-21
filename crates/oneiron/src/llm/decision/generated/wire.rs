//! A generated read's wire names (FIX 7506): what the request shows in place of each
//! question's id and each choice option, and how the reply's names read back. A caller with
//! no table shows every id and option as it is. A caller with one shows the table's labels
//! and binds the table into the request's identity, so a memoized reply is read only
//! against the table it was asked under. Questions, options, answers and receipts stay
//! canonical: an answer is the canonical option at the index its label was shown at.

use serde_json::Value;

use super::super::{AnswerContract, DecisionQuestion};
use crate::EntityId;
use crate::llm::LlmRequest;

/// One read's labels for the ids and options its request would show. The caller owns the
/// table; the read only looks names up in it, both ways.
pub trait DecisionWireLabels: Sync {
    /// The label the wire shows in place of `question`'s id; none shows the id.
    fn question_label(&self, question: EntityId) -> Option<String>;

    /// The question a reply's `label` names: the inverse of [`Self::question_label`].
    fn question_for_label(&self, label: &str) -> Option<EntityId>;

    /// What the wire shows for `question`'s choice option at `index`, `option` canonically;
    /// none shows the option as it is.
    fn choice_option(&self, question: EntityId, index: usize, option: &str) -> Option<String>;

    /// Binds this table into `request`'s identity.
    fn bind(&self, request: &mut LlmRequest);
}

/// How the wire names `question`.
pub(super) fn question_key(question: EntityId, labels: Option<&dyn DecisionWireLabels>) -> String {
    labels
        .and_then(|labels| labels.question_label(question))
        .unwrap_or_else(|| question.to_hex())
}

/// `question`'s `canonical` labels as the wire shows them, in the same order.
pub(super) fn shown_labels(
    question: &DecisionQuestion,
    canonical: &[&str],
    labels: Option<&dyn DecisionWireLabels>,
) -> Vec<String> {
    canonical
        .iter()
        .enumerate()
        .map(|(index, option)| {
            labels
                .filter(|_| matches!(question.contract, AnswerContract::Choice { .. }))
                .and_then(|labels| labels.choice_option(question.id, index, option))
                .unwrap_or_else(|| (*option).to_owned())
        })
        .collect()
}

/// `question`'s entry in the reply object `value`: under its id, or, when the table labels
/// it, under the key the table reads back as it.
pub(super) fn entry<'v>(
    value: &'v Value,
    question: EntityId,
    labels: Option<&dyn DecisionWireLabels>,
) -> Option<&'v Value> {
    match labels {
        Some(labels) if labels.question_label(question).is_some() => {
            value.as_object()?.iter().find_map(|(key, entry)| {
                (labels.question_for_label(key) == Some(question)).then_some(entry)
            })
        }
        _ => value.get(question.to_hex()),
    }
}
