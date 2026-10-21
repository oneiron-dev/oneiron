//! A parked conflict's settlement ask as the ladder reads it (FIX 7506 P2):
//! each stored member and retained alternative by a call-local `C` label,
//! each keep option shown as `keep:C<n>`. The question keeps its canonical
//! `keep:<id>` options. Only the model rungs see the labels, and an answer
//! reads back canonical before it settles anything.

use serde_json::json;

use super::{
    ConflictSettlement, DISMISS, ESCALATE, HOLD_BOTH, KEEP_PREFIX, MAX_KEEP_OPTIONS, OpenConflict,
};
use crate::claim::claim_surfaceable;
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::value_projection::rmpv_to_json;
use crate::error::Result;
use crate::llm::decision::catalogue::CONFLICT_SETTLE;
use crate::llm::decision::{AnswerContract, DecisionQuestion, cut_text, fit_state};
use crate::{EntityId, Vault};

/// One settlement ask: its canonical question, the state the ladder reads,
/// the call's labels, and the members a Keep may name.
pub(super) struct SettleAsk {
    pub(super) question: DecisionQuestion,
    pub(super) state: serde_json::Value,
    pub(super) labels: CallLabelMap,
    keepable: Vec<EntityId>,
}

impl SettleAsk {
    /// The ask over `conflict`, worded `wording`. Past the ladder's state
    /// bound, every member is still asked about, by label with its value's
    /// text cut to fit; a conflict whose labels alone pass the bound is the
    /// ladder's refusal. Only a standing member can be kept. The question is
    /// keyed by the contested predicates, so each learns its own bands.
    pub(super) fn of(vault: &Vault, conflict: &OpenConflict, wording: &str) -> Result<Self> {
        let mut labels = CallLabelMap::default();
        let txn = vault.store.env.read_txn()?;
        let mut members = Vec::new();
        let mut values = Vec::new();
        let mut keepable = Vec::new();
        for id in &conflict.members {
            let Some(body) = vault.get_claim_in_txn(&txn, id)? else {
                continue;
            };
            let standing = claim_surfaceable(&body);
            if standing && keepable.len() < MAX_KEEP_OPTIONS {
                keepable.push(*id);
            }
            let label = labels.assign(LabelKind::Claim, *id).to_string();
            let value = rmpv_to_json(&body.value);
            values.push((label.clone(), value.to_string()));
            members.push(json!({
                "id": label,
                "keep_option": standing.then(|| format!("{KEEP_PREFIX}{label}")),
                "predicate": body.predicate,
                "value": value,
                "source": body.source.map(|source| source.as_str()),
                "approval": body.approval.as_str(),
                "confidence": body.confidence,
                "valid_from": body.valid_from,
                "valid_to": body.valid_to,
            }));
        }
        drop(txn);
        // A candidate the round dropped rides as retained, never as a stored
        // claim; keeping it lands it (FIX 496). One whose staged Keep the
        // owner declined is the owner's to keep again, never this ladder's
        // (FIX 7072).
        for alternative in conflict
            .alternatives
            .iter()
            .filter(|alternative| alternative.declined.is_empty())
        {
            let label = labels.assign(LabelKind::Claim, alternative.id).to_string();
            let keep_option = if keepable.len() < MAX_KEEP_OPTIONS {
                keepable.push(alternative.id);
                Some(format!("{KEEP_PREFIX}{label}"))
            } else {
                None
            };
            let value = rmpv_to_json(&alternative.value);
            values.push((label.clone(), value.to_string()));
            members.push(json!({
                "id": label,
                "keep_option": keep_option,
                "retained": true,
                "predicate": alternative.predicate,
                "value": value,
                "source": alternative.source.as_str(),
                "confidence": alternative.confidence,
            }));
        }
        // Whole, each member rides with its claim's fields; past the bound, by
        // label with its value's canonical text cut to fit, never one left out.
        let whole = json!({
            "predicates": conflict.predicates,
            "members": members,
        });
        let longest = values.iter().map(|(_, text)| text.len()).max().unwrap_or(0);
        let state = fit_state(longest, |cut| {
            if cut.is_none() {
                return whole.clone();
            }
            let members: Vec<_> = values
                .iter()
                .map(|(id, text)| json!({"id": id, "value": cut_text(text, cut)}))
                .collect();
            json!({
                "predicates": conflict.predicates,
                "members": members,
                "cut_at_bytes": cut,
            })
        });
        let mut options: Vec<String> = [HOLD_BOTH, DISMISS, ESCALATE]
            .iter()
            .map(|label| (*label).to_owned())
            .collect();
        let mut shown = options.clone();
        for id in &keepable {
            options.push(format!("{KEEP_PREFIX}{}", id.to_hex()));
            shown.push(format!(
                "{KEEP_PREFIX}{}",
                labels.assign(LabelKind::Claim, *id)
            ));
        }
        let key = conflict.predicates.join("\n");
        let question = CONFLICT_SETTLE.question(
            &[key.as_bytes()],
            wording.to_owned(),
            AnswerContract::Choice { options },
        )?;
        labels.show_choices(question.id, shown);
        Ok(Self {
            question,
            state,
            labels,
            keepable,
        })
    }

    /// The settlement the canonical `answer` names: hold both, dismiss, or
    /// keep a member this ask offered. None for escalate or anything else.
    pub(super) fn settlement(&self, answer: &str) -> Option<ConflictSettlement> {
        match answer {
            HOLD_BOTH => Some(ConflictSettlement::HoldBoth),
            DISMISS => Some(ConflictSettlement::Dismiss),
            other => other.strip_prefix(KEEP_PREFIX).and_then(|hex| {
                self.keepable
                    .iter()
                    .find(|id| id.to_hex() == hex)
                    .map(|id| ConflictSettlement::Keep(*id))
            }),
        }
    }
}
