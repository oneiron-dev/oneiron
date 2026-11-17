//! The engine's projection of one bound settlement ask (FIX 7506 P2).
//!
//! `oneiron_dreamer::conflict_settle` chooses whole asks, pages and rounds;
//! the engine builds each ask and runs it for bound `ai.verdict`. Each
//! stored member and retained alternative has a call-local `C` label and
//! `keep:C<n>` option. Canonical questions and answers keep their hex ids,
//! while every offered value rides whole (Rule 5, FIX 7637).

use serde_json::{Map, Value as Json, json};

use super::decision_pages::PageAnswer;
use super::{DISMISS, ESCALATE, HOLD_BOTH, KEEP_PREFIX, OpenConflict};
use crate::claim::{ClaimSource, claim_surfaceable};
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::value_projection::rmpv_to_json;
use crate::error::Result;
use crate::model_decision::catalogue::CONFLICT_SETTLE;
use crate::model_decision::{AnswerContract, DecisionQuestion};
use crate::{EntityId, Vault};

/// One stored member or retained alternative as a settlement ask shows it:
/// whether a Keep may name it, and its fields, whole.
pub(crate) struct SettleRow {
    pub(crate) id: EntityId,
    pub(crate) keep: bool,
    fields: Map<String, Json>,
}

impl SettleRow {
    /// The row as one call shows it, by `label`.
    fn shown(&self, label: &str) -> Json {
        let mut row = Map::new();
        row.insert("id".to_owned(), Json::from(label));
        let keep_option = self.keep.then(|| format!("{KEEP_PREFIX}{label}"));
        row.insert("keep_option".to_owned(), json!(keep_option));
        row.extend(self.fields.clone());
        Json::Object(row)
    }
}

/// `value`'s fields, when it is an object.
fn fields(value: Json) -> Map<String, Json> {
    match value {
        Json::Object(fields) => fields,
        _ => Map::new(),
    }
}

/// Reads every row a settlement of `conflict` asks about, in the conflict's order:
/// each stored member, keepable while it stands, then each retained
/// alternative. A candidate the round dropped rides as retained, never as a
/// stored claim; keeping it lands it (FIX 496). One whose staged Keep the
/// owner declined is the owner's to keep again, never this ladder's (FIX
/// 7072). Every keepable row is offered: none is dropped for room.
pub(crate) fn settle_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    conflict: &OpenConflict,
) -> Result<Vec<SettleRow>> {
    let mut rows = Vec::new();
    for id in &conflict.members {
        let Some(body) = vault.get_claim_in_txn(txn, id)? else {
            continue;
        };
        rows.push(SettleRow {
            id: *id,
            keep: claim_surfaceable(&body),
            fields: fields(json!({
                "predicate": body.predicate,
                "value": rmpv_to_json(&body.value),
                "source": body.source.map(ClaimSource::as_str),
                "approval": body.approval.as_str(),
                "confidence": body.confidence,
                "valid_from": body.valid_from,
                "valid_to": body.valid_to,
            })),
        });
    }
    for alternative in conflict
        .alternatives
        .iter()
        .filter(|alternative| alternative.declined.is_empty())
    {
        rows.push(SettleRow {
            id: alternative.id,
            keep: true,
            fields: fields(json!({
                "retained": true,
                "predicate": alternative.predicate,
                "value": rmpv_to_json(&alternative.value),
                "source": alternative.source.as_str(),
                "confidence": alternative.confidence,
            })),
        });
    }
    Ok(rows)
}

/// Where one ask sits among its conflict's asks: its round, page and the
/// round's page count when the conflict is asked in more than one, and what
/// the pages of the round before answered.
pub(crate) struct AskPart<'p> {
    pub(crate) at: Option<(usize, usize, usize)>,
    pub(crate) before: &'p [PageAnswer],
}

/// The state an ask over `rows` reads, each row by the label `labels`
/// assigns it here: the contested predicates and every row whole, with the
/// ask's page and the answers of the round before when it has them.
fn state_of(
    conflict: &OpenConflict,
    rows: &[&SettleRow],
    part: &AskPart<'_>,
    labels: &mut CallLabelMap,
) -> Json {
    let members: Vec<Json> = rows
        .iter()
        .map(|row| row.shown(&labels.assign(LabelKind::Claim, row.id).to_string()))
        .collect();
    let mut state = Map::new();
    state.insert("predicates".to_owned(), json!(conflict.predicates));
    state.insert("members".to_owned(), Json::Array(members));
    if let Some((_, page, pages)) = part.at.filter(|(_, _, pages)| *pages > 1) {
        state.insert("page".to_owned(), json!(page + 1));
        state.insert("pages".to_owned(), json!(pages));
    }
    if !part.before.is_empty() {
        let labels: &CallLabelMap = labels;
        let answers: Vec<String> = part
            .before
            .iter()
            .map(|answer| answer.shown(labels))
            .collect();
        state.insert("page_answers".to_owned(), json!(answers));
    }
    Json::Object(state)
}

/// One settlement ask: its canonical question, the state the ladder reads,
/// and the call's labels.
pub(crate) struct SettleAsk {
    pub(crate) question: DecisionQuestion,
    pub(super) state: Json,
    pub(super) labels: CallLabelMap,
}

impl SettleAsk {
    /// The ask over `rows` of `conflict` at `part`, worded `wording`: every
    /// row whole, and a keep option for each one that may be kept. The
    /// question is keyed by the contested predicates, so each learns its own
    /// bands; an ask that is one of several adds its round and page.
    pub(crate) fn over(
        conflict: &OpenConflict,
        wording: &str,
        rows: &[&SettleRow],
        part: &AskPart<'_>,
    ) -> Result<Self> {
        let mut labels = CallLabelMap::default();
        let state = state_of(conflict, rows, part, &mut labels);
        let keepable: Vec<EntityId> = rows
            .iter()
            .filter(|row| row.keep)
            .map(|row| row.id)
            .collect();
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
        let page = part.at.map(|(round, page, _)| format!("{round}.{page}"));
        let mut parts: Vec<&[u8]> = vec![key.as_bytes()];
        if let Some(page) = &page {
            parts.push(b"page".as_slice());
            parts.push(page.as_bytes());
        }
        let question = CONFLICT_SETTLE.question(
            &parts,
            wording.to_owned(),
            AnswerContract::Choice { options },
        )?;
        labels.show_choices(question.id, shown);
        Ok(Self {
            question,
            state,
            labels,
        })
    }
}
