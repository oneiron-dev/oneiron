//! A parked conflict's settlement ask as the ladder reads it (FIX 7506 P2):
//! each stored member and retained alternative by a call-local `C` label,
//! each keep option shown as `keep:C<n>`. The question keeps its canonical
//! `keep:<id>` options. Only the model rungs see the labels, and an answer
//! reads back canonical before it settles anything. Every value rides whole
//! (Rule 5, FIX 7637): a conflict one ask does not hold is asked in pages
//! (`decision_pages`), each page an ask of its own over some of its rows.

use serde_json::{Map, Value as Json, json};

use super::decision_pages::{PageAnswer, json_len};
use super::{ConflictSettlement, DISMISS, ESCALATE, HOLD_BOTH, KEEP_PREFIX, OpenConflict};
use crate::claim::{ClaimSource, claim_surfaceable};
use crate::dreamer_consolidation::call_labels::{CallLabelMap, LabelKind};
use crate::dreamer_consolidation::value_projection::rmpv_to_json;
use crate::error::Result;
use crate::llm::decision::catalogue::CONFLICT_SETTLE;
use crate::llm::decision::{AnswerContract, DecisionQuestion};
use crate::{EntityId, Vault};

/// One stored member or retained alternative as a settlement ask shows it:
/// whether a Keep may name it, and its fields, whole.
pub(super) struct SettleRow {
    pub(super) id: EntityId,
    pub(super) keep: bool,
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

    /// What the row counts against a page's room: its length shown with its
    /// full id, never less than any label shows it.
    pub(super) fn bytes(&self) -> usize {
        json_len(&self.shown(&self.id.to_hex()))
    }
}

/// `value`'s fields, when it is an object.
fn fields(value: Json) -> Map<String, Json> {
    match value {
        Json::Object(fields) => fields,
        _ => Map::new(),
    }
}

/// Every row a settlement of `conflict` asks about, in the conflict's order:
/// each stored member, keepable while it stands, then each retained
/// alternative. A candidate the round dropped rides as retained, never as a
/// stored claim; keeping it lands it (FIX 496). One whose staged Keep the
/// owner declined is the owner's to keep again, never this ladder's (FIX
/// 7072). Every keepable row is offered: none is dropped for room.
pub(super) fn settle_rows(vault: &Vault, conflict: &OpenConflict) -> Result<Vec<SettleRow>> {
    let txn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    for id in &conflict.members {
        let Some(body) = vault.get_claim_in_txn(&txn, id)? else {
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
    drop(txn);
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
pub(super) struct AskPart<'p> {
    pub(super) at: Option<(usize, usize, usize)>,
    pub(super) before: &'p [PageAnswer],
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

/// The bytes an ask over `rows` at `part` would read.
pub(super) fn state_bytes(
    conflict: &OpenConflict,
    rows: &[&SettleRow],
    part: &AskPart<'_>,
) -> usize {
    json_len(&state_of(
        conflict,
        rows,
        part,
        &mut CallLabelMap::default(),
    ))
}

/// One settlement ask: its canonical question, the state the ladder reads,
/// the call's labels, and the rows a Keep may name.
pub(super) struct SettleAsk {
    pub(super) question: DecisionQuestion,
    pub(super) state: Json,
    pub(super) labels: CallLabelMap,
    keepable: Vec<EntityId>,
}

impl SettleAsk {
    /// The ask over `rows` of `conflict` at `part`, worded `wording`: every
    /// row whole, and a keep option for each one that may be kept. The
    /// question is keyed by the contested predicates, so each learns its own
    /// bands; an ask that is one of several adds its round and page.
    pub(super) fn over(
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
