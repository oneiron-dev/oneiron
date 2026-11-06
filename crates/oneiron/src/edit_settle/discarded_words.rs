//! What a settlement keeps once the owner's discard took its artifact's payload off this machine
//! (FIX 14534 rule 4): its history, with the identifiers its words carried. The words go.

use heed::RwTxn;
use oneiron_docedit::edit::{DeckTransactionReport, Digest, IdMarks, PartChange};
use serde::{Deserialize, Serialize};

use super::carry::WITHDRAWALS;
use super::codec::RECORD;
use super::records::SettlementRecord;
use crate::edit_roundtrip::slides_review::{SlideJudgment, SlideReviewLabels};
use crate::edit_roundtrip::{DeckEditContext, ParagraphJudgment, SheetAnswerBundle};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::{AnswerContract, DecisionAnswer, TypedDecision};
use crate::store::Store;

/// A settlement's typed review once its words left with its artifact's payload (FIX 14534): each
/// answer and judgment as it was settled, with its unit, revisions, hashes and decision receipt,
/// and every word in it emptied (question text, choice options and choices, sheet name, cell
/// values, comments, authors, labels). Beside it the record's own word fields stand empty, and
/// each exported comment keeps its thread, asker, answerer and author GUID but not the name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscardedSettleWords {
    /// When the words left (engine clock).
    pub discarded_at: u64,
    pub sheet_answers: Option<Box<SheetAnswerBundle>>,
    pub slide_judgments: Vec<SlideJudgment>,
    pub paragraph_judgments: Vec<ParagraphJudgment>,
    pub deck: Option<DiscardedDeck>,
}

/// A settled native deck transaction without its words: the handoff it bound, who made it and
/// what it answered, its review renders, and its report's digests, part diff and id marks; the
/// report's steps go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscardedDeck {
    pub handoff: [u8; 32],
    pub context: DeckEditContext,
    /// `None` when the stored report did not read.
    pub report: Option<DiscardedDeckReport>,
}

/// A deck transaction report's history: what it ran on and made, and part by part how they
/// differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscardedDeckReport {
    pub schema: u32,
    pub base: Digest,
    pub candidate: Digest,
    pub parts: Vec<PartChange>,
    pub untouched: usize,
    pub marks: IdMarks,
    pub handoff: Digest,
}

fn scrub_decision(decision: &mut TypedDecision) {
    if let DecisionAnswer::Choice(choice) = &mut decision.answer {
        choice.clear();
    }
}

fn scrub_contract(contract: &mut AnswerContract) {
    if let AnswerContract::Choice { options } = contract {
        options.iter_mut().for_each(String::clear);
    }
}

fn scrub_labels(labels: &mut SlideReviewLabels) {
    for label in [
        &mut labels.yes,
        &mut labels.no,
        &mut labels.low,
        &mut labels.middle,
        &mut labels.high,
    ] {
        label.clear();
    }
}

fn scrub_sheet(bundle: &mut SheetAnswerBundle) {
    bundle.question.text.clear();
    scrub_contract(&mut bundle.question.contract);
    bundle.sheet.clear();
    for answer in &mut bundle.answers {
        answer.before = None;
        answer.value = None;
        scrub_decision(&mut answer.decision);
    }
}

fn scrub_slide(judgment: &mut SlideJudgment) {
    scrub_decision(&mut judgment.decision);
    if let Some(presence) = &mut judgment.presence {
        scrub_decision(presence);
    }
    scrub_contract(&mut judgment.answer_contract);
    judgment.comment.clear();
    scrub_labels(&mut judgment.labels);
}

fn scrub_paragraph(judgment: &mut ParagraphJudgment) {
    scrub_decision(&mut judgment.decision);
    scrub_contract(&mut judgment.answer_contract);
    judgment.comment.clear();
    judgment.author.clear();
    scrub_labels(&mut judgment.labels);
}

impl DiscardedDeck {
    fn of(deck: crate::edit_roundtrip::DeckSettleEvidence) -> Self {
        let report = serde_json::from_str::<DeckTransactionReport>(&deck.report)
            .ok()
            .map(|report| DiscardedDeckReport {
                schema: report.schema,
                base: report.base,
                candidate: report.candidate,
                parts: report.parts,
                untouched: report.untouched,
                marks: report.marks,
                handoff: report.handoff,
            });
        Self {
            handoff: deck.handoff,
            context: deck.context,
            report,
        }
    }
}

/// `record` with its words emptied and its typed review kept without them, at `now`; `None`
/// when it holds no words, or lost them already.
fn without_words(mut record: SettlementRecord, now: u64) -> Option<SettlementRecord> {
    let holds_words = record.reason.is_some()
        || record.sheet_answers.is_some()
        || record.deck.is_some()
        || !record.pptx_judgments.is_empty()
        || !record.docx_judgments.is_empty()
        || record
            .pptx_review_identities
            .iter()
            .any(|identity| !identity.export_author_name.is_empty());
    if record.discarded_words.is_some() || !holds_words {
        return None;
    }
    let mut kept = DiscardedSettleWords {
        discarded_at: now,
        sheet_answers: record.sheet_answers.take(),
        slide_judgments: std::mem::take(&mut record.pptx_judgments),
        paragraph_judgments: std::mem::take(&mut record.docx_judgments),
        deck: record.deck.take().map(|deck| DiscardedDeck::of(*deck)),
    };
    if let Some(bundle) = &mut kept.sheet_answers {
        scrub_sheet(bundle);
    }
    kept.slide_judgments.iter_mut().for_each(scrub_slide);
    kept.paragraph_judgments
        .iter_mut()
        .for_each(scrub_paragraph);
    record.reason = None;
    for identity in &mut record.pptx_review_identities {
        identity.export_author_name.clear();
    }
    record.discarded_words = Some(Box::new(kept));
    Some(record)
}

/// The settle payload the owner's discard takes with `artifact` (FIX 14534 rule 4, call 4 = A;
/// Engine 11-07 02:10 = A): each settlement of it keeps its history in place, its words emptied
/// and its typed review kept without them, since the consume-once ledger stays; each answer
/// withdrawal of it goes with its wake, as the held proposals it re-asks went with the pending
/// purge in this same write, and a wake over an artifact no longer here cannot run. Each
/// settlement is rewritten under its own key; no settle, receipt or undo runs.
///
/// # Errors
///
/// Storage errors, or a row that does not decode or encode.
pub(crate) fn discard_settle_payload_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    artifact: &EntityId,
) -> Result<()> {
    for key in WITHDRAWALS.scan_keys(store, txn, artifact.as_bytes())? {
        if key.0 == *artifact {
            WITHDRAWALS.delete(store, txn, &key)?;
        }
    }
    let now = store.clock.now_recorded_at();
    let rewrites: Vec<_> = RECORD
        .scan_from(store, txn, artifact.as_bytes())?
        .into_iter()
        .filter(|((owner, _), _)| owner == artifact)
        .filter_map(|(key, record)| without_words(record, now).map(|record| (key, record)))
        .collect();
    for (key, record) in &rewrites {
        RECORD.put(store, txn, key, record)?;
    }
    Ok(())
}
