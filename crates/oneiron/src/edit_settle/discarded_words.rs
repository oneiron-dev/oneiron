//! What a settlement keeps once the owner's discard took its artifact's payload off this machine
//! (FIX 14534 rule 4): its history and the identifiers its words carried. The words go.

use std::collections::BTreeSet;

use heed::RwTxn;
use serde::{Deserialize, Serialize};

use super::carry::WITHDRAWALS;
use super::codec::RECORD;
use super::records::SettlementRecord;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::TypedDecision;
use crate::store::Store;

/// The identifiers a settlement's words carried, kept once the words left with their artifact's
/// payload (FIX 14534). Beside it the record's discard reason, typed sheet answers, slide and
/// paragraph judgments and deck evidence stand empty, and each exported comment keeps its
/// thread, asker, answerer and author GUID but not the author name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscardedSettleWords {
    /// When the words left (engine clock).
    pub discarded_at: u64,
    /// Each question an answer or judgment was for, by id and version.
    pub questions: BTreeSet<(EntityId, u32)>,
    /// Each principal a question was asked as.
    pub principals: BTreeSet<EntityId>,
    /// Each evidence revision a decision read, by id and body hash.
    pub evidence: BTreeSet<(EntityId, [u8; 32])>,
    /// Each other entity the words named: a decision's evidence, a judgment's thread, the deck
    /// edit's maker and answered thread.
    pub refs: BTreeSet<EntityId>,
    /// Each content hash the words were bound to: the deck handoff and its review images, a
    /// paragraph's judged text and frontier.
    pub hashes: BTreeSet<[u8; 32]>,
}

impl DiscardedSettleWords {
    fn decision(&mut self, decision: &TypedDecision) {
        self.questions
            .insert((decision.receipt.question, decision.receipt.question_version));
        self.principals.insert(decision.receipt.principal);
        self.evidence.extend(
            decision
                .receipt
                .evidence_versions
                .iter()
                .map(|pin| (pin.id, pin.body_hash)),
        );
        self.refs.extend(decision.evidence.iter().copied());
    }
}

/// `record` with its words emptied and their identifiers kept, at `now`; `None` when it holds no
/// words, or lost them already.
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
        ..DiscardedSettleWords::default()
    };
    record.reason = None;
    if let Some(bundle) = record.sheet_answers.take() {
        kept.questions
            .insert((bundle.question.id, bundle.question.version));
        kept.principals.insert(bundle.principal);
        for answer in &bundle.answers {
            kept.decision(&answer.decision);
            if let Some(source) = &answer.source {
                kept.evidence.insert((source.id, source.body_hash));
            }
        }
    }
    for judgment in std::mem::take(&mut record.pptx_judgments) {
        kept.refs.insert(judgment.thread_id);
        kept.decision(&judgment.decision);
        if let Some(presence) = &judgment.presence {
            kept.decision(presence);
        }
    }
    for judgment in std::mem::take(&mut record.docx_judgments) {
        kept.decision(&judgment.decision);
        kept.hashes.insert(judgment.text_hash);
        kept.hashes.insert(judgment.frontier);
    }
    if let Some(deck) = record.deck.take() {
        kept.hashes.insert(deck.handoff);
        kept.refs.extend(deck.context.made_by);
        kept.refs.extend(deck.context.thread);
        kept.hashes
            .extend(deck.context.renders.iter().map(|render| render.image_hash));
    }
    for identity in &mut record.pptx_review_identities {
        identity.export_author_name.clear();
    }
    record.discarded_words = Some(kept);
    Some(record)
}

/// The settle payload the owner's discard takes with `artifact` (FIX 14534 rule 4, call 4 = A;
/// Engine 11-07 02:10 = A): each settlement of it keeps its history in place, its words emptied
/// and the identifiers they carried kept beside them, since the consume-once ledger stays; each
/// answer withdrawal of it goes with its wake, as the held proposals it re-asks went with the
/// pending purge in this same write, and a wake over an artifact no longer here cannot run. Each
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
