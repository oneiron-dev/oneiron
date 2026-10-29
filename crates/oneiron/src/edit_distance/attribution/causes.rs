//! The amendment judge's labels, kept and read for one actor (FIX 8264,
//! 11638): the inlet agent-health cards join beside the attempt lane's
//! settled causes.
//!
//! Every persisted amendment judgment also settles a cause row here,
//! write-once per receipt and judge-revision slot, in the same write as the
//! judgment row. The judgment row is overwritten when the amendment is
//! judged again; its cause rows are not. Each stands under the revision
//! fence the attempt lane keeps: once its judge revision is displaced, the
//! row reads back with the displacement named, so a label the re-judgment
//! dropped stops standing as current. A withdrawal deletes no cause row —
//! labels a judge once settled are history the fence retires, not an
//! abstention.

use std::ops::RangeInclusive;

use super::evidence_judge::judgment_row;
use super::stored::{
    AMENDMENT_CAUSE, CAUSE_ROW_LABEL, ROW_VERSION, StoredAmendmentCause, hex_entity,
};
use super::taxonomy::{AmendmentClass, AmendmentJudgment, AmendmentShare};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill_attribution::displacing_revision_in_txn;

/// Domain of a cause's source id: one id per receipt and judge-revision slot.
const SOURCE_DOMAIN: &[u8] = b"oneiron:amendment-cause:v1";

/// One judged amendment or rejection, as the judge revision that settled
/// its cause row labeled it.
#[derive(Debug, Clone, PartialEq)]
pub struct AmendmentCauseRecord {
    /// Immutable: the same receipt and revision slot always spell it.
    pub source: EntityId,
    /// The judged receipt.
    pub receipt: String,
    /// The terminal pack receipt of the attempt the proposal came from, when
    /// the evidence named one.
    pub attempt_receipt: Option<String>,
    /// The skill the judgment joined to that attempt, or the one its evidence
    /// named.
    pub skill: Option<EntityId>,
    /// The label shares, summing to one.
    pub shares: Vec<AmendmentShare>,
    /// The judge revision the labels stand on; `None` only for settled,
    /// unjudged or owner-scripted labels — the rule tier stamps its own
    /// revision.
    pub judge: Option<String>,
    /// The drafting executor at revision; `None` when unknown.
    pub executor: Option<String>,
    /// A rejection's judgment, which carries no Δ.
    pub rejected: bool,
    /// The revision that displaced `judge`, when one has: the labels are
    /// history then, not current support.
    pub displaced_by: Option<String>,
    pub at: u64,
}

/// Keeps `judgment`'s labels as their cause row, in the write that lands
/// the judgment. First write wins for the receipt's revision slot: a later
/// answer under the same judge revision never rewrites the row, as
/// judgments are never rescored under one revision.
///
/// # Errors
///
/// Storage errors.
pub(super) fn put_amendment_cause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    judgment: &AmendmentJudgment,
) -> Result<()> {
    let slot = judgment.judge.as_deref().unwrap_or_default();
    let key = (receipt_key(&judgment.receipt_id), slot.to_owned());
    if AMENDMENT_CAUSE.get(&vault.store, wtxn, &key)?.is_some() {
        return Ok(());
    }
    let stored = judgment_row(judgment);
    let row = StoredAmendmentCause {
        v: ROW_VERSION,
        receipt: judgment.receipt_id.clone(),
        source: source_id(&judgment.receipt_id, slot)?.to_hex(),
        actor: stored.actor,
        skill: stored.skill,
        attempt: judgment.attempt_receipt.clone(),
        split: stored.split,
        executor: stored.executor,
        project: stored.project,
        judge: stored.judge,
        rejected: stored.rejected,
        at: stored.at,
    };
    AMENDMENT_CAUSE.put(&vault.store, wtxn, &key, &row)
}

/// Every cause row settled on `actor`'s proposals in `window`, oldest
/// first, on the caller's snapshot; with `skill`, only those that name it.
/// One receipt re-judged under another revision reads back once per
/// revision, each row marked when its judge was displaced. Reads stored
/// rows only: it never asks a judge.
///
/// # Errors
///
/// Storage errors; [`crate::error::Error::CorruptedIndex`] on an undecodable
/// row.
pub(crate) fn amendment_causes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
    skill: Option<&EntityId>,
    window: RangeInclusive<u64>,
) -> Result<Vec<AmendmentCauseRecord>> {
    let mut causes = Vec::new();
    for (_, row) in AMENDMENT_CAUSE.scan(&vault.store, txn)? {
        if !window.contains(&row.at) {
            continue;
        }
        let named_actor = row
            .actor
            .as_deref()
            .map(|hex| hex_entity(hex, CAUSE_ROW_LABEL))
            .transpose()?;
        if named_actor != Some(*actor) {
            continue;
        }
        let named_skill = row
            .skill
            .as_deref()
            .map(|hex| hex_entity(hex, CAUSE_ROW_LABEL))
            .transpose()?;
        let shares: Vec<AmendmentShare> = row
            .split
            .iter()
            .map(|share| -> Result<AmendmentShare> {
                Ok(AmendmentShare {
                    class: AmendmentClass::parse(&share.class)
                        .ok_or(Error::CorruptedIndex(CAUSE_ROW_LABEL))?,
                    share: share.share,
                    subject: share
                        .subject
                        .as_deref()
                        .map(|hex| hex_entity(hex, CAUSE_ROW_LABEL))
                        .transpose()?,
                })
            })
            .collect::<Result<_>>()?;
        if let Some(wanted) = skill
            && named_skill != Some(*wanted)
            && !shares.iter().any(|share| share.subject == Some(*wanted))
        {
            continue;
        }
        let displaced_by = match &row.judge {
            Some(revision) => displacing_revision_in_txn(vault, txn, revision)?,
            None => None,
        };
        causes.push(AmendmentCauseRecord {
            source: hex_entity(&row.source, CAUSE_ROW_LABEL)?,
            receipt: row.receipt,
            attempt_receipt: row.attempt,
            skill: named_skill,
            shares,
            judge: row.judge,
            executor: row.executor,
            rejected: row.rejected,
            displaced_by,
            at: row.at,
        });
    }
    causes.sort_by(|a, b| (a.at, &a.receipt, &a.judge).cmp(&(b.at, &b.receipt, &b.judge)));
    Ok(causes)
}

fn receipt_key(receipt: &str) -> [u8; 32] {
    *blake3::hash(receipt.as_bytes()).as_bytes()
}

fn source_id(receipt: &str, slot: &str) -> Result<EntityId> {
    EntityId::derive(SOURCE_DOMAIN, &[receipt.as_bytes(), slot.as_bytes()])
}
