//! The amendment judge's labels, read for one actor (FIX 8264): the inlet
//! agent-health cards join beside the attempt lane's settled causes.
//!
//! Only what the judgment ledger keeps is exposed. An amendment's labels are
//! its judgment's split, overwritten when it is judged again: there is no
//! cause row of their own, so no source id, no displacement fence and no
//! witness list stand behind them.

use std::ops::RangeInclusive;

use super::evidence_judge::amendment_judgments_in_txn;
use super::stored::{EVIDENCE, EVIDENCE_ROW_LABEL, hex_entity};
use super::taxonomy::{AmendmentClass, AmendmentShare};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// One judged amendment or rejection, as its labels stand.
#[derive(Debug, Clone, PartialEq)]
pub struct AmendmentCauseRecord {
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
    /// The judge revision the labels stand on; `None` for the rule tier and
    /// for settled or owner-scripted labels.
    pub judge: Option<String>,
    /// The drafting executor at revision; `None` when unknown.
    pub executor: Option<String>,
    /// A rejection's judgment, which carries no Δ.
    pub rejected: bool,
    pub at: u64,
}

/// Every judged amendment and rejection of `actor`'s proposals in `window`,
/// oldest first, on the caller's snapshot; with `skill`, only those that
/// name it. Reads stored rows only: it never asks a judge.
///
/// The actor is the one the amendment's evidence row names. A rejection
/// keeps no evidence row, so only its `execution_lapse` share names its
/// actor.
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
    for (judgment, join) in amendment_judgments_in_txn(vault, txn)? {
        if !window.contains(&judgment.at) {
            continue;
        }
        let evidence = EVIDENCE.get(&vault.store, txn, &judgment.receipt_id)?;
        let named_actor = match &evidence {
            Some(row) => Some(hex_entity(&row.actor, EVIDENCE_ROW_LABEL)?),
            None => judgment
                .split
                .iter()
                .find(|share| share.class == AmendmentClass::ExecutionLapse)
                .and_then(|share| share.subject),
        };
        if named_actor != Some(*actor) {
            continue;
        }
        let named_skill = match (join, &evidence) {
            (Some((_, joined)), _) => Some(joined),
            (None, Some(row)) => row
                .skill
                .as_deref()
                .map(|hex| hex_entity(hex, EVIDENCE_ROW_LABEL))
                .transpose()?,
            (None, None) => None,
        };
        if let Some(wanted) = skill
            && named_skill != Some(*wanted)
            && !judgment
                .split
                .iter()
                .any(|share| share.subject == Some(*wanted))
        {
            continue;
        }
        causes.push(AmendmentCauseRecord {
            receipt: judgment.receipt_id,
            attempt_receipt: judgment.attempt_receipt,
            skill: named_skill,
            shares: judgment.split,
            judge: judgment.judge,
            executor: judgment.executor,
            rejected: judgment.rejected,
            at: judgment.at,
        });
    }
    causes.sort_by(|a, b| (a.at, &a.receipt).cmp(&(b.at, &b.receipt)));
    Ok(causes)
}
