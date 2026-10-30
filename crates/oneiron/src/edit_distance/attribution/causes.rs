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
//! abstention. A settled cause row deletes a held all-unclear no-revision
//! row for the same receipt (FIX 11708); a settled no-revision row is
//! history and stays.

use std::ops::RangeInclusive;

use super::evidence_judge::judgment_row;
use super::stored::{
    AMENDMENT_ATTEMPT, AMENDMENT_CAUSE, CAUSE_ROW_LABEL, JUDGMENT, ROW_VERSION,
    StoredAmendmentCause, hex_entity,
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
/// judgments are never rescored under one revision — except a held row
/// that charged nobody (every share unclear), which takes the settled
/// answer a later pass in the same slot brings, keeping its source id.
/// A settled answer under a judge revision also deletes a held all-unclear
/// no-revision row for the same receipt (FIX 11708): the no-revision slot
/// never displaces by fence, so the stale hold retires whenever the call
/// leaves the receipt settled under a judge revision, written now or
/// already standing; a settled no-revision row stays as history.
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
    let source = match AMENDMENT_CAUSE.get(&vault.store, wtxn, &key)? {
        Some(held) => {
            let held_unclear = held
                .split
                .iter()
                .all(|share| share.class == AmendmentClass::Unclear.as_str() || share.share <= 0.0);
            let settles = judgment
                .split
                .iter()
                .any(|share| share.class != AmendmentClass::Unclear && share.share > 0.0);
            if !(held_unclear && settles) {
                if !slot.is_empty() && !held_unclear {
                    retire_held_unclear_no_revision_in_txn(vault, wtxn, &judgment.receipt_id)?;
                }
                return Ok(());
            }
            held.source
        }
        None => source_id(&judgment.receipt_id, slot)?.to_hex(),
    };
    let settles = judgment
        .split
        .iter()
        .any(|share| share.class != AmendmentClass::Unclear && share.share > 0.0);
    if !slot.is_empty() && settles {
        retire_held_unclear_no_revision_in_txn(vault, wtxn, &judgment.receipt_id)?;
    }
    let stored = judgment_row(judgment);
    let row = StoredAmendmentCause {
        v: ROW_VERSION,
        receipt: judgment.receipt_id.clone(),
        source,
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
    AMENDMENT_CAUSE.put(&vault.store, wtxn, &key, &row)?;
    if let Some(attempt) = &judgment.attempt_receipt {
        AMENDMENT_ATTEMPT.put(
            &vault.store,
            wtxn,
            &(receipt_key(attempt), key.0, key.1.clone()),
            &(),
        )?;
    }
    Ok(())
}

/// Deletes the held all-unclear no-revision cause row for `receipt`, when
/// one stands (FIX 11708). A settled no-revision row is history and stays.
///
/// # Errors
///
/// Storage errors.
fn retire_held_unclear_no_revision_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &str,
) -> Result<()> {
    let stale = (receipt_key(receipt), String::new());
    if let Some(held) = AMENDMENT_CAUSE.get(&vault.store, wtxn, &stale)?
        && held
            .split
            .iter()
            .all(|share| share.class == AmendmentClass::Unclear.as_str() || share.share <= 0.0)
    {
        AMENDMENT_CAUSE.delete(&vault.store, wtxn, &stale)?;
        if let Some(attempt) = &held.attempt {
            AMENDMENT_ATTEMPT.delete(
                &vault.store,
                wtxn,
                &(receipt_key(attempt), stale.0, stale.1.clone()),
            )?;
        }
    }
    Ok(())
}

/// The cause rows settled on `actor`'s proposals that name `attempt`, the
/// attempt's pack receipt, oldest first (FIX 11639): the nightly
/// agent-health pass's lookup, through the attempt index instead of a full
/// cause scan per receipt. One receipt re-judged under another revision reads
/// back once per revision, each row marked when its judge was displaced; a
/// receipt whose judgment was withdrawn reads none; a dangling index entry
/// reads no row and is skipped. Reads stored rows only: it never asks a judge.
///
/// # Errors
///
/// Storage errors; [`crate::error::Error::CorruptedIndex`] on an undecodable
/// row.
pub(crate) fn amendment_causes_for_attempt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
    attempt: &str,
) -> Result<Vec<AmendmentCauseRecord>> {
    let window = 0..=u64::MAX;
    let mut causes = Vec::new();
    for (_, key, slot) in AMENDMENT_ATTEMPT.scan_keys(&vault.store, txn, &receipt_key(attempt))? {
        let Some(row) = AMENDMENT_CAUSE.get(&vault.store, txn, &(key, slot))? else {
            continue;
        };
        if let Some(cause) = cause_record_in_txn(vault, txn, row, actor, None, &window)? {
            causes.push(cause);
        }
    }
    causes.sort_by(|a, b| (a.at, &a.receipt, &a.judge).cmp(&(b.at, &b.receipt, &b.judge)));
    Ok(causes)
}

/// One stored cause row as its record, or `None` when it falls outside
/// `window`, its judgment was withdrawn, or it names another actor or skill.
fn cause_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: StoredAmendmentCause,
    actor: &EntityId,
    skill: Option<&EntityId>,
    window: &RangeInclusive<u64>,
) -> Result<Option<AmendmentCauseRecord>> {
    if !window.contains(&row.at) {
        return Ok(None);
    }
    // A receipt whose judgment was withdrawn reads no causes: its rows
    // stay stored as history, but no judgment stands behind them.
    if JUDGMENT.get(&vault.store, txn, &row.receipt)?.is_none() {
        return Ok(None);
    }
    let named_actor = row
        .actor
        .as_deref()
        .map(|hex| hex_entity(hex, CAUSE_ROW_LABEL))
        .transpose()?;
    if named_actor != Some(*actor) {
        return Ok(None);
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
        return Ok(None);
    }
    let displaced_by = match &row.judge {
        Some(revision) => displacing_revision_in_txn(vault, txn, revision)?,
        None => None,
    };
    Ok(Some(AmendmentCauseRecord {
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
    }))
}

fn receipt_key(receipt: &str) -> [u8; 32] {
    *blake3::hash(receipt.as_bytes()).as_bytes()
}

fn source_id(receipt: &str, slot: &str) -> Result<EntityId> {
    EntityId::derive(SOURCE_DOMAIN, &[receipt.as_bytes(), slot.as_bytes()])
}
