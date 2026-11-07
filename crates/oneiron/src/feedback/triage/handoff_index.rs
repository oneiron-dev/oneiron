//! The handoff rows a sweep reads, indexed (FIX 7550), so the requeue pass
//! and the owner's status read those rows, not every handoff ever made.
//!
//! Every handoff write goes through [`put_handoff_in_txn`], which keeps three
//! membership indexes in step with the row in the writer's own transaction:
//! - open: each row a requeue pass visits, an unacknowledged revision or one
//!   whose evidence was settled erased;
//! - by sweep: each row under the sweep that handed it off and the sweep that
//!   queued its current job, for a sweep's own status;
//! - by evidence: each acknowledged revision whose evidence is still retained,
//!   under its evidence ASSET, for the erased-evidence backstop (FIX 10921),
//!   which reads keys and one marker per ASSET, never a row.
//!
//! Handoffs written before these indexes have no index rows; no migration
//! builds them (no backward compatibility).

use std::collections::BTreeSet;

use super::{FeedbackTriageHandoff, FeedbackTriageHandoffSource, HANDOFFS};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};

/// Key: the handoff's key. Value: empty.
const OPEN: SideTable<[u8; 32], (), Raw> =
    SideTable::new(&side_table::FEEDBACK_TRIAGE_HANDOFF_OPEN);
/// Key: a sweep's attempt id16, then the handoff's key. Value: empty.
const BY_SWEEP: SideTable<([u8; 16], [u8; 32]), (), Raw> =
    SideTable::new(&side_table::FEEDBACK_TRIAGE_HANDOFF_BY_SWEEP);
/// Key: the evidence ASSET id16, then the handoff's key. Value: empty.
const BY_EVIDENCE: SideTable<([u8; 16], [u8; 32]), (), Raw> =
    SideTable::new(&side_table::FEEDBACK_TRIAGE_HANDOFF_BY_EVIDENCE);

/// What one handoff row is listed under.
#[derive(Default, PartialEq, Eq)]
struct Memberships {
    open: bool,
    sweeps: BTreeSet<[u8; 16]>,
    evidence: Option<[u8; 16]>,
}

fn memberships(handoff: &FeedbackTriageHandoff) -> Memberships {
    let evidence = match (&handoff.source, &handoff.result) {
        (FeedbackTriageHandoffSource::Retained { evidence, .. }, Some(_)) => {
            Some(*evidence.as_bytes())
        }
        _ => None,
    };
    Memberships {
        open: handoff.result.is_none() || handoff.erased_at().is_some(),
        sweeps: [*handoff.sweep.as_bytes(), *handoff.queued_by.as_bytes()]
            .into_iter()
            .collect(),
        evidence,
    }
}

/// Writes `handoff` under `key`, and keeps its index rows in step, in the
/// caller's transaction. A stored row that does not read is listed nowhere.
///
/// # Errors
///
/// Storage errors.
pub(super) fn put_handoff_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    handoff: &FeedbackTriageHandoff,
) -> Result<()> {
    let before = match HANDOFFS.get(store, txn, key) {
        Ok(Some(stored)) => memberships(&stored),
        Ok(None) | Err(_) => Memberships::default(),
    };
    let after = memberships(handoff);
    if before != after {
        if before.open && !after.open {
            OPEN.delete(store, txn, key)?;
        }
        if after.open && !before.open {
            OPEN.put(store, txn, key, &())?;
        }
        for gone in before.sweeps.difference(&after.sweeps) {
            BY_SWEEP.delete(store, txn, &(*gone, *key))?;
        }
        for added in after.sweeps.difference(&before.sweeps) {
            BY_SWEEP.put(store, txn, &(*added, *key), &())?;
        }
        if before.evidence != after.evidence {
            if let Some(gone) = before.evidence {
                BY_EVIDENCE.delete(store, txn, &(gone, *key))?;
            }
            if let Some(added) = after.evidence {
                BY_EVIDENCE.put(store, txn, &(added, *key), &())?;
            }
        }
    }
    HANDOFFS.put(store, txn, key, handoff)
}

/// The keys of the rows a requeue pass visits: every open row, and every
/// acknowledged row whose retained evidence now carries the erase marker
/// (the backstop), one marker read per ASSET.
///
/// # Errors
///
/// Storage errors.
pub(super) fn requeue_keys(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<BTreeSet<[u8; 32]>> {
    let mut keys: BTreeSet<[u8; 32]> = OPEN
        .scan_keys(&vault.store, txn, &[])?
        .into_iter()
        .collect();
    let mut asset: Option<([u8; 16], bool)> = None;
    for (evidence, key) in BY_EVIDENCE.scan_keys(&vault.store, txn, &[])? {
        let erased = match asset {
            Some((held, erased)) if held == evidence => erased,
            _ => {
                let erased = vault.local_hard_delete_marker_exists_in_txn(
                    txn,
                    &EntityId::from_bytes_unchecked(evidence),
                )?;
                asset = Some((evidence, erased));
                erased
            }
        };
        if erased {
            keys.insert(key);
        }
    }
    Ok(keys)
}

/// The keys of the rows the status of sweep `attempt` reads: every open
/// row, and every row that sweep handed off or queued.
///
/// # Errors
///
/// Storage errors.
pub(super) fn status_keys(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    attempt: &EntityId,
) -> Result<BTreeSet<[u8; 32]>> {
    let mut keys: BTreeSet<[u8; 32]> = OPEN.scan_keys(store, txn, &[])?.into_iter().collect();
    keys.extend(
        BY_SWEEP
            .scan_keys(store, txn, attempt.as_bytes())?
            .into_iter()
            .map(|(_, key)| key),
    );
    Ok(keys)
}

/// The rows under `keys`, each read once; a key whose row is gone is passed
/// by.
///
/// # Errors
///
/// Storage errors, or a row that does not read.
pub(super) fn rows(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    keys: BTreeSet<[u8; 32]>,
) -> Result<Vec<([u8; 32], FeedbackTriageHandoff)>> {
    let mut rows = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(handoff) = HANDOFFS.get(store, txn, &key)? {
            rows.push((key, handoff));
        }
    }
    Ok(rows)
}
