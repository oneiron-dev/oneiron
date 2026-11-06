//! Core half of `vault_cleanup::run_snapshot`: its store-layer items live in `oneiron_store::vault_cleanup::run_snapshot` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::vault_cleanup::run_snapshot::*;

use super::run_record::{self, KEY_REVERT, KEY_SNAPSHOT};
use super::run_revert::{CleanupRunRevert, decode_revert};
use super::{
    CleanupDecision, CleanupKind, CleanupPosture, CleanupProposal, CleanupRunReport, KEY_AT,
    KEY_DECISION, KEY_ENTITY, KEY_KIND, field,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::attempt_id::AttemptId;
use rmpv::Value;

/// One run that archived something: its snapshot, and its revert once there
/// is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupRunRecord {
    /// The run's attempt id, the name a revert takes.
    pub attempt: AttemptId,
    /// What it archived.
    pub snapshot: CleanupRunSnapshot,
    /// The stored answer of its revert, once the owner reverted it.
    pub revert: Option<CleanupRunRevert>,
}

/// Every run that archived something, and the runs whose row does not read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupRuns {
    /// Runs with a snapshot, in attempt order.
    pub runs: Vec<CleanupRunRecord>,
    /// Runs whose RUN row does not read; the others still answer.
    pub unreadable: Vec<AttemptId>,
}

/// Every cleanup run that archived something, in attempt order, each with
/// its revert if the owner reverted it.
///
/// A run that archived nothing, or ran before runs kept snapshots, is not
/// listed. A RUN row that does not read is named in
/// [`CleanupRuns::unreadable`], and the rest still answer.
///
/// # Errors
///
/// Storage errors.
pub fn cleanup_runs(vault: &Vault) -> Result<CleanupRuns> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = CleanupRuns::default();
    for (key, raw) in run_record::rows_in_txn(vault, &rtxn)? {
        let attempt = AttemptId::from_bytes(&key)?;
        match decode_run(attempt, &raw) {
            Ok(Some(run)) => out.runs.push(run),
            Ok(None) => {}
            Err(_) => out.unreadable.push(attempt),
        }
    }
    Ok(out)
}

fn decode_run(attempt: AttemptId, raw: &[u8]) -> Result<Option<CleanupRunRecord>> {
    let fields = run_record::decode_fields(raw)?;
    let Some(snapshot) = field(&fields, KEY_SNAPSHOT)
        .map(decode_snapshot)
        .transpose()?
        .flatten()
    else {
        return Ok(None);
    };
    let revert = match field(&fields, KEY_REVERT) {
        None | Some(Value::Nil) => None,
        Some(value) => Some(decode_revert(attempt, value)?),
    };
    Ok(Some(CleanupRunRecord {
        attempt,
        snapshot,
        revert,
    }))
}

/// Records `snapshot` on `run`'s RUN row in the archive's own transaction.
/// The row's report keys stay as the run wrote them. A decision that
/// archived nothing records no snapshot (FIX 7519): the row's snapshot stays
/// Nil and `runs` does not list it, while its report and digest stand.
pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    run: &AttemptId,
    snapshot: &CleanupRunSnapshot,
) -> Result<()> {
    if snapshot.entries.is_empty() {
        return Ok(());
    }
    run_record::set_field_in_txn(vault, txn, run, KEY_SNAPSHOT, encode_snapshot(snapshot))?;
    Ok(())
}

/// Records an accepted proposal's snapshot on the RUN row of the run that
/// opened it. A run that left no row gets the propose-first report it would
/// have written. A row that does not read stays as it is and the archive
/// still stands; the review names that run as unreadable. An accept that
/// archived nothing still leaves that row, with no snapshot (FIX 7519): its
/// revert answers with no entries, as before.
pub(super) fn record_accept_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &CleanupProposal,
    snapshot: &CleanupRunSnapshot,
) -> Result<()> {
    if !run_record::exists_in_txn(vault, txn, &proposal.attempt)? {
        run_record::put_in_txn(
            vault,
            txn,
            &CleanupRunReport {
                attempt: proposal.attempt,
                posture: CleanupPosture::ProposeFirst,
                candidates: proposal.candidates.clone(),
                proposal: Some(proposal.id),
                archived: Vec::new(),
                digest: None,
            },
        )?;
    }
    record_in_txn(vault, txn, &proposal.attempt, snapshot)
}

/// A RUN row's `snapshot` value; Nil is a run that archived nothing yet.
pub(super) fn decode_snapshot(value: &Value) -> Result<Option<CleanupRunSnapshot>> {
    let corrupt = || Error::CorruptedIndex(SNAPSHOT_LABEL);
    let parts = match value {
        Value::Nil => return Ok(None),
        Value::Map(parts) => parts,
        _ => return Err(corrupt()),
    };
    let Some(Value::Array(rows)) = field(parts, KEY_ENTRIES) else {
        return Err(corrupt());
    };
    Ok(Some(CleanupRunSnapshot {
        at: field(parts, KEY_AT)
            .and_then(Value::as_u64)
            .ok_or_else(corrupt)?,
        decision: field(parts, KEY_DECISION)
            .and_then(Value::as_str)
            .and_then(CleanupDecision::parse)
            .ok_or_else(corrupt)?,
        digest: entity_at(parts, KEY_DIGEST).ok_or_else(corrupt)?,
        entries: rows
            .iter()
            .map(|row| match row {
                Value::Nil => Some(None),
                row => decode_entry(row).map(Some),
            })
            .collect::<Option<_>>()
            .ok_or_else(corrupt)?,
    }))
}

fn decode_entry(row: &Value) -> Option<CleanupSnapshotEntry> {
    let Value::Map(parts) = row else {
        return None;
    };
    Some(CleanupSnapshotEntry {
        entity: entity_at(parts, KEY_ENTITY)?,
        kind: field(parts, KEY_KIND)
            .and_then(Value::as_str)
            .and_then(CleanupKind::parse)?,
        revision: match field(parts, KEY_REVISION)? {
            Value::Nil => None,
            value => Some(value.as_slice()?.try_into().ok()?),
        },
        before: match field(parts, KEY_BEFORE)? {
            Value::Nil => None,
            value => Some(value.as_slice()?.to_vec()),
        },
        after: match field(parts, KEY_AFTER)? {
            Value::Nil => None,
            value => Some(value.as_slice()?.to_vec()),
        },
    })
}

/// The entity id a row holds as hex under `key`.
pub(super) fn entity_at(parts: &[(Value, Value)], key: &str) -> Option<EntityId> {
    field(parts, key)
        .and_then(Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
}
