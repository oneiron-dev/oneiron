//! The trace history: what stays of a turn's tagging once its settled marker
//! has left the job ledger.
//!
//! Every attempt's trace is recorded in the transaction that settles or
//! retries it, so a marker is pruned only once its trace is recorded. A turn
//! keeps its newest [`TaggingTraceHistory::per_turn`] traces, and a trace
//! older than [`TaggingTraceHistory::max_age_secs`] is pruned by the worker's
//! next pass. The rows are job state, kept under `vault_meta`'s `job:` family:
//! derived, local, never synced, and in no content database.
//!
//! [`TaggingTraceHistory::per_turn`]: super::TaggingTraceHistory::per_turn
//! [`TaggingTraceHistory::max_age_secs`]: super::TaggingTraceHistory::max_age_secs

use serde::{Deserialize, Serialize};

use super::trace::TaggingTrace;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{EntityId, Vault};

/// The turn's id, or sixteen zero bytes for a payload that named no turn,
/// then the trace's sequence number within the turn.
type TraceKey = ([u8; 16], u64);
/// The second a trace was recorded at, then its [`TraceKey`].
type AgeKey = (u64, [u8; 16], u64);

const TRACES: SideTable<TraceKey, TaggingTraceRecord, Named> =
    SideTable::new(&side_table::TAGGING_TRACE);
const TRACE_AGE: SideTable<AgeKey, (), Raw> = SideTable::new(&side_table::TAGGING_TRACE_AGE);

/// The most expired traces one pass prunes.
const PRUNE_BUDGET: usize = 256;

/// One recorded trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaggingTraceRecord {
    /// The store-clock second the trace was recorded at.
    pub recorded_at: u64,
    pub trace: TaggingTrace,
}

fn turn_key(trace: &TaggingTrace) -> [u8; 16] {
    trace.turn.map_or([0; 16], |turn| *turn.as_bytes())
}

fn expired(recorded_at: u64, now: u64, max_age_secs: u64) -> bool {
    now.saturating_sub(recorded_at) > max_age_secs
}

/// Records `trace` at `recorded_at` in the caller's transaction, then drops
/// the turn's oldest traces past the per-turn bound. A bound of zero records
/// nothing and drops what the turn kept.
pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    trace: &TaggingTrace,
    recorded_at: u64,
) -> Result<()> {
    let Some(tagging) = vault.config.tagging.as_ref() else {
        return Ok(());
    };
    let keep = usize::try_from(tagging.trace_history.per_turn).unwrap_or(usize::MAX);
    let turn = turn_key(trace);
    let mut kept = TRACES.scan_from(&vault.store, txn, &turn)?;
    if keep > 0 {
        let sequence = kept.last().map_or(0, |((_, sequence), _)| sequence + 1);
        TRACES.put(
            &vault.store,
            txn,
            &(turn, sequence),
            &TaggingTraceRecord {
                recorded_at,
                trace: trace.clone(),
            },
        )?;
        TRACE_AGE.put(&vault.store, txn, &(recorded_at, turn, sequence), &())?;
    }
    // The new trace is the newest; the oldest kept ones make room for it.
    let over = (kept.len() + usize::from(keep > 0)).saturating_sub(keep);
    for ((_, sequence), record) in kept.drain(..over) {
        TRACES.delete(&vault.store, txn, &(turn, sequence))?;
        TRACE_AGE.delete(&vault.store, txn, &(record.recorded_at, turn, sequence))?;
    }
    Ok(())
}

/// Whether the oldest recorded trace is past the history's age at `now`:
/// a read, so a pass with nothing to prune writes nothing.
pub(super) fn expired_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, now: u64) -> Result<bool> {
    let Some(tagging) = vault.config.tagging.as_ref() else {
        return Ok(false);
    };
    let Some(oldest) = TRACE_AGE.iter_from(&vault.store, txn, &[])?.next() else {
        return Ok(false);
    };
    let ((recorded_at, _, _), ()) = oldest?;
    Ok(expired(
        recorded_at,
        now,
        tagging.trace_history.max_age_secs,
    ))
}

/// Prunes the traces past the history's age at `now`, oldest first and at
/// most [`PRUNE_BUDGET`] of them, in the caller's transaction; returns how
/// many went.
pub(super) fn prune_expired_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<usize> {
    let Some(tagging) = vault.config.tagging.as_ref() else {
        return Ok(0);
    };
    let max_age_secs = tagging.trace_history.max_age_secs;
    let mut due = Vec::new();
    for row in TRACE_AGE.iter_from(&vault.store, txn, &[])? {
        let (key, ()) = row?;
        if due.len() == PRUNE_BUDGET || !expired(key.0, now, max_age_secs) {
            break;
        }
        due.push(key);
    }
    for (recorded_at, turn, sequence) in &due {
        TRACE_AGE.delete(&vault.store, txn, &(*recorded_at, *turn, *sequence))?;
        TRACES.delete(&vault.store, txn, &(*turn, *sequence))?;
    }
    Ok(due.len())
}

impl Vault {
    /// The recorded tagging traces of `turn`, oldest first: at most the
    /// configured number per turn, and none past the configured age once the
    /// worker's next pass has pruned it.
    pub fn tagging_trace_history(&self, turn: &EntityId) -> Result<Vec<TaggingTraceRecord>> {
        let txn = self.store.env.read_txn()?;
        Ok(TRACES
            .scan_from(&self.store, &txn, turn.as_bytes())?
            .into_iter()
            .map(|(_, record)| record)
            .collect())
    }
}
