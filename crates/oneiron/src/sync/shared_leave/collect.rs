//! A left shared vault's orphan body files (FIX 2413).
//!
//! The leave's purge drops the raw-output rows that named the env's result
//! bodies, and opening the env collects only released bodies, so their files
//! would stay. The transaction of the purge's final pass therefore owes the
//! env one orphan collection, due an hour later at the earliest: by then
//! every file the purge left unnamed is past the collector's grace. Each
//! housekeeping pass that finds it due, a handle's first pass included, runs
//! one bounded collector pass, and so does a connection opening on the env,
//! on a blocking thread of its own. A body a reader pinned, a page that may
//! have more, or a fault keeps the row for a later pass; a pass that finds no
//! more to collect drops it. Nothing waits on it: not the leave, its
//! response, nor a connection's open.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// Seconds from the purge's final pass until the env's orphan collection is
/// due: at least the collector's one-hour grace for a body no row names.
const LEFT_ENV_BODY_COLLECT_DELAY_SECS: u64 = 3600;

/// Released bodies, then orphan files, one collector pass takes at most: the
/// bound an open and the serve start collect with.
#[cfg(unix)]
const LEFT_ENV_BODY_COLLECT_LIMIT: usize = 4096;

/// The env's owed collection: one row, written with the purge's final pass.
const BODY_COLLECT: SideTable<(), LeftEnvBodyCollect, Named> =
    SideTable::new(&side_table::SYNC_LEFT_ENV_BODY_COLLECT);

/// When the env's purge finished, and when its orphan collection is due, in
/// unix seconds: the clock the collector's grace reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeftEnvBodyCollect {
    purge_finished_at: u64,
    due_at: u64,
}

/// Owes the env its orphan collection in the transaction of the purge's
/// final pass. A purge a repeated confirm finishes again owes it afresh,
/// from then.
pub(super) fn owe_left_env_body_collect_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let purge_finished_at = crate::unix_seconds_now();
    let owed = LeftEnvBodyCollect {
        purge_finished_at,
        due_at: purge_finished_at.saturating_add(LEFT_ENV_BODY_COLLECT_DELAY_SECS),
    };
    BODY_COLLECT.put(&vault.store, wtxn, &(), &owed)
}

/// When the env's owed orphan collection is due, or `None` when it owes none.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn left_env_body_collect_due_at(vault: &Vault) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    Ok(BODY_COLLECT
        .get(&vault.store, &txn, &())?
        .map(|owed| owed.due_at))
}

/// Runs one bounded collector pass when the env's owed collection is due.
/// Warning-only: a fault keeps the row, and the next pass retries.
pub(crate) fn collect_left_env_bodies(vault: &Vault) {
    if let Err(error) = collect_due(vault) {
        tracing::warn!(
            kind = ?error.kind(),
            "a left env's owed body collection did not finish; the next pass retries"
        );
    }
}

/// [`collect_left_env_bodies`] as a connection on the env opens: when the
/// env's owed collection is due, the pass runs on a blocking thread of its
/// own, so the open never fails, waits or blocks for it. A due time that does
/// not read is warned, and outside a runtime the pass is left to
/// housekeeping.
pub(crate) fn collect_left_env_bodies_at_open(vault: &Arc<Vault>) {
    let due = match left_env_body_collect_due_at(vault) {
        Ok(due_at) => due_at.is_some_and(|due_at| due_at <= crate::unix_seconds_now()),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a left env's owed body collection did not read at open; housekeeping retries"
            );
            false
        }
    };
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    if due {
        let vault = Arc::clone(vault);
        drop(runtime.spawn_blocking(move || collect_left_env_bodies(&vault)));
    }
}

/// [`collect_left_env_bodies`]'s pass, its fault returned.
fn collect_due(vault: &Vault) -> Result<()> {
    let owed = {
        let txn = vault.store.env.read_txn()?;
        BODY_COLLECT.get(&vault.store, &txn, &())?
    };
    let Some(owed) = owed.filter(|owed| owed.due_at <= crate::unix_seconds_now()) else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        let limit = LEFT_ENV_BODY_COLLECT_LIMIT;
        let report = vault.collect_result_bodies(limit)?;
        tracing::info!(
            collected = report.collected,
            orphans = report.orphans,
            pinned = report.pinned,
            "a left env's owed body collection ran"
        );
        // A pinned body, or a full page, may leave more for the next pass.
        if report.pinned > 0
            || report.orphans >= limit
            || report.collected.saturating_add(report.held) >= limit
        {
            return Ok(());
        }
    }
    // Finished: the row goes, unless a purge owed it afresh since it was read.
    vault.with_write_txn_grouped(|wtxn| {
        if BODY_COLLECT.get(&vault.store, wtxn, &())? == Some(owed) {
            BODY_COLLECT.delete(&vault.store, wtxn, &())?;
        }
        Ok(())
    })
}
