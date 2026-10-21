//! The Arc backstop (FIX 7509 P8, ARCH-0026: "The nightly sweep is the
//! backstop only"): Arcs aged a nightly cadence past their first dirty mark,
//! stale ones and owed ones are queued from the Nightly recipe's commit and
//! from the elected home's Macro Timer pass, whose deadline the earliest Arc
//! due time arms. No timer, service or rate of its own: the age is the wake
//! policy's `nightly_secs`, and the threshold the recipe row's.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::error::Result;

/// The recipe row's `arc_min_new_statements` and the wake policy's
/// `nightly_secs`, as the Arc gate reads them.
pub(crate) fn arc_policy_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<(u32, u64)> {
    let threshold = super::recipes::policy_in_txn(vault, txn)?.arc_min_new_statements;
    let nightly_secs = super::policy::policy_in_txn(vault, txn)?.nightly_secs;
    Ok((threshold, nightly_secs))
}

/// The Nightly recipe's sweep, in the commit that takes its input: each due
/// Arc is queued as a child of `parent` on `run_id`, and each conversation a
/// standing sitting's summary covers turns in gets its Arc when it has none.
pub(crate) fn enqueue_stale_arcs_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    parent: Option<AttemptId>,
    run_id: Option<&str>,
    now: u64,
) -> Result<()> {
    crate::scope_summary::sweep_due_arcs_in_txn(vault, txn, (parent, run_id), now, true)
}

/// The home's Macro Timer pass sweeps the Arcs due by `now`, on the elected
/// home only. A sweep that fails is logged and never stops the pass.
pub(crate) fn sweep_on_timer(vault: &Vault, now: u64, local_node_id: u64) {
    let swept = vault.with_write_txn_grouped(|txn| {
        if local_node_id == 0
            || crate::identity::load_or_mint_client_id_in_txn(vault, txn)? != local_node_id
            || !DreamerRunnerStore::new(vault)
                .home_node_designation_in_txn(txn)?
                .is_some_and(|home| home.node_id == local_node_id)
        {
            return Ok(false);
        }
        crate::scope_summary::sweep_due_arcs_in_txn(vault, txn, (None, None), now, false)?;
        Ok(true)
    });
    match swept {
        Ok(true) => vault.store.notify_attempt_observers(),
        Ok(false) => {}
        Err(error) => tracing::warn!(kind = ?error.kind(), "due arcs were not swept this pass"),
    }
}

impl Vault {
    /// The earliest instant an Arc is due at (Unix seconds), for the home's
    /// Timer deadline (FIX 7509 P8). An Arc whose attempt is queued is not
    /// here: its queue row arms its own wake.
    pub fn next_arc_due_at(&self) -> Result<Option<u64>> {
        let txn = self.store.env.read_txn()?;
        crate::scope_summary::next_arc_due_in_txn(self, &txn)
    }
}
