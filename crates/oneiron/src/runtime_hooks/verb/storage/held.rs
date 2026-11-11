//! A session-only call's held runs (WILL L11-01 S01-2c): what its chains
//! hold for the call to keep, and the keep's one write of them, in a
//! segment of their own. That write lands each run through the vault's
//! erase fence again, so a run held before an erase of a row it names keeps
//! what the erase's scrub would have left, and the vault's intent and
//! blocks of a run that retires there go with it (FIX 22240). What a store
//! already keeps, the erase's sweep reaches (`scrub_erased_in_session_stores`).

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};

use serde::{Deserialize, Serialize};

use crate::code_run::{
    SessionHookDisposition, SessionHookPhase, SessionHookReceipt, SessionHookState,
};
use crate::receipt::ReceiptRecord;
use crate::runtime_hooks::store::{self, RunKey};
use crate::session_overlay::SessionOverlay;
use crate::side_table::{RoutedDbs, SideTableDbs};
use crate::{Result, Vault};

use super::super::record::{self, HookVerbRunRecord};
use super::{HookRecordsKept, HooksTarget, SessionHookKeep, SessionHooks};

/// One run as a session keeps it: its receipt and its saved copy under its
/// run key, and what the call's answer says of it, but for its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::runtime_hooks::verb) struct HeldRun {
    pub(in crate::runtime_hooks::verb) key: RunKey,
    pub(in crate::runtime_hooks::verb) receipt: ReceiptRecord,
    pub(in crate::runtime_hooks::verb) saved: HookVerbRunRecord,
    pub(in crate::runtime_hooks::verb) hook: String,
    pub(in crate::runtime_hooks::verb) phase: SessionHookPhase,
    pub(in crate::runtime_hooks::verb) state: SessionHookState,
}

impl SessionHookKeep {
    /// Every overlay the keep stages hook records in now, for the erase's
    /// sweep of what they hold (FIX 22240). The keep's lock is released
    /// before any is read.
    pub(crate) fn overlays(&self) -> Vec<Arc<SessionOverlay>> {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .map(|kept| Arc::clone(&kept.overlay))
            .collect()
    }
}

impl SessionHooks<'_> {
    /// Keeps every run held, in one segment of their own, and records what
    /// each hook did, then what the call noted. Each run lands as `vault`'s
    /// erase fence leaves it in that write ([`put_run`]). A store that keeps
    /// none fails nothing.
    pub(super) fn keep(&self, vault: &Vault) -> Result<()> {
        let runs = self.held.take();
        if runs.is_empty() {
            self.dispositions.borrow_mut().extend(self.notes.take());
            return Ok(());
        }
        let rows = |txn: &mut heed::RwTxn<'_>, read: RoutedDbs<'_>, write: RoutedDbs<'_>| {
            let mut retired = BTreeSet::new();
            for run in &runs {
                if put_run(vault, &read, &write, txn, run)? {
                    retired.insert(run.key);
                }
            }
            let at = vault.store.clock.now_recorded_at();
            store::retire_kept_runs_in_txn(vault, txn, &retired, at)
        };
        let kept = match &self.target {
            HooksTarget::Room { session, route, .. } => session.stage_hook_records(route, rows)?,
            HooksTarget::Kept { vault, key } => vault
                .runtime()
                .verb_hook_state()
                .session
                .stage(vault, key, rows)?,
        };
        self.dispositions
            .borrow_mut()
            .extend(runs.into_iter().map(|run| SessionHookDisposition {
                hook: Some(run.hook),
                phase: run.phase,
                state: run.state,
                receipt: match &kept {
                    HookRecordsKept::Kept => SessionHookReceipt::Kept {
                        id: store::receipt_id(&run.key),
                    },
                    HookRecordsKept::NotKept(why) => SessionHookReceipt::NotKept { why: *why },
                },
            }));
        self.dispositions.borrow_mut().extend(self.notes.take());
        Ok(())
    }
}

/// One run's receipt and saved copy as the keep's write lands them: checked
/// again against `vault`'s erase fence in that write, as a chain's own
/// commit checks them ([`store::scrub_erased_verb_run_in_txn`]), so an
/// erase that landed after the hold reaches them; its earlier saved copy
/// read through `read`, and its rows written along `write`. Returns whether
/// its payload retired there.
fn put_run(
    vault: &Vault,
    read: &impl SideTableDbs,
    write: &impl SideTableDbs,
    txn: &mut heed::RwTxn<'_>,
    run: &HeldRun,
) -> Result<bool> {
    let (mut receipt, mut saved) = (run.receipt.clone(), run.saved.clone());
    let retired = store::scrub_erased_verb_run_in_txn(vault, txn, &mut saved, &mut receipt)?;
    store::RECEIPTS.put(write, txn, &run.key, &receipt)?;
    record::put_in_txn(read, write, txn, &run.key, &saved)?;
    Ok(retired)
}
