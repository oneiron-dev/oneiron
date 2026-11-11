//! A permanent erase in a session's own store of hook records (FIX 22240).
//! A session-only call's chains keep their runs' receipts and saved copies
//! in a live room's overlay or in the in-memory keep (`SessionHookKeep`),
//! where the vault's hook scrub never looks. Two parts reach them, as FIX
//! 7366 reaches a room's code runs.
//!
//! - The fence: the keep's own write lands each run it held through
//!   [`super::scrub_erased_verb_run_in_txn`], so a run held before an erase
//!   of a row it names lands as that erase's scrub would have left it.
//! - The sweep ([`scrub_erased_in_session_stores`]): once an erase's write
//!   commits, each live room's overlay and each keep rewrites the runs and
//!   receipts it already holds that name an erased id, as the vault's scrub
//!   rewrites its own, and the vault's intents and blocks of a run that
//!   retires go with it. Only rows a store stages are touched; a row in
//!   base is the vault's own scrub's.
//!
//! Lock order is the vault writer, then the overlay's segment permit, as a
//! routed write takes them. The segment is published as the write commits,
//! before any post-commit work that needs a writer, so a routed writer
//! waiting on that segment never waits behind it. The keep's own lock is
//! not held meanwhile.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{
    RunErase, erase_receipt_caller, erase_verb_run, erased_among_in_txn, retire_kept_runs_in_txn,
    scrub_receipt_payload, scrub_verb_payload,
};
use crate::runtime_hooks::store::{RECEIPTS, RunKey};
use crate::runtime_hooks::verb::VERB_RUNS;
use crate::session_overlay::{OverlayKeyspace, SessionOverlay, SnapshotMergeRow, TxnSegmentGuard};
use crate::side_table::RoutedDbs;
use crate::{EntityId, Result, Vault};

/// Rewrites what every live room's overlay and every in-memory keep holds
/// of the hook runs that name an id of `ids` a permanent erase fenced: each
/// saved run as the vault's scrub leaves its own, each Hook receipt with
/// it, and the vault's intents and blocks of a run that retires. Runs once
/// the erase's write committed, holding no vault writer. A store whose
/// sweep fails is logged and the next one runs; its session's close drops
/// what it keeps.
pub(crate) fn scrub_erased_in_session_stores(vault: &Vault, ids: &[EntityId]) {
    let named = || -> Result<bool> {
        let rtxn = vault.store.env.read_txn()?;
        Ok(erased_among_in_txn(vault, &rtxn, ids.iter().copied().collect(), &[])?.is_some())
    };
    if ids.is_empty() || !named().unwrap_or(true) {
        return;
    }
    let stores = vault
        .store
        .off_record_sessions
        .live_overlay_handles()
        .into_iter()
        .chain(vault.runtime().verb_hook_state().session.overlays());
    for overlay in stores {
        if let Err(error) = scrub_store(vault, &overlay, ids) {
            tracing::warn!(
                kind = ?error.kind(),
                "a session's kept hook runs that name an erased id stay until its close"
            );
        }
    }
}

/// One store's sweep. Its keys are read only once this writer holds the
/// vault writer and the overlay's segment permit: the permit waits for any
/// keep still publishing its segment, and the snapshot taken under it shows
/// that write, so no run of an in-flight keep is missed. The segment is
/// published as the write commits ([`TxnSegmentGuard::commit`]), as
/// `SessionHookKeep::stage` publishes its own.
fn scrub_store(vault: &Vault, overlay: &Arc<SessionOverlay>, ids: &[EntityId]) -> Result<()> {
    vault.with_write_txn_grouped_after_commit(
        |wtxn| {
            let segment = overlay.install_txn_segment()?;
            let erased = {
                let txn: &heed::RoTxn<'_> = wtxn;
                erased_among_in_txn(vault, txn, ids.iter().copied().collect(), &[])?
            };
            let Some(erased) = erased else {
                return Ok(segment);
            };
            let runs = staged_keys(overlay, VERB_RUNS.decl().prefix)?;
            let receipts = staged_keys(overlay, RECEIPTS.decl().prefix)?;
            if runs.is_empty() && receipts.is_empty() {
                return Ok(segment);
            }
            let view = vault.store.session_view(Arc::clone(overlay))?;
            let dbs = RoutedDbs::Session(&view);
            let mut retired = BTreeSet::new();
            for key in &runs {
                let Some(mut record) = VERB_RUNS.get_lenient(&dbs, wtxn, key)? else {
                    continue;
                };
                match erase_verb_run(&mut record, &erased) {
                    RunErase::Unchanged => continue,
                    RunErase::Rewritten => {}
                    RunErase::Depends => {
                        scrub_verb_payload(&mut record);
                        retired.insert(*key);
                    }
                }
                VERB_RUNS.put(&dbs, wtxn, key, &record)?;
            }
            for key in &receipts {
                let Some(mut receipt) = RECEIPTS.get_lenient(&dbs, wtxn, key)? else {
                    continue;
                };
                let caller = erase_receipt_caller(&mut receipt, &erased);
                if retired.contains(key)
                    || receipt
                        .trigger_ref
                        .as_deref()
                        .is_some_and(|trigger| erased.is_ref(trigger))
                {
                    scrub_receipt_payload(&mut receipt);
                } else if !caller {
                    continue;
                }
                RECEIPTS.put(&dbs, wtxn, key, &receipt)?;
            }
            let at = vault.store.clock.now_recorded_at();
            retire_kept_runs_in_txn(vault, wtxn, &retired, at)?;
            Ok(segment)
        },
        TxnSegmentGuard::commit,
    )
}

/// The run keys of the rows `overlay` stages under `prefix`, as one
/// snapshot reads them; deletions over base are none of them. Under this
/// thread's installed segment the snapshot is that segment's view.
fn staged_keys(overlay: &Arc<SessionOverlay>, prefix: &[u8]) -> Result<Vec<RunKey>> {
    let snapshot = overlay.snapshot()?;
    let plan = snapshot.merge_plan(OverlayKeyspace::VaultMeta, |key| key.starts_with(prefix));
    Ok(plan
        .rows
        .into_iter()
        .filter_map(|row| match row {
            SnapshotMergeRow::Single {
                key,
                value: Some(_),
            } => key
                .strip_prefix(prefix)
                .and_then(|key| RunKey::try_from(key).ok()),
            _ => None,
        })
        .collect())
}
