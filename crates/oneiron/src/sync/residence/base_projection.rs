//! The owner's discard of a world copy, carried into each BASE window it
//! took rows from (FIX 14534 part E, Engine 11-06 23:52). The write that
//! takes a window's rows marks its projection owed
//! (`sync::window::mark_projection_owed_in_txn`); a pass projects every
//! window that owes one for all the rows the discard marked
//! (`wd:e:`), held closed, and settles it once installed or once nothing
//! there is the rows'. A window a handle holds open, whose home has not
//! acked every operation it holds, or with a queued send, waits for the
//! next pass: the owner's discard and every home eviction pass run one.

use crate::Vault;
use crate::error::Result;
use crate::sync::WindowKey;
use crate::sync::window::{
    DiscardInstall, install_discard_projection, owed_projections_in, settle_projection_in_txn,
};

/// What one pass over the owed projections came to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct BaseProjections {
    /// Windows whose persisted state the projection replaced.
    pub(super) installed: usize,
    /// Windows that wait for a later pass: open, queued, ahead of the home,
    /// or a document the projection cannot place.
    pub(super) waiting: usize,
}

/// Projects each BASE window whose projection is owed, for every row the
/// owner's discard marks once that window is closed.
///
/// # Errors
/// Store errors; a stored document that does not open.
pub(super) fn project_owed_windows(vault: &Vault) -> Result<BaseProjections> {
    let windows = {
        let txn = vault.store.env.read_txn()?;
        owed_projections_in(&vault.store, &txn)?
    };
    let mut pass = BaseProjections::default();
    for window in windows {
        let Some(key) = WindowKey::try_new(&window) else {
            continue;
        };
        vault.unload_idle_window(&key)?;
        let step = vault.while_window_closed(&key, || install_discard_projection(vault, &key));
        match step.transpose()? {
            Some(DiscardInstall::Installed { erased, rewritten }) => {
                tracing::info!(
                    %window,
                    erased,
                    rewritten,
                    "BASE window projected for the owner's discard"
                );
                pass.installed += 1;
            }
            Some(DiscardInstall::Unchanged) => {
                vault.with_write_txn_grouped(|txn| {
                    settle_projection_in_txn(&vault.store, txn, &window)
                })?;
            }
            Some(DiscardInstall::Deferred(why)) => {
                tracing::info!(%window, why, "BASE window projection waits");
                pass.waiting += 1;
            }
            None => pass.waiting += 1,
        }
    }
    Ok(pass)
}
