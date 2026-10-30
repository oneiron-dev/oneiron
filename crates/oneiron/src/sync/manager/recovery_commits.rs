//! The updates a window's cold-open recovery commits, each persisted and
//! routed as the commit it is (FIX 5133). The recovery's passes commit each
//! MESSAGE document and pin part on its own so no update outgrows a frame
//! (FIX 853); one export of the whole recovery would join them back into one
//! update, and a first open of a large month would queue it offline whole.
//!
//! The recovery runs on the bare doc, before Observer A attaches, so the
//! commits are gathered here from its start and handed on as Observer A
//! hands on a local update (FIX 3095). What the recovery imports from this
//! window's own persisted rows is durable already and is not sent again.

use std::sync::{Arc, Mutex, PoisonError};

use loro::{LoroDoc, Subscription};

use super::WindowManager;
use crate::error::Result;
use crate::sync::types::WindowKey;

/// The local commits of one recovery, in commit order.
pub(super) struct RecoveryCommits {
    updates: Arc<Mutex<Vec<Vec<u8>>>>,
    _watch: Subscription,
}

impl RecoveryCommits {
    /// Gathers every local commit `doc` makes from now on.
    pub(super) fn watch(doc: &LoroDoc) -> Self {
        let updates = Arc::new(Mutex::new(Vec::new()));
        let gathered = Arc::clone(&updates);
        let watch = doc.subscribe_local_update(Box::new(move |update| {
            gathered
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(update.to_vec());
            true
        }));
        Self {
            updates,
            _watch: watch,
        }
    }

    /// Stops gathering, persists every gathered update of window `key` in
    /// one transaction, then routes each in commit order.
    pub(super) fn route(self, manager: &WindowManager, key: &WindowKey) -> Result<()> {
        let Self {
            updates,
            _watch: watch,
        } = self;
        drop(watch);
        let updates = std::mem::take(&mut *updates.lock().unwrap_or_else(PoisonError::into_inner));
        if updates.is_empty() {
            return Ok(());
        }
        manager.vault.with_write_txn_grouped(|wtxn| {
            for update in &updates {
                crate::sync::bridge::persist_window_update_in_txn(
                    &manager.vault,
                    wtxn,
                    key.as_str(),
                    update,
                )?;
            }
            Ok(())
        })?;
        for update in &updates {
            manager.outbound.route(&manager.vault, key.as_str(), update);
        }
        Ok(())
    }
}
