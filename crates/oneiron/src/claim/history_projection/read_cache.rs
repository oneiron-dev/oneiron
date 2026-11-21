//! One read's verified machine histories, each resolved once (FIX
//! MACHINE-HISTORY-PAGE-PER-CONTROL-RESOLVE).
//!
//! A selector's page or export judges every control of a machine CLAIM's
//! history, and every control of one target rests on the same verified
//! history in one read transaction. [`MachineHistoryReadCache`] keeps one
//! [`TargetHistory`] per target for the read, so a page or an export of N
//! controls resolves each history once, not about 2N times.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use super::*;
use crate::authority::AuthorityView;

/// The machine histories one read transaction of a vault resolves: one
/// [`TargetHistory`] per target, under the authority view the vault holds in
/// that read.
///
/// Build it for one read transaction and ask it only in that one: what it
/// keeps is that snapshot's. It is a cache of reads, never a judgement of its
/// own: every answer is the one the uncached check gives in the same read.
pub(crate) struct MachineHistoryReadCache<'s> {
    vault: &'s Vault,
    /// The vault's authority view in the read, read on first ask as the
    /// uncached checks read it. The vault's posture is its store's (both are
    /// the opened config's), so this is the fold both the causal check and
    /// the disclosure scope read.
    fold: OnceCell<AuthorityView>,
    targets: RefCell<HashMap<EntityId, Rc<TargetHistory>>>,
}

impl<'s> MachineHistoryReadCache<'s> {
    /// The cache for one read transaction of `vault`.
    pub(crate) fn new(vault: &'s Vault) -> Self {
        Self {
            vault,
            fold: OnceCell::new(),
            targets: RefCell::default(),
        }
    }

    pub(crate) fn store(&self) -> &'s Store {
        &self.vault.store
    }

    /// The vault's authority fold in the read `txn`.
    ///
    /// # Errors
    ///
    /// The authority view's read errors.
    pub(crate) fn fold(&self, txn: &heed::RoTxn<'_>) -> Result<&AuthorityFold> {
        if let Some(view) = self.fold.get() {
            return Ok(&**view);
        }
        let view = self.vault.authority_view_readonly_in_txn(txn)?;
        Ok(&**self.fold.get_or_init(|| view))
    }

    /// The history of `target` this read resolves, one per target.
    pub(crate) fn target(&self, target: EntityId) -> Rc<TargetHistory> {
        Rc::clone(
            self.targets
                .borrow_mut()
                .entry(target)
                .or_insert_with(|| Rc::new(TargetHistory::new(target))),
        )
    }
}
