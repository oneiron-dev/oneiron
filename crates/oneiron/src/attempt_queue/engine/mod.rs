//! The [`AttemptQueue`] handle and its lease state machine.
//!
//! Deliberately kept whole: enqueue, claim, complete, fail, retry, intervene,
//! manifest append, cleanup, and the read paths are one transactional
//! discipline over the same LMDB row set. Supporting concerns live beside it —
//! types in [`super::types`], validators in [`super::validate`], key/row
//! encoding in [`super::encoding`], counters in [`super::telemetry`], and the
//! ONE-1896 graceful-cancel/landing doors in [`super::cancel`].
mod enqueue_claim;
mod mutate;
mod place;
mod prune;
mod reads;
mod redirect;
mod task_lease;
mod workflow;

use crate::store::Store;

/// Queue handle over a vault store.
pub struct AttemptQueue<'a> {
    /// Visible to the whole `attempt_queue` module tree: the ONE-1896 cancel
    /// doors in [`super::cancel`] are inherent methods on this same handle and
    /// run against this same store under the same transactional discipline.
    pub(super) store: &'a Store,
    /// The vault this handle was opened over ([`Self::new`]); `None` for a
    /// store-only handle. Settling a row through a vault-opened handle also
    /// records its inbox notification (OF-221) through the vault's own write
    /// door; a store-only handle writes no entity.
    pub(super) vault: Option<&'a crate::Vault>,
}

use self::enqueue_claim::ERR_DEDUPE_ACTOR_MISMATCH;
pub(crate) use self::reads::dreamer_run_root_id_in_txn;
#[cfg(test)]
pub(super) use self::reads::{
    ERR_RETRY_CHAIN_CYCLE, ERR_RETRY_CHAIN_MISMATCH, ERR_RETRY_CHAIN_MISSING_ROW,
};

impl<'a> AttemptQueue<'a> {
    pub(crate) fn from_store(store: &'a Store) -> Self {
        Self { store, vault: None }
    }

    /// One row's bytes, read once by the side-row wall in the writer's
    /// transaction (OF-067; [`super::encoding::encode_admitted_record`]). A
    /// vault-opened handle lifts a secret the payload or notes hold into
    /// custody; a store-only handle holds no custody door and refuses one.
    pub(super) fn encode_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &mut super::AttemptRecord,
    ) -> crate::Result<Vec<u8>> {
        match self.vault {
            Some(vault) => super::encoding::encode_admitted_record(vault, wtxn, record),
            None => super::encoding::encode_admitted_record(self.store, wtxn, record),
        }
    }
}
