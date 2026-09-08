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
mod reads;

use crate::store::Store;

/// Queue handle over a vault store.
pub struct AttemptQueue<'a> {
    /// Visible to the whole `attempt_queue` module tree: the ONE-1896 cancel
    /// doors in [`super::cancel`] are inherent methods on this same handle and
    /// run against this same store under the same transactional discipline.
    pub(super) store: &'a Store,
}

use self::enqueue_claim::ERR_DEDUPE_ACTOR_MISMATCH;
#[cfg(test)]
pub(super) use self::mutate::RETRY_REASON_UNSPECIFIED;
pub(crate) use self::reads::dreamer_run_root_id_in_txn;
#[cfg(test)]
pub(super) use self::reads::{
    ERR_RETRY_CHAIN_CYCLE, ERR_RETRY_CHAIN_MISMATCH, ERR_RETRY_CHAIN_MISSING_ROW,
    RETRY_CHAIN_DEPTH_LIMIT,
};
