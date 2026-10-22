//! The [`AttemptQueue`] handle and its lease state machine.
//!
//! Deliberately kept whole: enqueue, claim, complete, fail, retry, intervene,
//! manifest append, cleanup, and the read paths are one transactional
//! discipline over the same LMDB row set. Supporting concerns live beside it —
//! types in [`super::types`], validators in [`super::validate`], key/row
//! encoding in [`super::encoding`], counters in [`super::telemetry`], and the
//! ONE-1896 graceful-cancel/landing doors in [`super::cancel`].
mod defer;
mod enqueue_claim;
mod enqueue_record;
mod mutate;
mod owner_retained_payload;
mod place;
mod prune;
mod reads;
mod reclaim;
mod redirect;
mod requeue;
mod successor;
mod task_lease;
mod workflow;

use crate::scan_check::{EngineScan, ScanCount};
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
pub(super) use self::requeue::validate_requeued_history;
pub use self::requeue::{RequeueAttempt, RequeuedFailure};

impl<'a> AttemptQueue<'a> {
    pub(crate) fn from_store(store: &'a Store) -> Self {
        Self { store, vault: None }
    }

    /// One row's bytes, read once by the side-row wall in the writer's
    /// transaction (OF-067; [`super::encoding::encode_admitted_record`]). A
    /// vault-opened handle lifts a secret the payload or notes hold into
    /// custody; a store-only handle holds no custody door and refuses one.
    /// An erased dispatch target's text leaves the row first (FIX 7076).
    pub(super) fn encode_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        record: &mut super::AttemptRecord,
    ) -> crate::Result<Vec<u8>> {
        super::payload_erase::scrub_hard_erased_payload_in_txn(self.store, wtxn, record);
        // FIX 9578: a settled row carries what it left behind, written with
        // the write that settles it, whichever door settles it.
        super::result::settle_terminal_exhaust(record);
        observe_event_bytes(self.store, wtxn, record);
        match self.vault {
            Some(vault) => super::encoding::encode_admitted_record(vault, wtxn, record),
            None => super::encoding::encode_admitted_record(self.store, wtxn, record),
        }
    }
}

/// The longest actor and note `record` carries, each against its scan row
/// (FIX 9580): what the queue once refused past is observed, never refused.
/// A threshold row that does not read skips the observation, never the
/// write; the crossing waits for the vault's next write of its own.
fn observe_event_bytes(store: &Store, txn: &heed::RoTxn<'_>, record: &super::AttemptRecord) {
    let actors = record.events.iter().map(|event| event.actor.len()).chain(
        record
            .cancel_receipts()
            .iter()
            .map(|receipt| receipt.actor.len()),
    );
    let notes = record
        .events
        .iter()
        .filter_map(|event| event.note.as_deref().map(str::len));
    for (scan, longest) in [
        (EngineScan::AttemptEventActorBytes, actors.max()),
        (EngineScan::AttemptEventNoteBytes, notes.max()),
    ] {
        let Some(longest) = longest else {
            continue;
        };
        if let Ok(mut count) = ScanCount::start(store, txn, scan, record.id.as_bytes()) {
            count.rows(longest);
            count.defer(store);
        }
    }
}
