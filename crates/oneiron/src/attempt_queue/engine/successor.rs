//! The successor of a terminally failed attempt (FIX 3694, OF-568): the one
//! new try an owner-approved prompt continuation runs as.
//!
//! It is linked by `retry_of`, the row link a retry and a landing handoff
//! use, so every surface that folds a chain to its live head treats the
//! failed row as superseded history. Unlike a retry it starts from a row
//! that is already terminal: the failed row is read, never written, and the
//! successor copies exactly the six fields `retries_the_same_attempt`
//! compares, so the link holds as a lineage.

use crate::attempt_queue::cancel::{AttemptCancelState, AttemptLandingReserve};
use crate::attempt_queue::encoding::{DedupeIndexKeys, decode_record, ready_at, ready_key};
use crate::attempt_queue::telemetry::invalid_transition;
use crate::attempt_queue::types::{AttemptId, AttemptRecord, AttemptState};
use crate::error::{Error, Result};

use super::AttemptQueue;

/// The action a refused successor names.
const SUCCESSOR_ACTION: &str = "successor_of_failed";

impl AttemptQueue<'_> {
    /// Mints the queued successor of `predecessor`, a `Failed` attempt, in
    /// the caller's write transaction: a fresh id, the predecessor's kind,
    /// payload, TASK, run group and dedupe key and scope, `retry_of` the
    /// predecessor, no lease, no tries yet, empty logs and an unspent
    /// landing reserve on the same dial. The predecessor stays as it is.
    ///
    /// The successor enters the ready, run and dedupe indexes as an enqueue
    /// does. A pending row that holds the dedupe key keeps it: the successor
    /// is refused, never handed the key.
    ///
    /// # Errors
    ///
    /// An invalid transition when the predecessor is missing or not
    /// `Failed`, when a row of its run is already `retry_of` it, or when
    /// another pending row holds its dedupe key; an id collision; storage
    /// errors. The caller aborts its transaction then.
    pub(crate) fn successor_of_failed_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        predecessor: AttemptId,
        now: u64,
    ) -> Result<AttemptRecord> {
        let Some(raw) = self
            .store
            .attempt_records
            .get(txn, predecessor.as_bytes())?
        else {
            return Err(invalid_transition(SUCCESSOR_ACTION, "missing"));
        };
        let source = decode_record(&raw, predecessor)?;
        if source.state != AttemptState::Failed {
            return Err(invalid_transition(SUCCESSOR_ACTION, source.state.as_str()));
        }
        // A retry that already took the failed row's place is its live try,
        // or its history: a second successor would fork the chain.
        if let Some(run_id) = source.run_id.as_deref() {
            let superseded = self
                .list_run_in_txn(txn, run_id)?
                .iter()
                .any(|record| record.retry_of == Some(predecessor));
            if superseded {
                return Err(invalid_transition(SUCCESSOR_ACTION, "superseded"));
            }
        }
        // The failed row gave its entry up when it settled; a pending row
        // that took the key since owns it now.
        if let Some(dedupe_key) = source.dedupe_key.as_deref() {
            let scope = source.dedupe_actor_ref.as_deref();
            let keys = DedupeIndexKeys::new(&source.kind, scope, dedupe_key);
            if self
                .read_existing_dedupe_in_write_txn(txn, &keys, &source.kind, scope, dedupe_key)?
                .is_some()
            {
                return Err(invalid_transition(SUCCESSOR_ACTION, "dedupe_key_held"));
            }
        }

        let id = AttemptId::from_bytes(&self.store.clock.ulid()?)?;
        let mut successor = failed_successor(&source, id, now);
        crate::attempt_queue::check_owner_retained_range(&successor.kind, &successor.id)?;
        if self
            .store
            .attempt_records
            .get(txn, successor.id.as_bytes())?
            .is_some()
        {
            return Err(Error::InvariantViolation("attempt id collision"));
        }
        // The minted id joins the persisted id floor.
        crate::ports::recorded_at_in_txn(self.store, txn)?;
        let encoded = self.encode_in_txn(txn, &mut successor)?;
        self.store
            .attempt_records
            .put(txn, successor.id.as_bytes(), &encoded)?;
        let ready_key = ready_key(ready_at(&successor), successor.id);
        self.store
            .attempt_ready
            .put(txn, &ready_key, successor.id.as_bytes())?;
        self.store.put_attempt_run_index_in_txn(
            txn,
            successor.run_id.as_deref(),
            successor.id.as_bytes(),
        )?;
        // The entry comes from the scope the successor copied, as a retry's
        // does: one chain, one key family.
        if let Some(dedupe_key) = successor.dedupe_key.as_deref() {
            let keys = DedupeIndexKeys::new(
                &successor.kind,
                successor.dedupe_actor_ref.as_deref(),
                dedupe_key,
            );
            self.store
                .attempt_dedupe
                .put(txn, &keys.primary[..], successor.id.as_bytes())?;
        }
        Ok(successor)
    }
}

/// The queued row that continues `source`, a failed attempt, under `id`.
/// Modelled on the landing successor, without its resume point: what a
/// continuation resumes from is its own row, never this one's.
fn failed_successor(source: &AttemptRecord, id: AttemptId, now: u64) -> AttemptRecord {
    AttemptRecord {
        id,
        kind: source.kind.clone(),
        payload: source.payload.clone(),
        state: AttemptState::Queued,
        lease_owner: None,
        attempt_count: 0,
        claimed_at: None,
        scheduled_at: None,
        retry_of: Some(source.id),
        folded_retries: 0,
        backoff_until: None,
        last_error: None,
        task_ref: source.task_ref.clone(),
        run_id: source.run_id.clone(),
        dedupe_key: source.dedupe_key.clone(),
        dedupe_actor_ref: source.dedupe_actor_ref.clone(),
        created_at: now,
        updated_at: now,
        events: Vec::new(),
        manifest: Vec::new(),
        executor_model: None,
        executor_seat: None,
        executor_role: None,
        // The dial's values carry over; its one-shot mark and the spent
        // reserve do not: the successor's own admission dials it.
        cancel_state: AttemptCancelState {
            reserve: AttemptLandingReserve {
                spent_units: 0,
                dial_generation: None,
                ..source.cancel_state.reserve
            },
            ..AttemptCancelState::default()
        },
        signals: Vec::new(),
        asks: Vec::new(),
        placement: source.placement.as_ref().map(|placement| {
            crate::attempt_queue::AttemptPlacement {
                worker: placement.worker.clone(),
                // Below its predecessor, not beside it.
                parent: Some(source.id),
            }
        }),
        result_ref: None,
    }
}
