//! The attempt queue operations the store layer runs but the engine owns: the
//! trait the engine implements, and the store-layer eraser the derived-row
//! sweep names.

use std::collections::BTreeSet;

use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;
use crate::store::attempt_inputs::{ClaimAttempt, FailAttempt, RetryAttempt};
use crate::store::attempt_outcomes::{ClaimOutcome, FailOutcome, RetryOutcome};

/// The engine's attempt queue operations the store layer calls. A store holds
/// one implementation from the moment it is assembled (see
/// [`crate::store::StoreHooks`]). Each method is the engine operation of the
/// same name; each store-layer caller calls it at the point, with the
/// arguments and in the order it called the engine operation before.
pub(crate) trait StoreAttemptOperations: Send + Sync {
    /// The engine's `attempt_queue::erase_attempt_payload_actor_in_txn`: the
    /// dispatch text one hard-erased actor owns leaves the attempt payloads.
    fn erase_attempt_payload_actor_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()>;

    /// The engine's `attempt_queue::erase_attempt_payload_actors_in_txn`: the
    /// same erasure for every actor in `actors`, in one pass over the ledger.
    fn erase_attempt_payload_actors_in_txn(
        &self,
        store: &Store,
        txn: &mut RwTxn<'_>,
        actors: &BTreeSet<EntityId>,
    ) -> Result<()>;

    /// The engine's `attempt_queue::erase_model_step_failure_reasons_in_txn`:
    /// the queue copy of a public model step's failure text (FIX 10460).
    fn erase_model_step_failure_reasons_in_txn(
        &self,
        store: &Store,
        wtxn: &mut RwTxn<'_>,
        owner: &EntityId,
    ) -> Result<()>;

    /// The engine's `AttemptQueue::claim_kind`, on a queue handle opened over
    /// `vault`.
    fn claim_kind(
        &self,
        vault: &crate::Vault,
        kind: &str,
        input: ClaimAttempt,
    ) -> Result<ClaimOutcome>;

    /// The engine's `AttemptQueue::fail`, on a queue handle opened over
    /// `vault`.
    fn fail(&self, vault: &crate::Vault, input: FailAttempt) -> Result<FailOutcome>;

    /// The engine's `AttemptQueue::retry_in_txn`, on a queue handle opened
    /// over `vault`, in the caller's writer.
    fn retry_in_txn(
        &self,
        vault: &crate::Vault,
        wtxn: &mut RwTxn<'_>,
        input: RetryAttempt,
    ) -> Result<RetryOutcome>;
}

/// The derived-row eraser the per-entity sweep names for FIX 10460: the
/// engine's `attempt_queue::erase_model_step_failure_reasons_in_txn`, through
/// the store's attempt operations.
pub(crate) fn erase_model_step_failure_reasons_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    store
        .attempt_operations
        .erase_model_step_failure_reasons_in_txn(store, wtxn, owner)
}
