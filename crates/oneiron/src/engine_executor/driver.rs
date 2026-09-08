//! Executor driver: struct, constructors, and the witness-turn doors.

use super::types::{EngineExecutorResult, ExecutorLegibility, JsCodeModeRuntime};
use crate::code_run::{ExecutorStorage, GatedActorWrite};
use crate::entity_id::EntityId;
use crate::memory::WitnessReceipt;
use crate::off_record::{ExecutorUtterance, OffRecordSession};
use crate::{BudgetLease, Error, LlmBackend, Vault};
use std::sync::atomic::{AtomicU32, Ordering};

/// Engine-native executor driver.
pub struct EngineNativeExecutor<'a> {
    pub(super) storage: ExecutorStorage<'a>,
    pub(super) backend: &'a dyn LlmBackend,
    pub(super) lease: &'a BudgetLease,
    pub(super) runtime: &'a mut dyn JsCodeModeRuntime,
    pub(super) gated_write: &'a GatedActorWrite<'a>,
    pub(super) legibility: Option<ExecutorLegibility<'a>>,
    /// Next order for the public compatibility witness door, whose callers do
    /// not have an [`EngineExecutorConfig`] run id. Explicit-order witnesses
    /// bypass this allocator and retain their exact order.
    next_witness_order: AtomicU32,
    /// TEST-ONLY (ONE-1929): fails the run once at the moment BETWEEN the
    /// terminal replay commit and the implicit bubble, which is the exact
    /// window the checkpointed payload exists to survive.
    #[cfg(test)]
    pub(super) fail_before_implicit_speak_once: bool,
}

impl<'a> EngineNativeExecutor<'a> {
    #[must_use]
    pub fn new(
        vault: &'a Vault,
        backend: &'a dyn LlmBackend,
        lease: &'a BudgetLease,
        runtime: &'a mut dyn JsCodeModeRuntime,
        gated_write: &'a GatedActorWrite<'a>,
    ) -> Self {
        Self {
            storage: ExecutorStorage::Canonical(vault),
            backend,
            lease,
            runtime,
            gated_write,
            legibility: None,
            next_witness_order: AtomicU32::new(0),
            #[cfg(test)]
            fail_before_implicit_speak_once: false,
        }
    }

    /// Binds a run to an already-acquired live off-record session
    /// (ONE-1729/P4b).
    ///
    /// Every artifact this run produces — replay record, config and terminal
    /// markers, generated scripts, observations, runtime outputs, raw output
    /// bytes, and its turns — follows the session's mode-aware route: the
    /// overlay while the room is off record, ordinary base storage after the
    /// same live session flips on record. There is no executor-specific base
    /// bypass and no durable session row.
    ///
    /// The run's `crate::off_record::SessionWriteRoute` is captured HERE,
    /// at run entry (R-20260807-02 rider 2), which is why this constructor is
    /// fallible where the canonical one is not.
    pub fn for_off_record_session(
        session: &'a OffRecordSession<'a>,
        backend: &'a dyn LlmBackend,
        lease: &'a BudgetLease,
        runtime: &'a mut dyn JsCodeModeRuntime,
        gated_write: &'a GatedActorWrite<'a>,
    ) -> EngineExecutorResult<Self> {
        Ok(Self {
            storage: ExecutorStorage::for_session(session)?,
            backend,
            lease,
            runtime,
            gated_write,
            legibility: None,
            next_witness_order: AtomicU32::new(0),
            #[cfg(test)]
            fail_before_implicit_speak_once: false,
        })
    }

    /// Configures the wake-pass legibility context: every subsequent
    /// bridge-call response carries the budget envelope (ONE-1305).
    #[must_use]
    pub fn with_legibility(mut self, legibility: ExecutorLegibility<'a>) -> Self {
        self.legibility = Some(legibility);
        self
    }

    #[cfg(test)]
    pub(super) fn fail_before_implicit_speak_once_for_test(&mut self) {
        self.fail_before_implicit_speak_once = true;
    }

    /// Records ONE executor turn.
    ///
    /// This is a CALL SITE, not a transcript surface: the turn event is
    /// formed by ONE-1728's facade witness door, the one place conversation
    /// identity, container resolution, role tags, and session routing are
    /// decided. Nothing here mints a message schema, a `BatchOp` program, or
    /// a guest-facing transcript input, and `turn_ref` is not a parameter the
    /// executor has — turn identity comes from the session.
    ///
    /// BOTH storage arms materialize the bubble (ONE-1686): a canonical run
    /// witnesses into the run-scoped shell its dispatcher's run ref derives,
    /// a session-bound run into the room's captured shell. The `Option` is
    /// kept for API compatibility and is now always `Some` on success — a
    /// receipt is the proof that speech happened.
    ///
    /// This is a WRITE-CAPABLE entry point, so it verifies the same
    /// storage/dispatcher binding [`Self::run`] does, before it reads or
    /// writes anything: a mismatched pair that never calls `run` would
    /// otherwise land a turn through one binding's session under the other's
    /// actor.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidConfig` for a mismatched storage/dispatcher
    /// pair, and propagates the witness door's typed refusals — the ONE-1686
    /// approval ceiling and the stale-route family when the room flipped mode
    /// after this run's entry.
    pub fn witness_turn(
        &self,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
    ) -> EngineExecutorResult<Option<WitnessReceipt>> {
        let order = self.allocate_witness_order()?;
        self.witness_turn_at(kind, text, occurred_at, order)
    }

    /// [`Self::witness_turn`], carrying an explicit bubble `order`.
    ///
    /// The order is the emitter's position in the run's bridge ordering, so a
    /// turn recorded outside the bridge can still be placed against the calls
    /// it follows. It is also the bubble's IDENTITY input: the storage door
    /// derives the MESSAGE id from the run identity and this order, so
    /// re-emitting the same position converges on the same row.
    ///
    /// This explicit door never advances [`Self::witness_turn`]'s compatibility
    /// allocator. Durable runtime dispatch and fallback use a private sibling
    /// that also binds [`EngineExecutorConfig::run_id`].
    ///
    /// # Errors
    ///
    /// Same as [`Self::witness_turn`], plus `Error::InvalidConfig` when `order`
    /// exceeds the witness MESSAGE order ceiling.
    pub fn witness_turn_at(
        &self,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
    ) -> EngineExecutorResult<Option<WitnessReceipt>> {
        self.witness_turn_for_run_at(None, kind, text, occurred_at, order)
    }

    fn allocate_witness_order(&self) -> EngineExecutorResult<u32> {
        // Relaxed ordering is sufficient: the atomic protects only uniqueness
        // of the returned integer, not publication of any other memory.
        self.next_witness_order
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |order| {
                if order > crate::gate::MAX_WITNESS_MESSAGE_ORDER {
                    None
                } else {
                    order.checked_add(1)
                }
            })
            .map_err(|_| {
                Error::InvalidConfig(
                    "engine executor compatibility witness order exhausted".to_owned(),
                )
                .into()
            })
    }

    pub(super) fn witness_turn_for_run_at(
        &self,
        run_id: Option<EntityId>,
        kind: ExecutorUtterance,
        text: &str,
        occurred_at: u64,
        order: u32,
    ) -> EngineExecutorResult<Option<WitnessReceipt>> {
        if order > crate::gate::MAX_WITNESS_MESSAGE_ORDER {
            return Err(Error::InvalidConfig(
                "engine executor witness order exceeds the MESSAGE order ceiling".to_owned(),
            )
            .into());
        }
        self.verify_storage_dispatcher_binding()?;
        Ok(Some(self.storage.witness_executor_utterance(
            self.gated_write.run_ref(),
            run_id,
            kind,
            text,
            occurred_at,
            order,
            self.gated_write.actor(),
        )?))
    }

    /// Refuses a mismatched storage/dispatcher pair before ANY read or write.
    ///
    /// Correctness must not rest on a caller having picked the matching
    /// constructor pair, so both dimensions are checked: the session ref, and
    /// the OWNING STORE. The store check is what catches two vaults whose
    /// refs compare equal — `None == None` for a pair of canonical runs, or
    /// the same session ref entered in two different vaults.
    pub(super) fn verify_storage_dispatcher_binding(&self) -> EngineExecutorResult<()> {
        if self.storage.session_ref() != self.gated_write.session_ref()
            || !std::ptr::eq(
                self.storage.store_identity(),
                self.gated_write.store_identity(),
            )
        {
            return Err(Error::InvalidConfig(
                "executor storage/dispatcher binding mismatch".to_owned(),
            )
            .into());
        }
        Ok(())
    }
}
