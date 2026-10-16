//! Executor driver: struct, constructors, and the witness-turn doors.

use super::types::{EngineExecutorResult, ExecutorLegibility, JsCodeModeRuntime};
use crate::code_run::{ExecutorStorage, GatedActorWrite};
use crate::compaction::output::{OutputDecayPolicy, OutputWorkingContext};
use crate::entity_id::EntityId;
use crate::llm::seat::ModelSeat;
use crate::memory::WitnessReceipt;
use crate::off_record::{ExecutorUtterance, OffRecordSession};
use crate::result_memory::{ResultHold, ResultShare};
use crate::{BudgetLease, Error, LlmBackend, Vault};
use std::sync::atomic::{AtomicU32, Ordering};

/// Engine-native executor driver.
pub struct EngineNativeExecutor<'a> {
    pub(super) storage: ExecutorStorage<'a>,
    pub(super) backend: &'a dyn LlmBackend,
    pub(super) seat: Option<&'a ModelSeat>,
    pub(super) lease: &'a BudgetLease,
    pub(super) runtime: &'a mut dyn JsCodeModeRuntime,
    pub(super) gated_write: &'a GatedActorWrite<'a>,
    pub(super) legibility: Option<ExecutorLegibility<'a>>,
    pub(super) output_context: OutputWorkingContext,
    pub(super) output_run: Option<EntityId>,
    pub(super) output_decay: OutputDecayPolicy,
    /// This run's share of the result-memory pool (OF-190 B++).
    pub(super) result_share: ResultShare,
    /// What the context this run built last holds of its share: the bodies
    /// its Full views carry, given back when the next context is built.
    pub(super) context_holds: Vec<ResultHold>,
    /// The host's compaction seat for this run, when it keeps one.
    pub(super) compaction: Option<&'a mut super::compaction::RunCompaction>,
    /// Shadow mode: each program is type-checked before it runs, and the
    /// check is recorded, never acted on.
    pub(super) code_check: Option<&'a oneiron_code_check::ShadowCheck>,
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
            result_share: vault.result_share(),
            context_holds: Vec::new(),
            storage: ExecutorStorage::Canonical(vault),
            backend,
            seat: None,
            lease,
            runtime,
            gated_write,
            legibility: None,
            output_context: OutputWorkingContext::default(),
            output_run: None,
            output_decay: OutputDecayPolicy {
                overview_after_turns: 2,
                stub_after_turns: 5,
            },
            compaction: None,
            code_check: None,
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
        let storage = ExecutorStorage::for_session(session, gated_write.actor().entity_ref())?;
        Ok(Self {
            result_share: storage.result_share(),
            context_holds: Vec::new(),
            storage,
            backend,
            seat: None,
            lease,
            runtime,
            gated_write,
            legibility: None,
            output_context: OutputWorkingContext::default(),
            output_run: None,
            output_decay: OutputDecayPolicy {
                overview_after_turns: 2,
                stub_after_turns: 5,
            },
            compaction: None,
            code_check: None,
            next_witness_order: AtomicU32::new(0),
            #[cfg(test)]
            fail_before_implicit_speak_once: false,
        })
    }

    /// Bind the already-resolved run seat. The executor applies the pin to
    /// every provider request BEFORE canonical hashing and backend admission.
    #[must_use]
    pub fn with_model_seat(mut self, seat: &'a ModelSeat) -> Self {
        self.seat = Some(seat);
        self
    }

    /// Configures the wake-pass legibility context: every subsequent
    /// bridge-call response carries the budget envelope (ONE-1305).
    #[must_use]
    pub fn with_legibility(mut self, legibility: ExecutorLegibility<'a>) -> Self {
        self.legibility = Some(legibility);
        self
    }

    /// Shadow mode: type-check each generated program before it runs and
    /// record what the check found beside the step. The program runs as it
    /// would unchecked; nothing is blocked.
    #[must_use]
    pub fn with_code_check(mut self, shadow: &'a oneiron_code_check::ShadowCheck) -> Self {
        self.code_check = Some(shadow);
        self
    }

    /// Host policy for code-run console context. The default keeps the most
    /// recent observations full, then a bounded overview, then a reference.
    #[must_use]
    pub fn with_output_decay(mut self, policy: OutputDecayPolicy) -> Self {
        self.output_decay = policy;
        self
    }

    /// Binds the host's compaction seat for this run (agent-runtime-v1 §d7):
    /// the window compacts itself, and fills park with a typed reason. A run
    /// bound to an off-record room compacts into the room's overlay, along
    /// the route it captured at entry.
    #[must_use]
    pub fn with_compaction(mut self, seat: &'a mut super::compaction::RunCompaction) -> Self {
        if let ExecutorStorage::Session(binding) = &self.storage {
            seat.bind_room(binding.route.target());
        }
        // Docs Q13: the agent's own decay thresholds, when its profile names them.
        if let Some(decay) = seat.output_decay() {
            self.output_decay = decay;
        }
        self.compaction = Some(seat);
        self
    }

    /// Land a gated compaction in the SAME output context used to build this
    /// executor's next model request. A rejected mint changes no output views.
    /// The request must be this run's own session, so no other run's
    /// lineage can bind these steps. The run's host door rules first, as it
    /// does on the seat's landing (#1405, Wonder P3-1).
    pub fn integrate_compaction(
        &mut self,
        driver: &mut crate::compaction::CompactionDriver,
        byline: crate::WriteActor,
        gated: crate::compaction::GatedCompaction,
        accumulated: &[crate::compaction::CompactionWindowMessage],
    ) -> EngineExecutorResult<crate::compaction::SwapPlan> {
        self.admit_compaction_read()?;
        let placement = crate::compaction::EpochPlacement::default();
        self.integrate_in(driver, byline, placement, gated, accumulated)
    }

    /// The run seat's swap: its summary is born at the run's `placement`.
    pub(super) fn integrate_placed(
        &mut self,
        driver: &mut crate::compaction::CompactionDriver,
        byline: crate::WriteActor,
        placement: crate::compaction::EpochPlacement,
        gated: crate::compaction::GatedCompaction,
    ) -> EngineExecutorResult<crate::compaction::SwapPlan> {
        self.integrate_in(driver, byline, placement, gated, &[])
    }

    fn integrate_in(
        &mut self,
        driver: &mut crate::compaction::CompactionDriver,
        byline: crate::WriteActor,
        placement: crate::compaction::EpochPlacement,
        gated: crate::compaction::GatedCompaction,
        accumulated: &[crate::compaction::CompactionWindowMessage],
    ) -> EngineExecutorResult<crate::compaction::SwapPlan> {
        self.verify_storage_dispatcher_binding()?;
        let run_id = self.output_run.ok_or(crate::Error::InvalidConfig(
            "executor output context has not assembled".into(),
        ))?;
        let record = self.storage.get_code_run_replay_record(&run_id)?.ok_or(
            crate::Error::CorruptedIndex("missing executor replay record"),
        )?;
        let request = gated.request().clone();
        if request.session_ref
            != crate::code_run::executor_compaction_session_id(self.gated_write.run_ref(), run_id)?
        {
            return Err(crate::Error::InvalidConfig(
                "compaction request names another session".into(),
            )
            .into());
        }
        let span = crate::code_run::ExecutorOutputSpan::from_replay(&record, &request)?;
        // The last committed step was not part of the preceding request's
        // history. Synchronize it BEFORE the mint, even across a soft yield.
        self.sync_output_context(&record)?;
        let plan = match &self.storage {
            ExecutorStorage::Canonical(vault) => driver.integrate_with_coverage(
                vault,
                byline,
                placement,
                gated,
                accumulated,
                &span,
            )?,
            // A room's run lands through its own handle, on the route it
            // captured at entry: the summary stays in the room's overlay and
            // drops with it at close, and a closed or flipped room refuses.
            // Docs Q17: a room already on record at entry lands its summary in
            // base under the room's saver instead.
            ExecutorStorage::Session(binding) => driver.integrate_in_session(
                &binding.session,
                &binding.route,
                byline,
                placement,
                gated,
                accumulated,
                &span,
            )?,
        };
        // This is only an in-memory cache; the next assembly re-derives it
        // from the typed row joined to the committed SUMMARY.
        let last = request
            .window
            .last()
            .expect("integrated window is nonempty")
            .turn;
        self.output_context.compact_span(request.turn_start, last);
        Ok(plan)
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
    /// that also binds [`EngineExecutorConfig::run_id`](crate::engine_executor::EngineExecutorConfig::run_id).
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
    /// constructor pair, so every dimension is checked: the session ref, the
    /// OWNING VAULT's identity, and the participant a session-bound run acts
    /// as. The vault check is what catches two vaults whose refs compare
    /// equal — `None == None` for a pair of canonical runs, or the same
    /// session ref entered in two different vaults.
    pub(super) fn verify_storage_dispatcher_binding(&self) -> EngineExecutorResult<()> {
        if self.storage.session_ref() != self.gated_write.session_ref()
            || self.storage.vault_id() != self.gated_write.vault_id()
            || self.storage.participant() != self.gated_write.participant()
        {
            return Err(Error::InvalidConfig(
                "executor storage/dispatcher binding mismatch".to_owned(),
            )
            .into());
        }
        Ok(())
    }
}
