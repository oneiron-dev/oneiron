//! What a host reads and binds on a run's own route as it enters the run
//! (FIX 2594, FIX 7507): the seat its model calls are bound to, and the
//! first start its clock was frozen at. A session-bound run's are its
//! room's, never base's, and the run's storage stays behind its dispatcher.

use std::time::Instant;

use super::HostSelfDispatcher;
use crate::code_run::CodeRunDeterminism;
use crate::llm::seat::{ModelSeat, SeatChoiceReceipt, SeatDecisions, SeatTask};
use crate::{EntityId, Error, Result, Vault};

impl HostSelfDispatcher<'_> {
    /// Binds this dispatcher to `run`, the run its host enters through it:
    /// the run whose own seat and first start the host reads here. A reader
    /// child's dispatcher is bound to its job's run as it binds the job.
    #[must_use]
    pub fn with_bound_run(mut self, run: EntityId) -> Self {
        self.bound_run = Some(run);
        self
    }

    /// The determinism `run`'s own record froze at its first start, read on
    /// this dispatcher's route; `None` for a run with no record yet.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `run` is not the run this dispatcher is
    /// bound to; the route's own read errors.
    pub fn recorded_determinism(&self, run: EntityId) -> Result<Option<CodeRunDeterminism>> {
        self.require_bound_run(run)?;
        Ok(self
            .storage
            .get_code_run_replay_record(&run)?
            .map(|record| record.determinism))
    }

    /// The receipt of the seat `run`'s model calls are bound to, read on
    /// this dispatcher's route; `None` while no seat is born for it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `run` is not the run this dispatcher is
    /// bound to; the route's own read errors.
    pub fn model_seat_receipt(&self, run: EntityId) -> Result<Option<SeatChoiceReceipt>> {
        self.require_bound_run(run)?;
        self.storage.model_seat_receipt(run)
    }

    /// Births `run`'s model seat, or loads the one it was born on, on this
    /// dispatcher's route: a session-bound run's pin is its room's alone.
    /// `vault`, the vault the route is on, lends the model catalog, manifest
    /// and seat pool. `parent_at`, the cutoff of the parent a child is born
    /// under, bounds a fresh pick (FIX 8230).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when `run` is not the run this dispatcher is
    /// bound to or `vault` is not the route's; the seat birth's own errors.
    pub fn birth_model_seat(
        &self,
        vault: &Vault,
        run: EntityId,
        task: &SeatTask,
        decisions: &SeatDecisions,
        parent_at: Option<Instant>,
    ) -> Result<ModelSeat> {
        self.require_bound_run(run)?;
        vault.birth_model_seat_on(&self.storage, run, task, decisions, parent_at)
    }

    fn require_bound_run(&self, run: EntityId) -> Result<()> {
        if self.bound_run == Some(run) {
            return Ok(());
        }
        Err(Error::InvalidConfig(
            "run is not the one its dispatcher is bound to".to_owned(),
        ))
    }
}
