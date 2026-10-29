//! A run's type feedback rows on its own route (FIX 10389, CALLS "session
//! feedback lives on the session route only"): the vault's own rows for a
//! canonical run; for a session-bound run, the route it captured at entry,
//! in the stretch instance it was bound to, and no other. A stretch on
//! record keeps them in base, as it keeps its bodies, and its close leaves
//! them there; an off-record stretch keeps them in its overlay, and they go
//! with it. No row of a session-bound run is copied to base, and none is
//! read from base when its stretch is gone. A run with no result store of
//! its own (a foreign program, a pack script) keeps its whole collection in
//! its row on the vault's rows; a shadow arm keeps its feedback under its
//! lease alone, in no row.

use super::super::type_diagnostics::{
    StepKey, StoredStepFeedback, put_in, row_in, rows_in, runs_program_steps_in_txn,
};
use super::*;
use crate::code_run::ProgramStepFeedback;
use crate::side_table::RoutedDbs;

/// The stretch instance a session-bound run was bound to, bound again for
/// one late call on a vault ([`OffRecordSession::instance_bind`]): the call
/// runs only while that instance lives.
pub(crate) type SessionInstanceBind =
    Box<dyn Fn(&Vault, &mut dyn FnMut(OffRecordSession<'_>)) + Send + Sync>;

/// Whether a shadow arm's lease still holds the arm (FIX 10389, fork d).
pub(crate) type ArmLiveness = std::sync::Arc<dyn Fn() -> bool + Send + Sync>;

/// Where a check that lands after its step keeps its result (FIX 10389):
/// owned by the check, never borrowing its run, so the run never waits on
/// it and it never extends the run's stretch.
pub(crate) enum FeedbackRoute {
    /// The vault with this id's own rows.
    Canonical(VaultId),
    /// The vault with this id's own rows, for a run with no result store of
    /// its own (a foreign program, a pack script): its whole collection
    /// stays in its row, read by its `check_ref`, never in a body no reader
    /// of the run reaches.
    RowsOnly(VaultId),
    /// The route a session-bound run captured, in the instance it was bound
    /// to.
    Session(SessionFeedbackRoute),
    /// A shadow arm's own feedback (fork d): no row anywhere, read under the
    /// arm's lease alone; its check runs only while the lease holds the arm.
    Arm(ArmLiveness),
    /// A stretch that records nothing: its feedback rides with its run
    /// alone.
    NotKept,
}

/// The route a session-bound run captured at entry, the shell its turns
/// ride and the instance it was bound to.
pub(crate) struct SessionFeedbackRoute {
    bind: SessionInstanceBind,
    route: SessionWriteRoute,
    container: EntityId,
}

impl FeedbackRoute {
    /// `vault`, when this route is its own rows.
    pub(crate) fn canonical_on<'v>(&self, vault: &'v Vault) -> Option<&'v Vault> {
        match self {
            Self::Canonical(id) if *id == vault.vault_id() => Some(vault),
            Self::Canonical(_)
            | Self::RowsOnly(_)
            | Self::Session(_)
            | Self::Arm(_)
            | Self::NotKept => None,
        }
    }

    /// Whether a check may keep its own result on `vault` by this route.
    pub(crate) fn reaches(&self, vault: &Vault) -> bool {
        match self {
            Self::Canonical(id) | Self::RowsOnly(id) => *id == vault.vault_id(),
            Self::Session(_) => true,
            Self::Arm(_) | Self::NotKept => false,
        }
    }

    /// Whether a collection past one reply goes to a body of the run: on a
    /// route whose run reads its results back. A run with no result store,
    /// and an arm, keep theirs whole where their feedback is.
    pub(crate) fn keeps_bodies(&self) -> bool {
        !matches!(self, Self::RowsOnly(_) | Self::Arm(_))
    }

    /// Whether the stretch or the arm this route names still lives on
    /// `vault`; a canonical route, and one that keeps nothing, always do.
    pub(crate) fn live_on(&self, vault: &Vault) -> bool {
        let session = match self {
            Self::Session(session) => session,
            Self::Arm(live) => return (**live)(),
            Self::Canonical(_) | Self::RowsOnly(_) | Self::NotKept => return true,
        };
        let mut live = false;
        (session.bind)(vault, &mut |_: OffRecordSession<'_>| live = true);
        live
    }

    /// Runs `publish` on this route's storage on `vault`: the vault's own,
    /// or the run's captured route in its stretch while that instance
    /// lives. It does not run for another vault, or once the stretch has
    /// closed.
    pub(crate) fn on(&self, vault: &Vault, publish: &mut dyn FnMut(&ExecutorStorage<'_>)) {
        match self {
            Self::Canonical(id) | Self::RowsOnly(id) if *id == vault.vault_id() => {
                publish(&ExecutorStorage::Canonical(vault));
            }
            Self::Canonical(_) | Self::RowsOnly(_) | Self::Arm(_) | Self::NotKept => {}
            Self::Session(session) => {
                (session.bind)(vault, &mut |bound: OffRecordSession<'_>| {
                    publish(&ExecutorStorage::Session(SessionBinding {
                        session: bound,
                        route: session.route.clone(),
                        container: session.container,
                    }));
                });
            }
        }
    }
}

impl ExecutorStorage<'_> {
    /// Where this run's late type feedback lands: its own route.
    pub(crate) fn feedback_route(&self) -> FeedbackRoute {
        match self {
            Self::Canonical(vault) => FeedbackRoute::Canonical(vault.vault_id()),
            Self::Session(binding) if binding.route.target() == RouteTarget::Discard => {
                FeedbackRoute::NotKept
            }
            Self::Session(binding) => FeedbackRoute::Session(SessionFeedbackRoute {
                bind: binding.session.instance_bind(),
                route: binding.route.clone(),
                container: binding.container,
            }),
        }
    }

    /// Runs `read` over the run's feedback rows in one snapshot: the
    /// vault's own, or the composed view of the stretch the run is bound
    /// to, checked as each of its reads is.
    fn read_feedback<T>(
        &self,
        read: impl FnOnce(&RoutedDbs<'_>, &heed::RoTxn<'_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let rtxn = vault.store.env.read_txn()?;
                read(&RoutedDbs::Base(*vault), &rtxn)
            }
            Self::Session(binding) => binding.answered(|| {
                binding
                    .session
                    .routed_side_read(|rtxn, dbs| read(&dbs, rtxn))
            }),
        }
    }

    /// One step's feedback row on the run's route.
    ///
    /// # Errors
    ///
    /// Storage errors, a row that does not decode, and a run no longer in
    /// its room.
    pub(crate) fn type_diagnostics_row(&self, key: StepKey) -> Result<Option<StoredStepFeedback>> {
        self.read_feedback(|dbs, rtxn| row_in(dbs, rtxn, key))
    }

    /// Every step feedback row of `run` on the run's route, in step order.
    ///
    /// # Errors
    ///
    /// Storage errors, a row that does not decode, and a run no longer in
    /// its room.
    pub(crate) fn type_diagnostics_rows(
        &self,
        run: EntityId,
    ) -> Result<Vec<(StepKey, StoredStepFeedback)>> {
        self.read_feedback(|dbs, rtxn| rows_in(dbs, rtxn, run))
    }

    /// The program steps' type feedback of each of `runs` on this route, as
    /// it stands: a wait's settled children's. A read that fails gives none.
    pub(crate) fn runs_program_steps(&self, runs: &[EntityId]) -> Vec<ProgramStepFeedback> {
        self.read_feedback(|dbs, rtxn| Ok(runs_program_steps_in_txn(dbs, rtxn, runs)))
            .unwrap_or_default()
    }

    /// Writes a step's feedback on the run's route: a pending row never
    /// takes the place of a check that has already landed. A stretch that
    /// records nothing keeps none.
    ///
    /// # Errors
    ///
    /// Storage errors; the side-row wall's refusal; a stale route or a run
    /// no longer in its room.
    pub(crate) fn put_type_diagnostics(
        &self,
        key: StepKey,
        row: &StoredStepFeedback,
    ) -> Result<()> {
        match self {
            Self::Canonical(vault) => vault.put_type_diagnostics(key, row),
            Self::Session(binding) if binding.route.target() == RouteTarget::Discard => Ok(()),
            Self::Session(binding) => binding.answered(|| {
                binding
                    .session
                    .routed_side_txn(&binding.route, |wtxn, read, write| {
                        put_in(&read, &write, wtxn, key, row)
                    })
            }),
        }
    }
}
