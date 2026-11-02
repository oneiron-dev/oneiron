//! Where a check that lands after its step keeps its result (FIX 10389):
//! its run's own route, the vault's rows or the route a session-bound run
//! captured in the stretch instance it was bound to, and never another. A
//! stretch's collection stays in its row as the check found it: no late body
//! is written into a stretch, whose close may already have taken its body
//! directory. A result that cannot be kept leaves the typed fact that it was
//! not kept in its pending row's place, never a check pending for good.

use super::{CheckJob, Service, keep_collection};
use crate::code_run::{
    CodeRunRawOutput, ExecutorStorage, ProgramStepFeedback, ProgramStepIdentity,
    StoredStepFeedback, TYPE_FEEDBACK_NOT_KEPT, TypeDiagnostics,
};

impl Service {
    /// Whether `job`'s check still has a route to keep its result on: false
    /// once the stretch its run was bound to has closed.
    pub(super) fn still_kept(&self, job: &CheckJob) -> bool {
        self.vault
            .as_deref()
            .is_none_or(|vault| job.route.live_on(vault))
    }

    /// `diagnostics` placed as the check keeps them: a collection past one
    /// reply in a body of the run when its rows are this service's vault's
    /// own, else as they are, for the step to place. Whether it is placed.
    pub(super) fn placed(
        &self,
        job: &CheckJob,
        diagnostics: TypeDiagnostics,
    ) -> (TypeDiagnostics, Option<CodeRunRawOutput>, bool) {
        let canonical = self
            .vault
            .as_deref()
            .and_then(|vault| job.route.canonical_on(vault));
        match canonical {
            Some(vault) => {
                let storage = ExecutorStorage::Canonical(vault);
                let (diagnostics, body) =
                    keep_collection(&storage, job.key, job.source.as_ref(), diagnostics);
                (diagnostics, body, true)
            }
            None => (diagnostics, None, false),
        }
    }

    /// Whether a landed check of `job` writes its own row.
    pub(super) fn publishes(&self, job: &CheckJob) -> bool {
        self.vault
            .as_deref()
            .is_some_and(|vault| job.route.reaches(vault))
    }

    /// Writes `row`, the landed check, on its run's own route. A row that
    /// cannot be written leaves the typed fact that it was not kept; a
    /// stretch that has closed keeps nothing.
    pub(super) fn publish(&self, job: &CheckJob, row: &StoredStepFeedback) {
        let Some(vault) = self.vault.as_deref() else {
            return;
        };
        job.route.on(vault, &mut |storage: &ExecutorStorage<'_>| {
            let Err(error) = storage.put_type_diagnostics(job.key, row) else {
                return;
            };
            tracing::warn!(target: "oneiron::code_check", %error, "late type feedback not kept");
            if let Err(error) = storage.put_type_diagnostics(job.key, &not_kept_row(job, &error)) {
                tracing::warn!(
                    target: "oneiron::code_check",
                    %error,
                    "late type feedback left pending"
                );
            }
        });
    }
}

/// The row stating that `job`'s landed check could not be kept, for
/// `error`: in the place of its pending row.
fn not_kept_row(job: &CheckJob, error: &crate::Error) -> StoredStepFeedback {
    let (run, seq, invocation) = job.key;
    let feedback = ProgramStepFeedback::new(
        ProgramStepIdentity::of(run, seq, invocation),
        job.note.clone(),
        TypeDiagnostics::unavailable(TYPE_FEEDBACK_NOT_KEPT, Some(error.to_string())),
    );
    StoredStepFeedback::of(job.actor, &feedback, None)
}
