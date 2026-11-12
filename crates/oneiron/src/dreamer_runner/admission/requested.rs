//! Admission of one requested attempt (`vault.evals.authoring.execute`): a
//! request that queued its own attempt runs that attempt, never the next
//! other one of its kind. The candidate tail is the ordinary one (budget
//! line, reserve, lease and started claim), in the caller's writer.
use super::*;

impl DreamerRunnerStore<'_> {
    /// Admits the queued attempt `id` of the plain kind `queue_kind` in
    /// `wtxn`, through the ordinary admission tail; `Empty` when that
    /// attempt is not ready for this worker. The caller notifies attempt
    /// observers once its writer commits.
    ///
    /// # Errors
    ///
    /// A macro or turn-program kind, whose scans pick by their own order;
    /// an invalid admission input; the queue's own admission errors.
    pub(crate) fn admit_requested_attempt_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        queue_kind: &str,
        id: AttemptId,
        input: AdmitDreamerAttempt,
    ) -> Result<DreamerAdmissionOutcome> {
        if queue_kind == DreamerConsolidationScope::Macro.attempt_kind()
            || queue_kind == DREAMER_TURN_PROGRAM_ATTEMPT_KIND
        {
            return Err(invalid_dreamer_runner(
                "a requested attempt is admitted only from a plain kind",
            ));
        }
        validate_admission_input(&input)?;
        Ok(self
            .admit_kind_in_txn(wtxn, queue_kind, input, None, Some(id))?
            .outcome)
    }
}
