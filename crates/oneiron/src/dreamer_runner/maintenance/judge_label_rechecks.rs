//! The judge labels' re-check after a rubric edit, run (ARCH-0042 "A human
//! edits the rubric at any time. The edit re-pins the judge", "Labels that
//! conflict with the new rubric wait for re-grade", OF-420). The Coach's pass
//! re-pins the judge on its rubric's current text, then asks the host's
//! checker whether each pick the edit stamped pending still fits it. A fit
//! keeps the label and its pick time. A conflict or an unknown answer takes it
//! out of the anchor and asks its person to re-grade it. A check no model made
//! stays pending for a later night.
use super::coach::COACH_JUDGE_LABEL_RECHECKS_FACET;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::skill_optimize::{JudgeLabelChecker, JudgeLabelRecheckReport};
use crate::{Result, Vault};

impl Vault {
    /// The judge labels' re-check as the Coach, under a leased
    /// `coach.judge_label_rechecks` attempt: at most `limit` pending picks
    /// reach `checker`, each outside any vault transaction and settled on its
    /// own.
    ///
    /// # Errors
    ///
    /// An attempt that is not the Coach's re-check job; storage errors and
    /// whatever the checker returns.
    pub fn run_coach_judge_label_rechecks(
        &self,
        attempt: &DreamerAdmittedAttempt,
        checker: &dyn JudgeLabelChecker,
        limit: usize,
        now: u64,
    ) -> Result<JudgeLabelRecheckReport> {
        self.require_coach_attempt(attempt, COACH_JUDGE_LABEL_RECHECKS_FACET)?;
        crate::skill_optimize::recheck_judge_labels(self, checker, limit, now)
    }
}
