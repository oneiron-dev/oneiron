//! The attribution judge's held-out audits, run (ARCH-0053 "The attribution
//! judge gets a defect-injection audit", ARCH-0056, OF-542): both built-in
//! fixture sets, the attempt cases and the amendment cases, put through the
//! host's decision ladder under the Coach's leased job. Each audit keeps its
//! cases' model answers beside its report, and the
//! `attribution_unclear_floor` they argue for is one held-out check, so the
//! floor is fitted on the judge the host actually runs.
use super::coach::COACH_ATTRIBUTION_AUDITS_FACET;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::edit_distance::attribution::{
    held_out_amendment_fixtures, run_judge_audit_with_decisions,
};
use crate::skill_attribution::{
    AttributionAuditReport, AttributionDecisions, held_out_audit_fixtures,
    run_attribution_audit_with_decisions,
};
use crate::{Result, Vault};

/// What one audit job measured, one report per fixture set.
#[derive(Debug, Clone, PartialEq)]
pub struct CoachAttributionAudits {
    pub attempts: AttributionAuditReport,
    pub amendments: AttributionAuditReport,
}

impl Vault {
    /// The attribution judge's held-out audits as the Coach, under a leased
    /// `coach.attribution_audits` attempt: the attempt cases, then the
    /// amendment cases, each through `decisions` and each kept as its own
    /// audit row with its floor check. A later failure leaves an earlier
    /// audit's row in place.
    ///
    /// # Errors
    ///
    /// An attempt that is not the Coach's audit job; storage errors and
    /// whatever the decision path returns.
    pub fn run_coach_attribution_audits(
        &self,
        attempt: &DreamerAdmittedAttempt,
        decisions: &AttributionDecisions<'_>,
        now: u64,
    ) -> Result<CoachAttributionAudits> {
        self.require_coach_attempt(attempt, COACH_ATTRIBUTION_AUDITS_FACET)?;
        let attempts = run_attribution_audit_with_decisions(
            self,
            &held_out_audit_fixtures(),
            Some(decisions),
            now,
        )?;
        let amendments = run_judge_audit_with_decisions(
            self,
            &held_out_amendment_fixtures(),
            Some(decisions),
            now,
        )?;
        Ok(CoachAttributionAudits {
            attempts,
            amendments,
        })
    }
}
