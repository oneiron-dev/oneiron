//! The seal's checks, run (ARCH-0079 #stuck-confession-and-the-seal, OF-544,
//! OF-420): "A confession triggers a re-check. The flaw it names is examined
//! directly", and a drawn random audit examines every objective of a passing
//! attempt. `coach.honesty_audits` only draws; this Coach job drains the
//! durable check requests through the host's independent checker and admits
//! each finding through [`Vault::record_seal_check_outcome`], which projects
//! it. The agent's own report never becomes a finding: a check the checker
//! cannot make stays pending for a later night.
use super::coach::COACH_SEAL_CHECKS_FACET;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::self_heal::audit::{SealCheckOutcome, SealCheckRequest};
use crate::{Error, Result, Vault};

/// What the host's checker made of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealCheck {
    /// One finding per requested objective, by a judge that did not produce
    /// the result.
    Checked(SealCheckOutcome),
    /// A judge was asked and its answer did not examine each objective; the
    /// request stays pending and counts against the pass.
    Inconclusive,
    /// Nothing to ask now: no independent judge, or no readable result. The
    /// request stays pending and costs the pass nothing.
    Unavailable,
}

/// What the host lends the Coach: an independent check of one request.
pub trait SealChecker {
    /// The check of `request` on its pinned result, by a judge that is not
    /// `executor`, the model that produced the result.
    ///
    /// # Errors
    ///
    /// Host-defined.
    fn check(&self, request: &SealCheckRequest, executor: &str, now: u64) -> Result<SealCheck>;
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SealCheckReport {
    /// Checks admitted with their findings.
    pub checked: u32,
    /// Checks a judge answered without settling; they stay pending.
    pub inconclusive: u32,
    /// Checks with no independent judge or readable result yet.
    pub unavailable: u32,
    /// Checks whose findings the seal refused (outside the request, or
    /// contradicting an earlier finding); they stay pending.
    pub refused: u32,
}

impl Vault {
    /// The seal's checks as the Coach, under a leased `coach.seal_checks`
    /// attempt: pending requests oldest first, until `limit` of them reached
    /// a judge. Each is checked by `checker` outside any vault transaction
    /// and admitted on its own.
    pub fn run_coach_seal_checks(
        &self,
        attempt: &DreamerAdmittedAttempt,
        checker: &dyn SealChecker,
        limit: usize,
        now: u64,
    ) -> Result<SealCheckReport> {
        self.require_coach_attempt(attempt, COACH_SEAL_CHECKS_FACET)?;
        let mut requests = self.pending_seal_checks()?;
        requests.sort_by_key(|request| (request.created_at, request.reference.clone()));
        let mut report = SealCheckReport::default();
        let mut asked = 0_usize;
        for request in requests {
            if asked >= limit {
                break;
            }
            let Some(sealed) = self.sealed_attempt_receipt(request.attempt)? else {
                continue;
            };
            let outcome = match checker.check(&request, &sealed.executor, now)? {
                SealCheck::Checked(outcome) => outcome,
                SealCheck::Inconclusive => {
                    asked += 1;
                    report.inconclusive += 1;
                    continue;
                }
                SealCheck::Unavailable => {
                    report.unavailable += 1;
                    continue;
                }
            };
            asked += 1;
            match self.record_seal_check_outcome(request.attempt, request.kind, &outcome, now) {
                Ok(_) => report.checked += 1,
                Err(Error::InvalidClaimBody(reason)) => {
                    tracing::warn!(
                        reason,
                        reference = %request.reference,
                        "the seal refused a check's findings"
                    );
                    report.refused += 1;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(report)
    }
}
