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
    /// request stays pending, counts against the pass and goes behind the
    /// requests not asked since.
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
    /// attempt: pending requests never asked first, then the longest since a
    /// pass last asked them, then oldest, until `limit` of them reached a
    /// judge. `limit` is a pace: each request a judge saw goes behind the
    /// rest, so a later pass reaches every one. Each is checked by `checker`
    /// outside any vault transaction, marked asked and admitted on its own.
    pub fn run_coach_seal_checks(
        &self,
        attempt: &DreamerAdmittedAttempt,
        checker: &dyn SealChecker,
        limit: usize,
        now: u64,
    ) -> Result<SealCheckReport> {
        self.require_coach_attempt(attempt, COACH_SEAL_CHECKS_FACET)?;
        let mut pending = self.pending_seal_check_receipts()?;
        pending.sort_by_key(|check| {
            (
                check.last_asked_at,
                check.request.created_at,
                check.request.reference.clone(),
            )
        });
        let mut report = SealCheckReport::default();
        let mut asked = 0_usize;
        for request in pending.into_iter().map(|check| check.request) {
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
                    self.record_seal_check_asked(request.attempt, request.kind, now)?;
                    continue;
                }
                SealCheck::Unavailable => {
                    report.unavailable += 1;
                    continue;
                }
            };
            asked += 1;
            self.record_seal_check_asked(request.attempt, request.kind, now)?;
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

/// The owner wakes the existing Coach checker, without borrowing a Coach lease
/// or running a model in the HTTP handler. The host's normal admission, Grant
/// and budget remain the only way this job reaches `run_coach_seal_checks`.
pub fn queue_seal_checks_as_owner(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    now: u64,
) -> Result<crate::attempt_queue::AttemptId> {
    vault.with_write_txn_grouped(|txn| {
        super::validate_owner_in_txn(vault, txn, owner)?;
        let outcome = crate::dreamer_runner::DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
            txn,
            super::coach::COACH_HOST_QUEUE_KIND,
            crate::dreamer_runner::DreamerAttemptPayload {
                attempt_type: COACH_SEAL_CHECKS_FACET.into(),
                input: rmpv::Value::Nil,
                parent_attempt: None,
            },
            Some(COACH_SEAL_CHECKS_FACET.into()),
            None,
            now,
        )?;
        let (crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status)
        | crate::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        Ok(status.attempt.id)
    })
}
