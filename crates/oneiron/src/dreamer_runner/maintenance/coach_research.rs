//! The Coach's autoresearch jobs (OF-351, FIX 886, FIX 1331), both on the
//! host lane: execution advances a campaign's host continuations as its runs
//! finish, and selection runs one round for each due campaign, told by the
//! host's judge whether that campaign's goal is verified met.
use super::super::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use super::coach::{COACH_HOST_QUEUE_KIND, COACH_RESEARCH_RUN_FACET, COACH_RESEARCH_SELECT_FACET};
use crate::autoreason_campaign::research::{self, ResearchGoalBasis};
use crate::autoreason_campaign::selection::OracleSignal;
use crate::{AttemptId, Result, Vault};
use rmpv::Value;

/// What a host verified about one due campaign's goal (FIX 1331). GoalMet
/// only when its judge decided every axis the goal states is met on the
/// incumbent; every other case, a campaign with no target included, is
/// NoSignal. It invents no target and no threshold of its own.
pub trait ResearchGoalOracle {
    /// The signal for the campaign `basis` reads.
    ///
    /// # Errors
    ///
    /// The host's own read errors; the round then runs with no signal.
    fn signal(&self, basis: &ResearchGoalBasis) -> Result<OracleSignal>;
}

impl DreamerRunnerStore<'_> {
    /// Queues the host's research job, keyed as the nightly host jobs are: an
    /// unleased one absorbs the next request.
    ///
    /// # Errors
    ///
    /// Storage errors; the queue's own enqueue errors.
    pub fn enqueue_coach_research_run(&self, now: u64) -> Result<()> {
        self.vault.with_write_txn_grouped(|txn| {
            self.enqueue_kind_in_txn(
                txn,
                COACH_HOST_QUEUE_KIND,
                DreamerAttemptPayload {
                    attempt_type: COACH_RESEARCH_RUN_FACET.into(),
                    input: Value::Nil,
                    parent_attempt: None,
                },
                Some(COACH_RESEARCH_RUN_FACET.into()),
                None,
                now,
            )?;
            Ok(())
        })
    }
}

impl Vault {
    /// Advances the autoresearch host continuations as the Coach, under a
    /// leased `coach.research_run` attempt. Selection stays the nightly
    /// `coach.research_select` job's.
    pub fn run_coach_research(&self, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
        self.require_coach_attempt(attempt, COACH_RESEARCH_RUN_FACET)?;
        crate::autoreason_campaign::research::advance_research_continuations(
            self,
            attempt.status.attempt.id,
            now,
        )
    }

    /// The autoresearch tick as the Coach, under a leased
    /// `coach.research_select` attempt: one selection round for each bound
    /// campaign the loop's own record says is due, each with what `oracle`
    /// verified about its goal. The round reads the campaign's lease and
    /// pauses, never fails, on an empty budget. A campaign whose round errs
    /// is left for the next night; the others still run.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt, or storage errors
    /// reading the campaigns.
    pub fn run_coach_research_select(
        &self,
        attempt: &DreamerAdmittedAttempt,
        oracle: &dyn ResearchGoalOracle,
        now: u64,
    ) -> Result<()> {
        self.require_coach_attempt(attempt, COACH_RESEARCH_SELECT_FACET)?;
        for root in research::bound_research_roots(self)? {
            if !research::research_round_due(self, root)? {
                continue;
            }
            let signal = goal_signal(self, root, oracle).unwrap_or_else(|error| {
                tracing::warn!(kind = ?error.kind(), "the research goal oracle gave no signal");
                OracleSignal::NoSignal
            });
            if let Err(error) = research::select_next(self, root, signal, now) {
                tracing::warn!(kind = ?error.kind(), "autoresearch round did not run");
            }
        }
        Ok(())
    }
}

/// What `oracle` verified about `root`'s goal. The judge's calls take time,
/// so a GoalMet stands only while the basis it judged still does: a goal
/// that moved, a new incumbent or new receipts make it NoSignal.
fn goal_signal(
    vault: &Vault,
    root: AttemptId,
    oracle: &dyn ResearchGoalOracle,
) -> Result<OracleSignal> {
    let Some(basis) = research::research_goal_basis(vault, root)? else {
        return Ok(OracleSignal::NoSignal);
    };
    if oracle.signal(&basis)? != OracleSignal::GoalMet {
        return Ok(OracleSignal::NoSignal);
    }
    Ok(
        if research::research_goal_basis(vault, root)?.as_ref() == Some(&basis) {
            OracleSignal::GoalMet
        } else {
            OracleSignal::NoSignal
        },
    )
}
