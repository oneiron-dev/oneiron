//! The Coach's contribution checks (ARCH-0037 #lineage-credit, ARCH-0053):
//! each sampled credited run's skill measured on matched forks. The host's
//! replay capsule regenerates the run's step from its captured pre-use
//! context with and without the skill and scores both forks against the
//! run's anchor; this recipe records each finished pair as the run's check
//! ([`crate::skill_attribution::record_contribution_pair`]). A run the host
//! cannot replay stays unchecked, and the next pass reads it again. A check
//! is never inferred from a load, a citation or a success.
use std::time::{Duration, Instant};

use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerParkCause};
use crate::dreamer_wake::{DreamerAttemptExecution, WakeAttemptContext};
use crate::retrieval_depth::RetrievalDeadline;
use crate::skill_attribution::{
    ContributionCandidate, ContributionFork, ContributionPair, contribution_check_candidates,
    record_contribution_pair,
};
use crate::{Result, Vault};

/// Pairs one pass runs. Each is two regenerated steps and their scoring,
/// which the host meters.
const PAIRS_PER_PASS: usize = 4;
/// Candidates one pass reads. A run the host cannot replay is passed over,
/// so the window reaches past the runs captured before the capsule was.
const CANDIDATES_PER_PASS: usize = 64;

/// Both forks of one candidate's matched pair, each scored against the
/// candidate's anchor on its axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionForks {
    pub with_skill: ContributionFork,
    pub without_skill: ContributionFork,
}

/// The host's replay capsule, lent to the Coach for one pass.
pub trait ContributionReplayHost {
    /// Regenerates the candidate run's step from its captured pre-use
    /// context, once with the candidate's skill and once without, on the
    /// run's pinned executor, input snapshot, clock, seed and budget, with
    /// side effects replayed, never re-sent. Both forks are scored against
    /// the candidate's anchor on its axis, and model calls stop by `clock`.
    /// `None` when the run has no captured context or the forks are not
    /// comparable; never a guessed result.
    ///
    /// # Errors
    ///
    /// A failed fork or scoring call.
    fn run_pair(
        &self,
        vault: &Vault,
        candidate: &ContributionCandidate,
        clock: &RetrievalDeadline,
    ) -> Result<Option<ContributionForks>>;
}

/// Called only after normal admission and inside the driver's panic boundary.
pub(super) fn execute(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
    host: Option<&(dyn ContributionReplayHost + Send + Sync)>,
) -> Result<DreamerAttemptExecution> {
    // No capsule on this host: nothing is measured and nothing is recorded.
    let Some(host) = host else {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    };
    if ctx.deadline.in_finalize_window() {
        return Ok(DreamerAttemptExecution::Park {
            reason: "Coach contribution checks deadline".into(),
            cause: DreamerParkCause::Checkpoint,
        });
    }
    let candidates = contribution_check_candidates(ctx.vault, CANDIDATES_PER_PASS)?;
    if candidates.is_empty() {
        return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
    }
    // The forks' model calls block on the host's runtime, which a thread
    // already driving the wake pass cannot enter: the pairs run on their own
    // thread, and the pass waits for it, on the time the pass has left.
    let clock = RetrievalDeadline::hard(
        Instant::now(),
        Duration::from_millis(ctx.deadline.remaining_ms()),
    );
    let (vault, now) = (ctx.vault, ctx.now_ms / 1000);
    let spent = std::thread::scope(|scope| {
        scope
            .spawn(|| measure(vault, host, &candidates, &clock, now))
            .join()
    })
    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    Ok(DreamerAttemptExecution::Completed {
        // The host meters fork calls separately. The wake counter charges
        // its admitted reservation, never reports paid maintenance as free.
        completed_units: if spent {
            attempt.reservation.reserved_units
        } else {
            0
        },
    })
}

/// Runs up to [`PAIRS_PER_PASS`] pairs and records each finished one,
/// a tie or a loss as much as a win. Whether any fork ran.
fn measure(
    vault: &Vault,
    host: &(dyn ContributionReplayHost + Send + Sync),
    candidates: &[ContributionCandidate],
    clock: &RetrievalDeadline,
    now: u64,
) -> bool {
    let mut tried = 0;
    for candidate in candidates {
        if tried >= PAIRS_PER_PASS || !clock.decision_may_start() {
            break;
        }
        let forks = match host.run_pair(vault, candidate, clock) {
            Ok(Some(forks)) => forks,
            Ok(None) => continue,
            Err(error) => {
                tried += 1;
                tracing::warn!(kind = ?error.kind(), "contribution forks did not run");
                continue;
            }
        };
        tried += 1;
        let pair = ContributionPair {
            attempt_receipt: candidate.attempt_receipt.clone(),
            skill: candidate.skill,
            axis: candidate.axis.clone(),
            anchor: candidate.anchor,
            with_skill: forks.with_skill,
            without_skill: forks.without_skill,
            at: now,
        };
        if let Err(error) = record_contribution_pair(vault, &pair, now) {
            tracing::warn!(kind = ?error.kind(), "contribution check was not recorded");
        }
    }
    tried > 0
}
