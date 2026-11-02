//! What a pass's outcome leaves owed, and the debt of owed passes (FIX 8601).
//!
//! RULE: a pass that failed, failed before admission, panicked, or ran to
//! its end without admitting work (admitted == 0 + BudgetExhausted /
//! DeadlineHardCut) leaves the tick it consumed OWED, due again once that
//! tick's own capped restart backoff passes. A pass the host's pause stopped
//! leaves it owed at once; the loop's pause wait holds it until the pause
//! lifts. Only a pass that ran to a productive end settles its tick.
//! pass_index: only PreAdmissionFailed preserves it; every other arm
//! advances. Permanent failure = capped-backoff retry forever (the same
//! contract as HybridTick redelivery), and the debt outlives the source
//! running dry. An owed tick waits on its own clock, never the loop's: fresh
//! ticks and wave work keep their turns while it does.
use std::collections::VecDeque;
use std::time::Duration;

use oneiron::{WakePassReport, WakePassStop};
use tokio::time::Instant;

use super::config::{RestartBackoff, RestartBackoffConfig};
use super::run::WakeSupervisorReport;
use crate::tick::Tick;

pub(super) enum PassOutcome {
    Completed(WakePassReport),
    /// Pass ran (or at least crossed admission setup) and returned Err.
    /// The consumed tick is owed after backoff (same family as
    /// pre-admission failure / panic / zero-progress).
    Failed(oneiron::Error),
    /// Factory/`run_one_pass` setup failed before any attempt could be admitted.
    /// Owes the consumed tick after backoff and **keeps** `pass_index`
    /// (no durable budget row was written). Orthogonal to the debt: only this
    /// arm preserves the index; Failed/Panicked/Completed still advance.
    PreAdmissionFailed(oneiron::Error),
    /// Panic anywhere in the pass (including factory). Owed after backoff.
    Panicked,
    /// The host's pause stopped the pass (FIX 6909). Counted as completed,
    /// with no backoff; the consumed tick is owed at once and driven again
    /// once the pause lifts.
    Paused(WakePassReport),
}

/// True when a completed pass made no durable progress and would otherwise
/// hot-loop under HybridTick deadline redelivery (or leave PushTick work
/// stranded after a consumed wake). The consumed tick is owed after backoff.
fn zero_progress_should_backoff(pass: &WakePassReport) -> bool {
    pass.admitted == 0
        && matches!(
            pass.stop,
            WakePassStop::BudgetExhausted | WakePassStop::DeadlineHardCut
        )
}

/// One owed pass: the tick a pass consumed without settling it, when it may
/// run again, and that tick's own restart backoff.
pub(super) struct OwedPass {
    pub(super) tick: Tick,
    due: Instant,
    backoff: RestartBackoff,
}

/// What the debt makes of a tick fresh from the source.
pub(super) enum FreshTick {
    /// Run it: nothing owes it, or the owed pass that does is due.
    Run(OwedPass),
    /// An owed pass already holds this tick and falls due only at this
    /// instant. A redelivered deadline (a due HybridTick deadline re-surfaces
    /// on every read) rests its source's deadline lane until then; a push
    /// was consumed by its read (FIX 11403).
    Owed(Instant),
}

/// Every owed pass, oldest first, one per distinct tick: an equal tick
/// drives the same pass shape, so a second copy would only run it twice.
/// Process-local, as the consumed ticks themselves were.
pub(super) struct RetryDebt {
    owed: VecDeque<OwedPass>,
    backoff: RestartBackoffConfig,
}

impl RetryDebt {
    pub(super) fn new(backoff: RestartBackoffConfig) -> Self {
        Self {
            owed: VecDeque::new(),
            backoff,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.owed.is_empty()
    }

    /// Whether some owed pass is due at `now`.
    pub(super) fn ready(&self, now: Instant) -> bool {
        self.owed.iter().any(|owed| owed.due <= now)
    }

    /// The instant the next owed pass falls due.
    pub(super) fn next_due(&self) -> Option<Instant> {
        self.owed.iter().map(|owed| owed.due).min()
    }

    /// The oldest owed pass due at `now`, taken to run.
    pub(super) fn take_ready(&mut self, now: Instant) -> Option<OwedPass> {
        let index = self.owed.iter().position(|owed| owed.due <= now)?;
        self.owed.remove(index)
    }

    /// The pass `tick`, fresh from the source, drives: the owed pass that
    /// holds an equal tick once it is due, else a new one on a fresh backoff.
    pub(super) fn fresh(&mut self, tick: Tick, now: Instant) -> FreshTick {
        let Some(index) = self.owed.iter().position(|owed| owed.tick == tick) else {
            return FreshTick::Run(OwedPass {
                tick,
                due: now,
                backoff: RestartBackoff::new(self.backoff),
            });
        };
        let due = self.owed[index].due;
        if due > now {
            return FreshTick::Owed(due);
        }
        self.owed
            .remove(index)
            .map_or(FreshTick::Owed(due), FreshTick::Run)
    }

    /// Owes `owed` again once its own next backoff step has passed; returns
    /// that step.
    fn owe_after_backoff(&mut self, mut owed: OwedPass) -> Duration {
        let delay = owed.backoff.advance();
        owed.due = Instant::now() + delay;
        self.owe(owed);
        delay
    }

    /// Owes `owed` again at once, its backoff kept.
    pub(super) fn owe_now(&mut self, mut owed: OwedPass) {
        owed.due = Instant::now();
        self.owe(owed);
    }

    fn owe(&mut self, owed: OwedPass) {
        if let Some(held) = self.owed.iter_mut().find(|held| held.tick == owed.tick) {
            held.due = held.due.min(owed.due);
            return;
        }
        self.owed.push_back(owed);
    }
}

pub(super) struct PassAccounting<'a> {
    pub(super) report: &'a mut WakeSupervisorReport,
    pub(super) pass_index: &'a mut u64,
    pub(super) debt: &'a mut RetryDebt,
}

/// Tallies one pass and settles or owes the tick it consumed (module RULE).
pub(super) fn account_pass_outcome(
    outcome: PassOutcome,
    owed: OwedPass,
    accounting: PassAccounting<'_>,
) {
    let PassAccounting {
        report,
        pass_index,
        debt,
    } = accounting;
    match outcome {
        PassOutcome::Completed(pass) => {
            count_completed(report, pass_index, &pass);
            // Zero-progress BudgetExhausted / DeadlineHardCut
            // (admitted == 0): HybridTick re-surfaces the same due
            // deadline immediately; PushTick-only has already
            // consumed the wake. Owe it after backoff so we never
            // hot-loop empty refusals and never strand due work.
            // A productive pass settles its tick, and the next source
            // tick drains the rest.
            if zero_progress_should_backoff(&pass) {
                let delay = debt.owe_after_backoff(owed);
                tracing::warn!(
                    ?pass.stop,
                    ?delay,
                    "wake pass stopped without admitting work; its tick is owed after backoff"
                );
            }
        }
        PassOutcome::Failed(error) => {
            // In-pass failure may have admitted/parked some attempts;
            // the same consumed wake can still represent remaining
            // backlog → owed after backoff (idempotent for Hybrid).
            *pass_index = pass_index.saturating_add(1);
            report.passes_failed += 1;
            let delay = debt.owe_after_backoff(owed);
            tracing::error!(kind = ?error.kind(), ?delay, "wake pass failed; its tick is owed after backoff");
        }
        PassOutcome::PreAdmissionFailed(error) => {
            // No attempt row mutated and no durable budget row written —
            // keep pass_index; owed after backoff.
            report.passes_failed += 1;
            let delay = debt.owe_after_backoff(owed);
            tracing::error!(
                kind = ?error.kind(),
                ?delay,
                "wake pass failed before admission; its tick is owed after backoff"
            );
        }
        PassOutcome::Panicked => {
            // Setup panic before admission (or any uncontained panic):
            // owed after backoff so a PushTick-only host keeps work.
            *pass_index = pass_index.saturating_add(1);
            report.passes_panicked += 1;
            let delay = debt.owe_after_backoff(owed);
            tracing::error!(?delay, "wake pass panicked; its tick is owed after backoff");
        }
        PassOutcome::Paused(pass) => {
            // What the pause left (a Paused park, queued work, the timer
            // work after the wake) is the same tick's, owed at once and
            // driven again once the loop's wait for the pause is over.
            count_completed(report, pass_index, &pass);
            debt.owe_now(owed);
        }
    }
}

/// Tallies a pass that ran to its end, paused or not.
fn count_completed(report: &mut WakeSupervisorReport, pass_index: &mut u64, pass: &WakePassReport) {
    *pass_index = pass_index.saturating_add(1);
    report.passes_completed += 1;
    report.attempts_completed += u64::from(pass.completed);
    report.attempts_parked += u64::from(pass.parked);
    report.attempts_landed += u64::from(pass.landed);
}
