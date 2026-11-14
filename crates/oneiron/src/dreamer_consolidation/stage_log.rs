//! The one line a consolidation partition attempt logs when it ends (L07
//! DREAM-OBSERVE): the wall ms of each stage, the claims its write landed
//! and refused, and the Loro SnapshotAt exports this process made while it
//! ran (a recall beside it counts too). Ids, counts, ms and enum names
//! only: logs never carry world text.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerConsolidationScope};
use crate::dreamer_wake::DreamerAttemptExecution;
use crate::entity_id::bytes_to_hex_lower;
use crate::{EntityId, Result};

pub(crate) use crate::store::writer_hold::{WriterHold, ms_since};

/// Whole ms from `from` to `to`; 0 when `to` is not later.
fn ms_between(from: Instant, to: Instant) -> u64 {
    u64::try_from(to.saturating_duration_since(from).as_millis()).unwrap_or(u64::MAX)
}

/// The wall ms of one partition attempt's stages. A stage the attempt never
/// reached stays 0.
pub(crate) struct PartitionStages {
    started: Instant,
    exports_at_start: u64,
    /// The wake's frozen preparation, shared by every partition it prepared.
    /// It ran before this attempt, so `total_ms` leaves it out.
    prep_ms: u64,
    /// Opening the branch's resources at the wake's pin.
    pub(super) branch_ms: u64,
    /// The model run less the stages below: slices, the extraction fan-out
    /// and its reply checks, people bind and mint, and a thing's scoped
    /// agent pass. A residual, not a model wait: `call_ms`,
    /// `prefix_ready_ms`, `finish_start_ms` and `finish_ms` split it
    /// (FIX 21929) and sum to it.
    extract_ms: u64,
    /// The model run's start to its own extraction prefix's end: cutting
    /// the slices and the extraction calls, side by side.
    call_ms: u64,
    /// The own prefix's end to the end of the window's side-by-side phase
    /// (its last prefix or rung job): the wait at the window's prefix
    /// barrier. 0 outside a window, and for a window slot whose finish
    /// starts at its own prefix's end (FIX 21927).
    prefix_ready_ms: u64,
    /// The window's last prefix to this slot's finish start: the wait
    /// behind the earlier slots' serial finishes. 0 outside a window, and
    /// for a slot whose finish starts at its own prefix's end.
    finish_start_ms: u64,
    /// The finish less the stages below: reply checks, people bind and
    /// mint, candidate build, and a re-run prefix when an earlier finish
    /// changed the admitted priors.
    finish_ms: u64,
    /// When this attempt's own extraction prefix ended (the first mark
    /// stands: a finish that re-runs the prefix does not move it).
    prefix_ended: Option<Instant>,
    /// When the window's side-by-side phase (its last prefix or rung job)
    /// ended; for a slot whose finish starts at its own prefix's end, that
    /// end (FIX 21927). Its model run then closes at its finish's end, so
    /// its wait for its settle's turn stays out of `extract_ms`.
    window_prefixes_ended: Option<Instant>,
    /// When this slot's finish started.
    finish_started: Option<Instant>,
    /// The correction read over every child's candidates.
    pub(super) corrections_ms: u64,
    /// Assembly and conflict resolution, the gap upsert left out.
    pub(super) resolve_ms: u64,
    /// The gap-queue upsert of escalated contradictions.
    pub(super) gap_ms: u64,
    /// Sealing the write, the checker's turn and the promotion commit.
    pub(super) commit_ms: u64,
    landing: LandingTally,
}

impl PartitionStages {
    /// Starts the clock and the export count of an attempt whose wake took
    /// `prep_ms` to prepare.
    pub(crate) fn start(prep_ms: u64) -> Self {
        Self {
            started: Instant::now(),
            exports_at_start: loro::snapshot_at_exports(),
            prep_ms,
            branch_ms: 0,
            extract_ms: 0,
            call_ms: 0,
            prefix_ready_ms: 0,
            finish_start_ms: 0,
            finish_ms: 0,
            prefix_ended: None,
            window_prefixes_ended: None,
            finish_started: None,
            corrections_ms: 0,
            resolve_ms: 0,
            gap_ms: 0,
            commit_ms: 0,
            landing: LandingTally::default(),
        }
    }

    /// Where the promotion door tells this attempt what its write did.
    pub(super) fn landing(&self) -> &LandingTally {
        &self.landing
    }

    /// Marks the end of this attempt's own extraction prefix at `at`. The
    /// first mark stands.
    pub(crate) fn mark_prefix_ended(&mut self, at: Instant) {
        self.prefix_ended.get_or_insert(at);
    }

    /// Marks the end of the window's side-by-side phase at `at`.
    pub(crate) fn mark_window_prefixes_ended(&mut self, at: Instant) {
        self.window_prefixes_ended.get_or_insert(at);
    }

    /// Marks this slot's finish start at `at`.
    pub(crate) fn mark_finish_started(&mut self, at: Instant) {
        self.finish_started.get_or_insert(at);
    }

    /// Closes the model run that began at `run_started`: what the stages
    /// timed inside it did not take is `extract_ms`.
    pub(super) fn close_model_run(&mut self, run_started: Instant) {
        self.close_model_run_at(run_started, Instant::now());
    }

    /// Closes the model run that ran from `run_started` to `ended`, and
    /// splits its residual at the marks. An unmarked prefix runs to the
    /// end; an unmarked window or finish mark falls on the mark before it,
    /// so its part is 0. The four parts always sum to `extract_ms`.
    pub(crate) fn close_model_run_at(&mut self, run_started: Instant, ended: Instant) {
        let inner = self
            .corrections_ms
            .saturating_add(self.resolve_ms)
            .saturating_add(self.gap_ms);
        let ended = ended.max(run_started);
        self.extract_ms = ms_between(run_started, ended).saturating_sub(inner);
        // Each mark lies between the mark before it and the run's end.
        let within =
            |mark: Option<Instant>, floor: Instant| mark.unwrap_or(floor).clamp(floor, ended);
        let prefix = within(self.prefix_ended.or(Some(ended)), run_started);
        let window = within(self.window_prefixes_ended, prefix);
        let finish = within(self.finish_started, window);
        self.call_ms = ms_between(run_started, prefix).min(self.extract_ms);
        self.prefix_ready_ms = ms_between(prefix, window).min(self.extract_ms - self.call_ms);
        self.finish_start_ms =
            ms_between(window, finish).min(self.extract_ms - self.call_ms - self.prefix_ready_ms);
        self.finish_ms =
            self.extract_ms - self.call_ms - self.prefix_ready_ms - self.finish_start_ms;
    }

    /// Logs the attempt's one stage line once it `executed`.
    pub(super) fn log(
        &self,
        attempt: &DreamerAdmittedAttempt,
        turns: usize,
        executed: &Result<DreamerAttemptExecution>,
    ) {
        self.log_line(
            &bytes_to_hex_lower(attempt.status.attempt.id.as_bytes()),
            scope_name(&attempt.status.attempt.kind),
            turns,
            &outcome_label(executed),
        );
    }

    /// The stage line of `attempt` (hex) in `scope` over `turns` turns,
    /// ended as `outcome`.
    pub(crate) fn log_line(&self, attempt: &str, scope: &str, turns: usize, outcome: &str) {
        let (landed, rejected, landed_ids) = self.landing.read();
        tracing::info!(
            target: "oneiron::dreamer::stages",
            attempt = %attempt,
            scope,
            turns,
            prep_ms = self.prep_ms,
            branch_ms = self.branch_ms,
            extract_ms = self.extract_ms,
            call_ms = self.call_ms,
            prefix_ready_ms = self.prefix_ready_ms,
            finish_start_ms = self.finish_start_ms,
            finish_ms = self.finish_ms,
            corrections_ms = self.corrections_ms,
            resolve_ms = self.resolve_ms,
            gap_ms = self.gap_ms,
            commit_ms = self.commit_ms,
            total_ms = ms_since(self.started),
            landed,
            rejected,
            outcome = %outcome,
            snapshot_at_exports =
                loro::snapshot_at_exports().saturating_sub(self.exports_at_start),
            landed_ids = %landed_ids,
            "dreamer partition stages"
        );
    }
}

#[cfg(oneiron_test_support)]
impl PartitionStages {
    /// Sets the stages timed inside the model run, for the test door
    /// (FIX 21929).
    pub(crate) fn set_inner_stage_ms(&mut self, corrections_ms: u64, resolve_ms: u64, gap_ms: u64) {
        self.corrections_ms = corrections_ms;
        self.resolve_ms = resolve_ms;
        self.gap_ms = gap_ms;
    }
}

/// The consolidation lane an attempt kind names.
fn scope_name(kind: &str) -> &'static str {
    [
        DreamerConsolidationScope::Micro,
        DreamerConsolidationScope::Meso,
        DreamerConsolidationScope::Macro,
    ]
    .into_iter()
    .find(|scope| scope.attempt_kind() == kind)
    .map_or("other", DreamerConsolidationScope::as_str)
}

/// `landed`, `deferred`, `parked:<cause>` or `failed:<kind>`. Never a park's
/// reason: it can quote a reply.
fn outcome_label(executed: &Result<DreamerAttemptExecution>) -> String {
    match executed {
        Ok(DreamerAttemptExecution::Completed { .. }) => "landed".to_owned(),
        Ok(DreamerAttemptExecution::Deferred { .. }) => "deferred".to_owned(),
        Ok(
            DreamerAttemptExecution::Park { cause, .. }
            | DreamerAttemptExecution::ParkWithSpend { cause, .. },
        ) => format!("parked:{}", cause.as_str()),
        Ok(
            DreamerAttemptExecution::ParkOnSeat { .. }
            | DreamerAttemptExecution::ParkOnSeatWithSpend { .. },
        ) => "parked:signal".to_owned(),
        Ok(DreamerAttemptExecution::Failed { .. }) => "failed:terminal".to_owned(),
        Ok(DreamerAttemptExecution::Landed { .. }) => "landing".to_owned(),
        Err(error) => format!("failed:{:?}", error.kind()),
    }
}

/// What the promotion door did with a sealed write, told back to the
/// partition that sealed it: the claim ids it landed and how many
/// candidates it refused.
#[derive(Clone, Default)]
pub(crate) struct LandingTally(Arc<Mutex<Landing>>);

#[derive(Default)]
struct Landing {
    landed: Vec<EntityId>,
    rejected: usize,
}

impl LandingTally {
    /// Records one write's `landed` claim ids and `rejected` count.
    pub(crate) fn record(&self, landed: &[EntityId], rejected: usize) {
        if let Ok(mut landing) = self.0.lock() {
            landing.landed.extend_from_slice(landed);
            landing.rejected = landing.rejected.saturating_add(rejected);
        }
    }

    /// The landed count, the refused count and the landed ids as
    /// comma-joined hex.
    fn read(&self) -> (usize, usize, String) {
        self.0.lock().map_or_else(
            |_| (0, 0, String::new()),
            |landing| {
                let ids: Vec<String> = landing.landed.iter().map(EntityId::to_hex).collect();
                (landing.landed.len(), landing.rejected, ids.join(","))
            },
        )
    }
}
