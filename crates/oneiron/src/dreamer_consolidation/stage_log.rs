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

/// Wall ms since `started`.
pub(crate) fn ms_since(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The wall ms of one partition attempt's stages. A stage the attempt never
/// reached stays 0.
pub(super) struct PartitionStages {
    started: Instant,
    exports_at_start: u64,
    /// The wake's frozen preparation, shared by every partition it prepared.
    /// It ran before this attempt, so `total_ms` leaves it out.
    prep_ms: u64,
    /// Opening the branch's resources at the wake's pin.
    pub(super) branch_ms: u64,
    /// The model run less the stages below: slices, the extraction fan-out
    /// and its reply checks, people bind and mint, and a thing's scoped
    /// agent pass.
    extract_ms: u64,
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
    pub(super) fn start(prep_ms: u64) -> Self {
        Self {
            started: Instant::now(),
            exports_at_start: loro::snapshot_at_exports(),
            prep_ms,
            branch_ms: 0,
            extract_ms: 0,
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

    /// Closes the model run that began at `run_started`: what the stages
    /// timed inside it did not take is `extract_ms`.
    pub(super) fn close_model_run(&mut self, run_started: Instant) {
        let inner = self
            .corrections_ms
            .saturating_add(self.resolve_ms)
            .saturating_add(self.gap_ms);
        self.extract_ms = ms_since(run_started).saturating_sub(inner);
    }

    /// Logs the attempt's one stage line once it `executed`.
    pub(super) fn log(
        &self,
        attempt: &DreamerAdmittedAttempt,
        turns: usize,
        executed: &Result<DreamerAttemptExecution>,
    ) {
        let (landed, rejected, landed_ids) = self.landing.read();
        tracing::info!(
            target: "oneiron::dreamer::stages",
            attempt = %bytes_to_hex_lower(attempt.status.attempt.id.as_bytes()),
            scope = scope_name(&attempt.status.attempt.kind),
            turns,
            prep_ms = self.prep_ms,
            branch_ms = self.branch_ms,
            extract_ms = self.extract_ms,
            corrections_ms = self.corrections_ms,
            resolve_ms = self.resolve_ms,
            gap_ms = self.gap_ms,
            commit_ms = self.commit_ms,
            total_ms = ms_since(self.started),
            landed,
            rejected,
            outcome = %outcome_label(executed),
            snapshot_at_exports =
                loro::snapshot_at_exports().saturating_sub(self.exports_at_start),
            landed_ids = %landed_ids,
            "dreamer partition stages"
        );
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
