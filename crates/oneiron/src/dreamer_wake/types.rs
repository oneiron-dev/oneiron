//! Wake request and outcome vocabulary plus the executor contract.

use crate::Vault;
use crate::attempt_queue::{
    AttemptCancelReceiptKind, AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint,
    LandingTrigger,
};
#[cfg(feature = "sync")]
use crate::dreamer_runner::DreamerAttemptProgressProducer;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerConsolidationScope};
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::sync::EphemeralStore;
use crate::write_envelope::WriteEnvelope;

use super::deadline::WakePassDeadline;

/// What woke the Dreamer (C9 wake model, design D2).
///
/// # Compaction handoff (DREAM-008, ONE-1250)
///
/// [`Self::Compaction`] stays fully usable on its own: a host that simply
/// observed a compaction calls [`request_wake`] with no packet and nothing
/// about that path changed. The trigger carries no packet field, and no
/// wake path gained a validation step.
///
/// A Compaction wake that CARRIES a forked-compaction packet is the
/// separate case. That packet is host-supplied evidence about which turns
/// were compacted and which sitting they came from, so it must be admitted
/// through [`crate::compaction::admit_compaction_packet`] first and travel
/// as a [`crate::compaction::ValidatedCompactionPacket`] — the witness type
/// no caller can construct. A raw [`crate::compaction::CompactionPacket`]
/// is never a wake input: passing one unadmitted would let a host assert
/// turn/session provenance the vault never recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakeTrigger {
    Compaction,
    SessionEnd,
    Event,
    Timer,
}

impl WakeTrigger {
    /// Default consolidation scope for this trigger. `Event` defaults to
    /// Micro; the event payload may override at [`request_wake`] time.
    #[must_use]
    pub const fn default_scope(self) -> DreamerConsolidationScope {
        match self {
            Self::Compaction | Self::Event => DreamerConsolidationScope::Micro,
            Self::SessionEnd => DreamerConsolidationScope::Meso,
            Self::Timer => DreamerConsolidationScope::Macro,
        }
    }
}

/// Input for one wake pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunWakePass {
    pub trigger: WakeTrigger,
    pub scope: DreamerConsolidationScope,
    pub local_node_id: u64,
    pub lease_owner: String,
    pub budget_total_units: u64,
    pub reserve_units: u64,
    pub now: u64,
}

/// Why the pass stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WakePassStop {
    QueueEmpty,
    BudgetExhausted,
    DeadlineHardCut,
    Trapped,
    NotHomeNode,
    NoHomeNode,
    /// A [`WakeCancellation`] request was honored at an attempt-boundary
    /// checkpoint. Any attempt admitted when the request landed was parked and
    /// its budget reservation refunded — nothing leaks (H-S5/R2).
    Cancelled,
}

/// Wake-pass tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakePassReport {
    pub admitted: u32,
    pub completed: u32,
    pub failed: u32,
    pub parked: u32,
    /// ONE-1896: attempts that answered a stop by LANDING. Deliberately its own
    /// counter and never folded into `completed`: a landing delivered no
    /// result, and a pass that reported it as completed would be claiming work
    /// finished that a successor still has to do.
    pub landed: u32,
    pub stop: WakePassStop,
}

/// Terminal execution outcome one executor reports for one admitted attempt.
///
/// There is NO `Trap` variant by design (D18): traps surface at the STEP
/// layer; a trapped attempt comes back as `Park` carrying the trap note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DreamerAttemptExecution {
    Completed {
        completed_units: u64,
    },
    Park {
        reason: String,
    },
    /// ONE-1896 rung 1, answered: the worker saw a soft request or a typed
    /// runtime warning ([`WakeAttemptContext::landing_request`]) and chose to
    /// stop cleanly instead of being killed.
    ///
    /// The driver turns this into the durable protocol — enter LANDING, spend
    /// the bounded landing reserve, record the resume point, finish (optionally
    /// handing off to a successor that resumes from it) — so an executor never
    /// hand-rolls the lifecycle and can never report a landing as a completion.
    Landed {
        /// Ordinary units spent before landing began, settled exactly like a
        /// completion's.
        completed_units: u64,
        /// Bounded final work paid out of the attempt's LANDING RESERVE
        /// (commit/push, receipt, resume point, handoff). It fails closed:
        /// more than the reserve holds spends nothing.
        reserve_units: u64,
        /// The worker's own status line — "green + pushed + packet-only" is a
        /// complete landing answer.
        status: Option<String>,
        /// Where a successor picks up. Required for `hand_off`.
        resume_point: Option<AttemptResumePoint>,
        /// Mint a successor row carrying the resume point.
        hand_off: bool,
    },
}

/// Per-attempt execution context handed to the executor.
pub struct WakeAttemptContext<'a> {
    pub vault: &'a Vault,
    pub deadline: &'a WakePassDeadline,
    pub budget_id: &'a str,
    pub now_ms: u64,
}

impl WakeAttemptContext<'_> {
    /// The oldest stop this attempt has been asked for and not yet answered,
    /// with the trigger that motivated it — or `None` when nobody has asked.
    ///
    /// This is the worker-facing half of ONE-1896's soft rung: a request that
    /// arrives mid-execution lands on the durable row, not in the snapshot the
    /// executor was handed, so a cooperative worker POLLS here at its own
    /// step boundaries and answers by returning
    /// [`DreamerAttemptExecution::Landed`] (or by refusing through
    /// `AttemptQueue::reject_cancel`, which keeps it running and records why).
    pub fn landing_request(&self, attempt_id: AttemptId) -> Result<Option<LandingRequestNotice>> {
        let Some(record) = AttemptQueue::new(self.vault).get(attempt_id)? else {
            return Ok(None);
        };
        Ok(landing_request_notice(&record))
    }
}

/// The worker's landing answer, as the driver applies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LandingRequest {
    pub(super) reserve_units: u64,
    pub(super) status: Option<String>,
    pub(super) resume_point: Option<AttemptResumePoint>,
    pub(super) hand_off: bool,
}

/// One outstanding stop request as a worker sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandingRequestNotice {
    /// Receipt sequence identifying WHICH request this is, so the answer names
    /// the ask it consumed rather than the newest one.
    pub request_sequence: u64,
    pub trigger: LandingTrigger,
    /// Who asked. The runtime's own warnings carry
    /// [`crate::attempt_queue::ATTEMPT_RUNTIME_ACTOR`].
    pub requested_by: String,
    /// Units the attempt may spend on bounded landing work.
    pub reserve_units: u64,
}

/// Projects the oldest unanswered soft request off a durable row.
fn landing_request_notice(record: &AttemptRecord) -> Option<LandingRequestNotice> {
    if record.cancel_pressure().pending == 0 {
        return None;
    }
    let answered: std::collections::HashSet<u64> = record
        .cancel_receipts()
        .iter()
        .filter(|receipt| receipt.kind.answers_request())
        .filter_map(|receipt| receipt.request_sequence)
        .collect();
    record
        .cancel_receipts()
        .iter()
        .find(|receipt| {
            receipt.kind == AttemptCancelReceiptKind::SoftRequested
                && !answered.contains(&receipt.sequence)
        })
        .map(|receipt| LandingRequestNotice {
            request_sequence: receipt.sequence,
            trigger: receipt.trigger.unwrap_or(LandingTrigger::CancelRequest),
            requested_by: receipt.actor.clone(),
            reserve_units: record.landing_reserve().remaining_units(),
        })
}

/// Executes one admitted Dreamer attempt.
///
/// AT-LEAST-ONCE contract: the driver may re-execute an attempt after a crash or
/// resume — executors MUST be step-based (ONE-1343 `call_as_step`) so
/// re-execution fast-forwards through memoized steps instead of re-spending.
/// Milestones mark durable progress; this ticket does not implement step
/// memoization itself.
///
/// PARK-OWNER contract (design D2): the STEP LAYER is the one park-owner for
/// trap suspensions — it writes the trap record and parks the attempt in its own
/// wtxn. The executor still returns `Park` carrying the trap note; the
/// driver detects the existing parked row and only publishes progress,
/// never parking a second time.
#[allow(async_fn_in_trait)]
pub trait DreamerAttemptExecutor {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution>;
}

/// Durable milestone authorship for driver-written Started/Done milestones.
///
/// The driver mints one milestone claim per event from this template; hosts
/// that do not care about durable milestones simply do not configure one.
#[derive(Debug, Clone)]
pub struct WakeMilestoneAuthor {
    pub subject: EntityId,
    pub envelope: WriteEnvelope,
}

/// Live-progress lane for the sync build: producer + ephemeral store.
#[cfg(feature = "sync")]
pub struct WakeProgressLane<'a> {
    pub producer: DreamerAttemptProgressProducer,
    pub ephemeral: &'a EphemeralStore,
}

/// Driver-internal progress vocabulary (maps onto the sync-gated
/// `DreamerAttemptProgressState` when the progress lane is configured).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProgressKind {
    Running,
    Parked,
}
