//! Wake request and outcome vocabulary plus the executor contract.

use std::sync::{Mutex, OnceLock, PoisonError};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptCancelReceiptKind, AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint,
    LandingTrigger,
};
#[cfg(feature = "sync")]
use crate::dreamer_runner::DreamerAttemptProgressProducer;
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerConsolidationScope, DreamerParkCause};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::BudgetGuard;
#[cfg(feature = "sync")]
use crate::sync::EphemeralStore;
use crate::task_verb::{RunnerDoneAnswer, RunnerDoneQuestion};
use crate::write_envelope::WriteEnvelope;

use super::deadline::WakePassDeadline;

/// What woke the Dreamer (C9 wake model, design D2).
///
/// # Compaction handoff (DREAM-008, ONE-1250)
///
/// [`Self::Compaction`] stays fully usable on its own: a host that simply
/// observed a compaction calls [`request_wake`](crate::dreamer_wake::request_wake) with no packet and nothing
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
    /// Micro; the event payload may override at [`request_wake`](crate::dreamer_wake::request_wake) time.
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
    /// Exact caller attenuation for this wake. It is prepared once at the
    /// root, never inferred from a decorated executor's optional metadata.
    pub host_scope: Option<crate::llm::Scope>,
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
    /// A [`WakeCancellation`](crate::WakeCancellation) request was honored at an attempt-boundary
    /// checkpoint. Any attempt admitted when the request landed was parked and
    /// its budget reservation refunded — nothing leaks (H-S5/R2).
    Cancelled,
    /// The pass worked through the head of a backlog larger than one wake
    /// prepares and met the rest, which waits for the next pass.
    BacklogLeft,
    /// A `host.wake` pre-hook skipped the wake, or asked first (ARCH-0080
    /// §5): the pass did nothing, and the hook's receipt keeps why.
    HookSkipped,
}

/// Why a pass authored its claims single-pass under a promoted
/// claim-authoring default (FIX 897). Never a refusal: the pass ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAuthoringFallback {
    /// Several bound campaigns carry the default, in root order; none is
    /// chosen for the host (Engine 10-18).
    AmbiguousCampaigns { roots: Vec<AttemptId> },
}

/// Wake-pass tally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WakePassReport {
    pub admitted: u32,
    pub completed: u32,
    pub failed: u32,
    /// Attempts whose spend settled and whose remaining work has a timed retry.
    pub deferred: u32,
    pub parked: u32,
    /// ONE-1896: attempts that answered a stop by LANDING. Deliberately its own
    /// counter and never folded into `completed`: a landing delivered no
    /// result, and a pass that reported it as completed would be claiming work
    /// finished that a successor still has to do.
    pub landed: u32,
    /// Selection retries whose source budget left admissible sources out:
    /// each ran its originals and the oldest others that fit, and more
    /// sources exist. A truncation, never a refusal.
    pub sources_truncated: u32,
    pub stop: WakePassStop,
    /// Set when the pass's consolidation admissions fell back to
    /// single-pass under a promoted default, with why.
    pub claim_authoring_fallback: Option<ClaimAuthoringFallback>,
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
    /// The try ends Failed with `reason`, terminal and resumed by nothing:
    /// a turn program whose attested owner is no longer the vault's live
    /// owner (FIX 11090). The driver settles its spend, fails it on the
    /// queue and counts it failed; the pass goes on.
    Failed {
        reason: String,
        completed_units: u64,
    },
    Park {
        reason: String,
        cause: DreamerParkCause,
    },
    /// Checkpoint a stopped run after admitted calls have already spent units.
    /// The driver settles the wake reservation before parking the attempt.
    ParkWithSpend {
        reason: String,
        cause: DreamerParkCause,
        completed_units: u64,
        /// Terminal step identities this checkpoint charges for the first time.
        /// Atomic with wake-budget settlement so replay cannot double debit.
        step_hashes: Vec<[u8; 32]>,
    },
    /// Selection holds are scheduled retries, never unspent parked attempts.
    Deferred {
        completed_units: u64,
        retry_at: u64,
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
    /// One frozen LMDB ledger revision for this entire wake, if the driver
    /// supplied it. Standalone direct executor calls own a local snapshot.
    pub prepared_wake: Option<&'a crate::dreamer_consolidation::PreparedWake>,
    /// Selected immutable branch plan. Non-consolidation jobs have None.
    pub prepared_attempt: Option<&'a crate::dreamer_consolidation::PreparedConsolidationAttempt>,
    /// The attempt's own run line, as the driver observes it outside the
    /// executor's future (SCAN C012): a failed or plainly parked attempt
    /// settles what that line charged. `None` observes nothing.
    pub spend_meter: Option<&'a WakeAttemptMeter>,
}

/// The run line an attempt's calls charge, registered by the executor that
/// builds it and read by the driver once the attempt ends, a caught panic
/// included (SCAN C012). Only the first registration counts.
#[derive(Debug, Default)]
pub struct WakeAttemptMeter {
    line: OnceLock<(BudgetGuard, u64)>,
    /// The terminal steps the executor tallied as paid on that line, each
    /// with its units, in the order it noted them (FIX 6100).
    terminal_steps: Mutex<Vec<([u8; 32], u64)>>,
    /// What the executor's own tally spent before an error left it, with
    /// the terminal steps those units pay for (FIX 7432).
    spent_before_error: Mutex<(u64, Vec<[u8; 32]>)>,
}

impl WakeAttemptMeter {
    /// The units the registered line charged since it was registered, and
    /// what the executor's tally spent before an error (FIX 7432): 0 when
    /// neither was noted, as for an attempt that never dispatched.
    #[must_use]
    pub fn charged_units(&self) -> u64 {
        self.line_units()
            .saturating_add(self.lock_spent_before_error().0)
    }

    fn line_units(&self) -> u64 {
        self.line.get().map_or(0, |(line, start)| {
            line.read().used_units.saturating_sub(*start)
        })
    }

    fn lock_spent_before_error(&self) -> std::sync::MutexGuard<'_, (u64, Vec<[u8; 32]>)> {
        self.spent_before_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The terminal steps a settlement of [`Self::charged_units`] pays
    /// for, each once: those the tally spent before an error, then the
    /// leading noted line steps whose units fit in the line's charge, so no
    /// step is pinned paid beyond what the settlement charges (FIX 6100).
    pub(crate) fn step_receipts(&self) -> Vec<[u8; 32]> {
        let mut paid = self.lock_spent_before_error().1.clone();
        let steps = self
            .terminal_steps
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut left = self.line_units();
        for &(hash, units) in &*steps {
            let Some(rest) = left.checked_sub(units) else {
                break;
            };
            left = rest;
            if !paid.contains(&hash) {
                paid.push(hash);
            }
        }
        paid
    }
}

impl WakeAttemptContext<'_> {
    /// Registers `line`, the attempt's own run line, at what it has already
    /// used, so the driver settles what it charges if the attempt fails or
    /// parks before reporting its spend (SCAN C012). A second line, or a
    /// context with no meter, registers nothing.
    pub fn meter_run_line(&self, line: &BudgetGuard) {
        if let Some(meter) = self.spend_meter {
            let _ = meter.line.set((line.clone(), line.read().used_units));
        }
    }

    /// Notes a terminal step newly paid on the registered run line, with its
    /// `units`, so a failure or park that settles the line's charge pins
    /// that step's paid receipt in the same settlement and a replay of its
    /// memo is not paid again (FIX 6100). With no line registered, or no
    /// meter, nothing is noted: nothing would settle its charge.
    pub fn note_terminal_step_charge(&self, step_hash: [u8; 32], units: u64) {
        if let Some(meter) = self.spend_meter
            && meter.line.get().is_some()
        {
            meter
                .terminal_steps
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((step_hash, units));
        }
    }

    /// Hands the driver what the executor's own tally spent before an error
    /// leaves the attempt (FIX 7432): `units`, and the terminal `step_hashes`
    /// they pay for. The error itself goes on unchanged; the failure or park
    /// that settles it charges these units and pins their receipts. With no
    /// meter nothing is handed.
    pub(crate) fn note_spend_before_error(&self, units: u64, step_hashes: &[[u8; 32]]) {
        if let Some(meter) = self.spend_meter {
            let mut spent = meter.lock_spent_before_error();
            spent.0 = spent.0.saturating_add(units);
            for hash in step_hashes {
                if !spent.1.contains(hash) {
                    spent.1.push(*hash);
                }
            }
        }
    }

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

    /// The host's answer to a completed TASK try's "Done means met?"
    /// (OF-533), asked once the try's result is attached and outside any
    /// transaction. `None` judges nothing, so a briefed TASK's Done asks up.
    async fn judge_done(&self, _question: RunnerDoneQuestion) -> Option<RunnerDoneAnswer> {
        None
    }

    /// The runner ledger line a candidate's admission and settlement debit
    /// when the host routes it off the pass's line: a resident dreaming on
    /// its own model debits its own line (FIX 1152). Accounting only: `None`
    /// keeps the pass's line, and no answer refuses admission.
    fn runner_budget_id(&mut self, _candidate: &AttemptRecord) -> Option<String> {
        None
    }

    /// Whether this executor runs turn programs (DOOR-141 PR2): the driver
    /// admits program attempts only to one that does, so a pass whose host
    /// binds no program runtime admits none and changes nothing else.
    fn runs_turn_programs(&self) -> bool {
        false
    }
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
