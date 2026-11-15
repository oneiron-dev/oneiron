//! Moved from `crates/oneiron/src/dreamer_wake/types.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

#[cfg(feature = "sync")]
use crate::dreamer_runner::progress::DreamerAttemptProgressProducer;
use crate::dreamer_runner::types::DreamerParkCause;
use crate::memory::wake_observation::ClaimAuthoringFallback;
use crate::model_step_effect::StepEffectBinding;
use crate::settings::destination::ReadDestination;
use crate::store::attempt_cancel::AttemptResumePoint;
use crate::store::attempt_cancel::LandingTrigger;
#[cfg(feature = "sync")]
use loro::awareness::EphemeralStore;
use oneiron_contracts::entity_id::EntityId;
use oneiron_model::llm::BudgetGuard;
use oneiron_store::consolidation_scope::DreamerConsolidationScope;
use oneiron_store::model_step_submission::StepBudgetRefusal;
use oneiron_store::write_envelope::WriteEnvelope;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::PoisonError;

/// What woke the Dreamer (C9 wake model, design D2).
///
/// # Compaction handoff (DREAM-008, ONE-1250)
///
/// [`Self::Compaction`] stays fully usable on its own: a host that simply
/// observed a compaction calls `request_wake` with no packet and nothing
/// about that path changed. The trigger carries no packet field, and no
/// wake path gained a validation step.
///
/// A Compaction wake that CARRIES a forked-compaction packet is the
/// separate case. That packet is host-supplied evidence about which turns
/// were compacted and which sitting they came from, so it must be admitted
/// through `admit_compaction_packet` first and travel
/// as a `ValidatedCompactionPacket` — the witness type
/// no caller can construct. A raw `CompactionPacket`
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
    /// Micro; the event payload may override at `request_wake` time.
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
    pub host_scope: Option<oneiron_model::llm::Scope>,
    /// Where every leg of this pass's executors sends what it reads, as
    /// the vended executors state it ([`DreamerAttemptExecutor::destination_bound`],
    /// FIX 12735): the wake lists its sources, and each NOTE review its
    /// entities, for it. Read once the executors are vended, never before.
    /// `None` when an executor states no bound: the pass lists for a
    /// destination nobody proved, as every pass did before.
    pub destination_bound: Option<ReadDestination>,
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
    /// A [`WakeCancellation`](crate::dreamer_wake::deadline::WakeCancellation) request was honored at an attempt-boundary
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
        /// Terminal step identities this completion charges for the first time.
        /// Atomic with wake-budget settlement so replay cannot double debit.
        step_bindings: Vec<StepEffectBinding>,
    },
    /// The try ends Failed with `reason`, terminal and resumed by nothing:
    /// a turn program whose attested owner is no longer the vault's live
    /// owner (FIX 11090), or a step a spend scope refused for good. The
    /// driver settles its spend, fails it on the queue and counts it
    /// failed; the pass goes on.
    Failed {
        reason: String,
        completed_units: u64,
        /// The typed refusal when a spend scope refused the try's step for
        /// good (BUDGET-TRAP-UNTYPED-NO-SENDER); `None` for every other
        /// failure. The driver carries it to the failed row beside `reason`.
        budget_refusal: Option<StepBudgetRefusal>,
        /// Terminal step identities the try's paid steps charge for the
        /// first time, pinned in the settlement of its spend, so a failed
        /// try keeps the receipts of the steps it paid for.
        step_bindings: Vec<StepEffectBinding>,
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
        step_bindings: Vec<StepEffectBinding>,
    },
    /// A spent model seat parked the try: the seat's available write resumes it. `seat` is the
    /// seat's 16-byte id; `reset_at_s` is the vendor-reported reset in seconds, when one was read.
    ParkOnSeat {
        /// The refusal recorded on the park.
        reason: String,
        /// The refused model seat's durable id.
        seat: [u8; 16],
        /// The vendor-reported reset in Unix seconds, when known.
        reset_at_s: Option<u64>,
    },
    /// A spent model seat refused a step after the try's admitted calls spent units
    /// (SEAT-PARK-MODEL-STEP-PATH): the driver settles that spend as it settles
    /// [`Self::ParkWithSpend`], and parks the try on the seat in the same write. The seat's
    /// available write resumes it. `seat` is the seat's 16-byte id; `reset_at_s` is the
    /// vendor-reported reset in Unix seconds, none for a lapsed login.
    ParkOnSeatWithSpend {
        /// The refusal recorded on the park.
        reason: String,
        /// The refused model seat's durable id.
        seat: [u8; 16],
        /// The vendor-reported reset in Unix seconds, when known.
        reset_at_s: Option<u64>,
        /// Units the try's admitted calls spent before the refusal.
        completed_units: u64,
        /// Terminal step identities this park charges for the first time.
        /// Atomic with wake-budget settlement so replay cannot double debit.
        step_bindings: Vec<StepEffectBinding>,
    },
    /// Selection holds are scheduled retries, never unspent parked attempts.
    Deferred {
        completed_units: u64,
        retry_at: u64,
        /// Terminal step identities this deferral charges for the first time.
        /// Atomic with wake-budget settlement so replay cannot double debit.
        step_bindings: Vec<StepEffectBinding>,
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

/// The run line an attempt's calls charge, registered by the executor that
/// builds it and read by the driver once the attempt ends, a caught panic
/// included (SCAN C012). Only the first registration counts.
#[derive(Debug, Default)]
pub struct WakeAttemptMeter {
    pub line: OnceLock<(BudgetGuard, u64)>,
    /// The terminal steps the executor tallied as paid on that line, each
    /// with its units, in the order it noted them (FIX 6100).
    pub terminal_steps: Mutex<Vec<(StepEffectBinding, u64)>>,
    /// What the executor's own tally spent before an error left it, with
    /// the terminal steps those units pay for (FIX 7432).
    spent_before_error: Mutex<(u64, Vec<StepEffectBinding>)>,
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

    pub fn lock_spent_before_error(
        &self,
    ) -> std::sync::MutexGuard<'_, (u64, Vec<StepEffectBinding>)> {
        self.spent_before_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Captures one settlement's units and paid-step receipts together.
    /// The same line reading bounds the paid prefix, and error spend stays
    /// paired with the receipts recorded beside it.
    pub fn settlement(&self) -> (u64, Vec<StepEffectBinding>) {
        let spent = self.lock_spent_before_error();
        let steps = self
            .terminal_steps
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let line_units = self.line_units();
        let charged = line_units.saturating_add(spent.0);
        let mut paid = spent.1.clone();
        let mut left = line_units;
        for &(binding, units) in &*steps {
            let Some(rest) = left.checked_sub(units) else {
                break;
            };
            left = rest;
            if !paid.contains(&binding) {
                paid.push(binding);
            }
        }
        (charged, paid)
    }
}

/// The worker's landing answer, as the driver applies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandingRequest {
    pub reserve_units: u64,
    pub status: Option<String>,
    pub resume_point: Option<AttemptResumePoint>,
    pub hand_off: bool,
}

/// One outstanding stop request as a worker sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandingRequestNotice {
    /// Receipt sequence identifying WHICH request this is, so the answer names
    /// the ask it consumed rather than the newest one.
    pub request_sequence: u64,
    pub trigger: LandingTrigger,
    /// Who asked. The runtime's own warnings carry
    /// `ATTEMPT_RUNTIME_ACTOR`.
    pub requested_by: String,
    /// Units the attempt may spend on bounded landing work.
    pub reserve_units: u64,
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
pub enum ProgressKind {
    Running,
    Parked,
}
