//! Housekeeping sweep identifiers, cadence policy, and pass budget values.

use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// One sweep the housekeeping pass knows. The engine runs the first fifteen;
/// the rest need a host's authority and are reported, never run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HousekeepingSweep {
    /// Expires every active secret lease past its deadline and removes its
    /// registered file.
    SecretLeaseExpiry,
    /// Demotes critical-write confirms still Auto past their 300-second window.
    CriticalConfirmExpiry,
    /// Clears symbol-lease holds past their expiry.
    SymbolLeaseExpiry,
    /// Deletes voice prints past their retention deadline.
    VoicePrintRetention,
    /// Expires signing documents and recipients past their signing window.
    EsignExpiry,
    /// Re-queues the seal of a signing request whose trigger was missed.
    EsignSealBackstop,
    /// Lapses overdue open commitments and repairs missed close hooks.
    CommitmentLapse,
    /// Finishes staged key retirements and ages out gate decisions past the
    /// owner's horizon.
    GateDecisionRetention,
    /// Discharges queued erasure obligations from historical carriers.
    HardEraseSweep,
    /// Evicts cached graph walks past the longest serve window.
    PprCacheEviction,
    /// Tells the live Owners of each waiting shared act whose window has
    /// passed with no live objection (OF-163). Effect-free.
    SharedActMaturity,
    /// Works the queued historical lift run (OF-067): rows stored before the
    /// write wall saw them are masked through their own doors, and each hit
    /// no door places files a lift proposal. Idle when no run is queued, and
    /// paused while the owner's switch is off.
    SecretLiftHistory,
    /// Finishes owed claim VAD consolidations (FIX 9598): an approval whose
    /// writer or payment worker stopped, or whose consolidation failed,
    /// before it was done.
    ClaimVadDebt,
    /// Raises the found-key notices left due past one write's share (OF-560,
    /// FIX 2648), for a vault no later write comes to.
    FoundKeyNotices,
    /// Rebuilds whole-body line indexes reads found missing or short (FIX
    /// 1186b): a read notes the body, this sweep streams it once and
    /// publishes the derived sidecar.
    BodyLineIndexRebuild,
    /// Moves anchored comments with their artifact's live DOCX or XLSX body
    /// (FIX 2460), off every edit's and export's answer: stamps a body anchor
    /// on a thread on a version the body holds, lands it on the newest export
    /// and follows the body's edits.
    AnnotationBodyAnchors,
    /// Due signing reminders.
    EsignReminders,
    /// Consult deadlines and their expiry digests.
    ConsultSettlement,
    /// Pruning of resolved or stale moderation holds.
    PolicyHoldPrune,
    /// The TASK receipt attribution pump.
    TaskAttribution,
    /// Reclaim of attempt leases a live worker no longer holds.
    AttemptLeaseReclaim,
    /// Scheduled self-heal detector runs.
    SelfHealDetectorRuns,
}

/// Why a sweep is the host's to run, not the engine's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOnlyReason {
    /// Each dispatch needs an authenticated actor, grants and a window from
    /// the host; a timer is not that authority.
    NeedsAuthenticatedDispatch,
    /// The host supplies per-asker native routes and drives consult settlement
    /// on each admitted housekeeping pass; expiry itself needs no actor.
    NeedsHostDigestRoute,
    /// Only an authenticated owner may prune their holds.
    NeedsAuthenticatedOwner,
    /// Execution facts come from the host's receipt source.
    NeedsHostReceiptFacts,
    /// Attempt leases carry no heartbeat, so only the host knows which leases
    /// its live workers hold; the host reclaims dead ones when it starts.
    NeedsLiveLeaseSet,
    /// A detector run needs the host's instance, scope and observations.
    NeedsHostDetectorInputs,
}

/// How a sweep runs.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Runner {
    Engine {
        /// Seconds between runs.
        every: u64,
        /// Also due on the first pass of every handle, whatever the schedule
        /// says: work an interrupted owner act left durable must not wait a
        /// whole cadence after a restart.
        at_open: bool,
    },
    Host(HostOnlyReason),
}

pub(crate) const MINUTE: u64 = 60;
pub(crate) const HOUR: u64 = 60 * MINUTE;
pub(crate) const DAY: u64 = 24 * HOUR;

impl HousekeepingSweep {
    /// Every sweep, in report order.
    pub const ALL: [Self; 22] = [
        Self::SecretLeaseExpiry,
        Self::CriticalConfirmExpiry,
        Self::SymbolLeaseExpiry,
        Self::VoicePrintRetention,
        Self::EsignExpiry,
        Self::EsignSealBackstop,
        Self::CommitmentLapse,
        Self::GateDecisionRetention,
        Self::HardEraseSweep,
        Self::PprCacheEviction,
        Self::SharedActMaturity,
        Self::SecretLiftHistory,
        Self::ClaimVadDebt,
        Self::FoundKeyNotices,
        Self::BodyLineIndexRebuild,
        Self::AnnotationBodyAnchors,
        Self::EsignReminders,
        Self::ConsultSettlement,
        Self::PolicyHoldPrune,
        Self::TaskAttribution,
        Self::AttemptLeaseReclaim,
        Self::SelfHealDetectorRuns,
    ];

    /// The sweep's stable code: its schedule key and its log field.
    pub const fn code(self) -> &'static str {
        match self {
            Self::SecretLeaseExpiry => "secret_lease_expiry",
            Self::CriticalConfirmExpiry => "critical_confirm_expiry",
            Self::SymbolLeaseExpiry => "symbol_lease_expiry",
            Self::VoicePrintRetention => "voice_print_retention",
            Self::EsignExpiry => "esign_expiry",
            Self::EsignSealBackstop => "esign_seal_backstop",
            Self::CommitmentLapse => "commitment_lapse",
            Self::GateDecisionRetention => "gate_decision_retention",
            Self::HardEraseSweep => "hard_erase_sweep",
            Self::PprCacheEviction => "ppr_cache_eviction",
            Self::SharedActMaturity => "shared_act_maturity",
            Self::SecretLiftHistory => "secret_lift_history",
            Self::ClaimVadDebt => "claim_vad_debt",
            Self::FoundKeyNotices => "found_key_notices",
            Self::BodyLineIndexRebuild => "body_line_index_rebuild",
            Self::AnnotationBodyAnchors => "annotation_body_anchors",
            Self::EsignReminders => "esign_reminders",
            Self::ConsultSettlement => "consult_settlement",
            Self::PolicyHoldPrune => "policy_hold_prune",
            Self::TaskAttribution => "task_attribution",
            Self::AttemptLeaseReclaim => "attempt_lease_reclaim",
            Self::SelfHealDetectorRuns => "self_heal_detector_runs",
        }
    }

    /// Cadences: the code's own stated duty where canon is silent. A secret
    /// lease's expiry, a print's retention deadline and a confirm's 300-second
    /// window make their sweep due at that moment (the doors note them), so
    /// those sweeps run then and hourly besides, for a deadline no door noted.
    /// The seal backstop runs every fifteen minutes (ARCH-0064 SGN-04); the
    /// erasure sweep daily, hourly while an obligation waits (ARCH-0038's
    /// deadline is 30 days); the graph-walk cache daily. A shared act's
    /// deadline makes the maturity sweep due then (its start notes it), and
    /// it runs hourly besides, for an act an objection withdrawal released.
    /// The lift sweep looks for a queued run every fifteen minutes, and a run
    /// left unfinished at a pass's deadline is due again at once. Owed claim
    /// VAD work runs at open, for an approval a stopped process left, and
    /// every fifteen minutes, behind the payment worker each write wakes
    /// (FIX 11702). The found-key drain looks for due notices every
    /// fifteen minutes. The line-index rebuild drain looks for queued bodies
    /// every fifteen minutes. Comments follow their live body every minute
    /// and at open, so a stopped process leaves none behind.
    pub(crate) const fn runner(self) -> Runner {
        const fn engine(every: u64) -> Runner {
            Runner::Engine {
                every,
                at_open: false,
            }
        }
        match self {
            Self::SecretLeaseExpiry | Self::CriticalConfirmExpiry | Self::VoicePrintRetention => {
                engine(HOUR)
            }
            Self::SymbolLeaseExpiry => engine(5 * MINUTE),
            Self::EsignExpiry
            | Self::EsignSealBackstop
            | Self::CommitmentLapse
            | Self::SecretLiftHistory
            | Self::FoundKeyNotices
            | Self::BodyLineIndexRebuild => engine(15 * MINUTE),
            Self::GateDecisionRetention => Runner::Engine {
                every: HOUR,
                at_open: true,
            },
            Self::HardEraseSweep | Self::PprCacheEviction => engine(DAY),
            Self::SharedActMaturity => engine(HOUR),
            Self::ClaimVadDebt => Runner::Engine {
                every: 15 * MINUTE,
                at_open: true,
            },
            Self::AnnotationBodyAnchors => Runner::Engine {
                every: MINUTE,
                at_open: true,
            },
            Self::EsignReminders => Runner::Host(HostOnlyReason::NeedsAuthenticatedDispatch),
            Self::ConsultSettlement => Runner::Host(HostOnlyReason::NeedsHostDigestRoute),
            Self::PolicyHoldPrune => Runner::Host(HostOnlyReason::NeedsAuthenticatedOwner),
            Self::TaskAttribution => Runner::Host(HostOnlyReason::NeedsHostReceiptFacts),
            Self::AttemptLeaseReclaim => Runner::Host(HostOnlyReason::NeedsLiveLeaseSet),
            Self::SelfHealDetectorRuns => Runner::Host(HostOnlyReason::NeedsHostDetectorInputs),
        }
    }
}

/// How long one pass may keep starting work. A sweep in flight finishes; the
/// budget is checked before each sweep and between the pages of a paged one.
/// A pass always runs at least one due sweep, so it makes progress, unless
/// its host has asked it to stop.
#[derive(Debug, Clone, Default)]
pub struct HousekeepingBudget {
    time: Option<Duration>,
    stop: Option<Arc<AtomicBool>>,
}

impl HousekeepingBudget {
    /// Start no new sweep or page once `time` has passed.
    pub fn within(time: Duration) -> Self {
        Self {
            time: Some(time),
            stop: None,
        }
    }

    /// No time bound: every sweep runs to its own bound.
    pub fn unbounded() -> Self {
        Self::default()
    }

    /// Also start no new sweep or page once `stop` is set: a host that is
    /// shutting down sets it, then waits for the pass to return.
    #[must_use]
    pub fn stop_when(self, stop: Arc<AtomicBool>) -> Self {
        Self {
            stop: Some(stop),
            ..self
        }
    }

    pub(crate) fn deadline(&self) -> Deadline {
        Deadline {
            at: self.time.and_then(|time| Instant::now().checked_add(time)),
            stop: self.stop.clone(),
        }
    }
}

/// When a pass stops starting work.
#[derive(Debug, Clone)]
pub(crate) struct Deadline {
    at: Option<Instant>,
    stop: Option<Arc<AtomicBool>>,
}

impl Deadline {
    /// The host asked the pass to stop.
    pub(crate) fn stopped(&self) -> bool {
        self.stop
            .as_ref()
            .is_some_and(|stop| stop.load(Ordering::Acquire))
    }

    pub(crate) fn passed(&self) -> bool {
        self.stopped() || self.at.is_some_and(|at| Instant::now() >= at)
    }
}

/// Per-handle housekeeping state: one pass at a time, and whether this handle
/// has run its first pass yet.
#[derive(Debug, Default)]
pub(crate) struct HousekeepingHandle {
    pub(crate) first_pass_done: bool,
}
