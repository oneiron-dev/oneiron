//! Durable wire types of the ONE-1896 two-rung graceful-cancel protocol.
//!
//! Everything here is persisted inside [`AttemptCancelState`] on an attempt
//! row. The verb inputs and outcomes live in [`super::verbs`], the queue doors
//! in [`super::ops`] and [`super::terminal`].

use serde::{Deserialize, Serialize};

use crate::attempt_queue::validate::validate_cancel_actor;
use crate::error::Result;

/// Defensive cap on [`AttemptCancelState::receipts`] rows.
///
/// Like the manifest and unlike `events`, this door REFUSES at the cap instead
/// of draining: the rejection history is the pathology evidence (ONE-1896 §1),
/// so dropping its oldest rows would let a worker that refused a hundred times
/// present as one that refused twice.
pub const MAX_ATTEMPT_CANCEL_RECEIPTS: usize = 256;

/// Rows of [`MAX_ATTEMPT_CANCEL_RECEIPTS`] held back for the ONE terminal
/// receipt.
///
/// A bounded history must never make an attempt unsettleable: without this
/// slot, a row that reached the cap could not record `Landed`, `ForceCancelled`
/// or the runtime's lease-expiry cleanup, so a worker could refuse its way into
/// a permanently unkillable attempt. Non-terminal rows therefore refuse one row
/// EARLIER, and the reserved slot is spendable only by a terminal receipt.
pub const TERMINAL_CANCEL_RECEIPT_RESERVE: usize = 1;

/// Cap the append-only, NON-terminal protocol evidence refuses at.
pub const MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS: usize =
    MAX_ATTEMPT_CANCEL_RECEIPTS - TERMINAL_CANCEL_RECEIPT_RESERVE;

/// Share of an attempt's dialed budget held back for LANDING work.
///
/// The dial is a percent of INTEGER budget units, never a float: the reserve is
/// accounting a terminal receipt reports, and a rounded float would make
/// "spent exactly the reserve" untestable.
pub const LANDING_RESERVE_PERCENT: u64 = 10;

/// Largest landing reserve a caller may dial. Past half the budget the
/// "reserve" is the budget and ordinary execution is the exception.
pub const MAX_LANDING_RESERVE_PERCENT: u64 = 50;

/// Refused soft cancel requests after which repeated refusal is an observable
/// pathology rather than a legitimate "not yet".
///
/// Crossing it never changes the attempt's state: only the hard rung
/// ([`AttemptQueue::force_cancel`](crate::attempt_queue::AttemptQueue::force_cancel))
/// can stop a worker that will not land, and this is the signal that says so.
pub const SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD: u32 = 3;

/// Fraction of the lease timeout after which the runtime may WARN a worker to
/// land. Distinct from expiry: the warning asks, expiry forces.
pub const LEASE_LANDING_WARNING_PERCENT: u64 = 80;

/// Actor token reserved for runtime-authored rows.
///
/// Worker- and peer-facing cancel doors refuse it, so a worker cannot author a
/// row that reads as if the runtime wrote it. It matches the run-tree
/// projection's runtime actor so both surfaces name the runtime identically.
pub const ATTEMPT_RUNTIME_ACTOR: &str = "runtime";

/// Why an attempt was asked to LAND (ONE-1896 §5).
///
/// Typed provenance, never a bare "cancelling" boolean: a landing forced by a
/// budget ceiling and a landing a peer asked for produce the same state but
/// call for different successor work, and the receipt has to say which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum LandingTrigger {
    /// A soft `cancel.request` from an actor with standing.
    CancelRequest,
    /// Budget or quota depletion is approaching (the `budget.land.95` rung).
    BudgetWarning,
    /// The lease is inside its expiry warning window.
    LeaseWarning,
}

impl LandingTrigger {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CancelRequest => "cancel_request",
            Self::BudgetWarning => "budget_warning",
            Self::LeaseWarning => "lease_warning",
        }
    }
}

/// Standing to ASK a running attempt to stop — the soft rung, and only the
/// soft rung.
///
/// The queue does not authenticate actors; the calling adapter RESOLVES
/// standing from its own authority evidence (a spawner link, a task owner
/// record, the runtime's own clock) exactly as `tasks.cancel` resolves
/// ownership, and passes the resolved verdict here. Fail closed: an adapter
/// that cannot establish standing passes [`Self::None`] and the attempt is
/// left untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CancelStanding {
    /// A peer agent — typically the spawner of a sticky child.
    PeerAgent,
    /// A healer or self-repair loop.
    Healer,
    /// Scheduled automation, including the runtime's own warnings.
    Automation,
    /// The owner/authority. The ONLY standing that can also reach the hard rung.
    Authority,
    /// No standing established. Nothing may be asked.
    None,
}

impl CancelStanding {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerAgent => "peer_agent",
            Self::Healer => "healer",
            Self::Automation => "automation",
            Self::Authority => "authority",
            Self::None => "none",
        }
    }

    /// Whether this standing may issue a soft `cancel.request`.
    #[must_use]
    pub const fn may_request(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Grounds on which a hard, unrefusable `cancel.force` was authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ForceCancelGrounds {
    /// The owner/authority ruled.
    Owner,
    /// The lease this attempt held expired.
    LeaseExpiry,
    /// A criticality stop.
    Criticality,
}

impl ForceCancelGrounds {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::LeaseExpiry => "lease_expiry",
            Self::Criticality => "criticality",
        }
    }
}

/// Proof that a hard cancellation is AUTHORIZED and runtime-authored.
///
/// The fields AND every constructor are crate-private, deliberately: a public
/// `from_standing(CancelStanding::Authority, actor)` would have been a mint —
/// `CancelStanding` is a public enum any caller can name, so anyone could have
/// declared themselves the authority and chosen the actor the terminal receipt
/// names. The hard rung is therefore reachable only from a path that has
/// ALREADY verified the owner against durable ownership provenance
/// ([`Self::owner`], used by the verified `tasks.cancel.force` door) or from a
/// runtime ground the runtime itself establishes (lease expiry, criticality).
///
/// Public callers keep the whole soft rung — request, reject, land — and the
/// typed proposal path when they cannot establish authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceCancelAuthority {
    grounds: ForceCancelGrounds,
    actor: String,
}

impl ForceCancelAuthority {
    /// Grants OWNER force authority to an actor the CALLER has already verified
    /// against durable ownership provenance.
    ///
    /// Crate-private: possession of this value is the authorization, so minting
    /// one is exactly the capability that must not be public. The actor is
    /// validated here — before any durable row can be written from it — so a
    /// verified-but-malformed owner identity fails at the door instead of
    /// persisting a receipt no reader can decode.
    pub(crate) fn owner(actor: &str) -> Result<Self> {
        validate_cancel_actor(actor)?;
        Ok(Self {
            grounds: ForceCancelGrounds::Owner,
            actor: actor.to_owned(),
        })
    }

    /// Runtime grounds: the lease expired, so the runtime — not a worker —
    /// authors the terminal receipt.
    pub(crate) fn lease_expiry() -> Self {
        Self {
            grounds: ForceCancelGrounds::LeaseExpiry,
            actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
        }
    }

    /// Runtime grounds: a criticality stop.
    ///
    /// Kept beside its sibling ground even though this build has no criticality
    /// stop wired yet: the ONE-1896 hard rung rests on THREE verified grounds,
    /// and deleting the constructor would leave the only way to reach
    /// [`ForceCancelGrounds::Criticality`] as a caller-chosen actor string —
    /// exactly the forgery this type exists to prevent. Exercised by the
    /// crate's cancel tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn criticality() -> Self {
        Self {
            grounds: ForceCancelGrounds::Criticality,
            actor: ATTEMPT_RUNTIME_ACTOR.to_owned(),
        }
    }

    /// The grounds this authority rests on.
    #[must_use]
    pub const fn grounds(&self) -> ForceCancelGrounds {
        self.grounds
    }

    /// The actor the terminal receipt will name.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }
}

/// The exact point a successor resumes from after a designed landing.
///
/// A landing that cannot say where to pick up is a kill with extra steps, so
/// the handoff door refuses to mint a successor without one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptResumePoint {
    /// Worker-authored cursor: the smallest thing a successor needs to continue.
    pub marker: String,
    /// Durable artifact/receipt the successor should read first, when one exists.
    #[serde(default)]
    pub artifact_ref: Option<String>,
    pub recorded_at: u64,
}

impl AttemptResumePoint {
    /// Builds a resume point with no artifact reference.
    #[must_use]
    pub fn new(marker: impl Into<String>, recorded_at: u64) -> Self {
        Self {
            marker: marker.into(),
            artifact_ref: None,
            recorded_at,
        }
    }

    /// Attaches the durable artifact a successor should read first.
    #[must_use]
    pub fn with_artifact_ref(mut self, artifact_ref: impl Into<String>) -> Self {
        self.artifact_ref = Some(artifact_ref.into());
        self
    }
}

/// Durable LANDING record: why the attempt is landing, who asked, and what the
/// worker reported when it accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptLanding {
    pub trigger: LandingTrigger,
    /// The actor whose request was accepted, or the runtime for a warning.
    pub requested_by: String,
    pub entered_at: u64,
    /// The worker's own status at acceptance — "green + pushed + packet-only"
    /// is a complete and valid landing answer.
    #[serde(default)]
    pub status: Option<String>,
}

/// Whether a terminal cancellation was a designed landing or a hard stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CancelMode {
    /// The worker landed: it chose to stop and left a resume point.
    Landed,
    /// The hard rung fired: unrefusable and runtime-authored.
    Forced,
}

impl CancelMode {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Landed => "landed",
            Self::Forced => "forced",
        }
    }
}

/// Durable terminal cancellation receipt, authored by the runtime.
///
/// `actor` is copied from the landing lease owner or from
/// [`ForceCancelAuthority`], never from free request text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCancellation {
    pub mode: CancelMode,
    /// Set exactly on [`CancelMode::Forced`].
    #[serde(default)]
    pub grounds: Option<ForceCancelGrounds>,
    pub actor: String,
    pub at: u64,
    #[serde(default)]
    pub reason: Option<String>,
    /// The trigger of the landing that led here, when there was one.
    #[serde(default)]
    pub trigger: Option<LandingTrigger>,
    /// Landing reserve accounting AS SETTLED at the terminal instant.
    pub reserve_units: u64,
    pub reserve_spent_units: u64,
}

impl AttemptCancellation {
    /// A cancellation row is well-formed when its grounds match its mode: only
    /// a forced stop rests on grounds, and it always does.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        matches!(self.mode, CancelMode::Forced) == self.grounds.is_some()
    }
}

/// What one [`AttemptCancelReceipt`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AttemptCancelReceiptKind {
    /// Rung 1: an actor with standing asked the worker to stop.
    SoftRequested,
    /// Rung 1 answered by LANDING.
    LandingAccepted,
    /// Rung 1 answered by REFUSAL. The attempt keeps running.
    SoftRejected,
    /// The landing recorded its exact resume point.
    ResumePointRecorded,
    /// Reserve units were spent inside the landing.
    ReserveSpent,
    /// The landing finished; a successor may carry the resume point.
    Landed,
    /// Rung 2: an authorized hard force terminated the attempt.
    ForceCancelled,
}

impl AttemptCancelReceiptKind {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftRequested => "soft_requested",
            Self::LandingAccepted => "landing_accepted",
            Self::SoftRejected => "soft_rejected",
            Self::ResumePointRecorded => "resume_point_recorded",
            Self::ReserveSpent => "reserve_spent",
            Self::Landed => "landed",
            Self::ForceCancelled => "force_cancelled",
        }
    }

    /// True for the two rows that SETTLE an attempt. Exactly one of them may
    /// exist on a row, and it is always the last one: it is the receipt the
    /// reserved history slot ([`TERMINAL_CANCEL_RECEIPT_RESERVE`]) exists for.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Landed | Self::ForceCancelled)
    }

    /// True for the two rows that ANSWER one recorded soft request, and which
    /// therefore name it through [`AttemptCancelReceipt::request_sequence`].
    #[must_use]
    pub const fn answers_request(self) -> bool {
        matches!(self, Self::LandingAccepted | Self::SoftRejected)
    }
}

/// One append-only row of the two-rung graceful-cancel protocol.
///
/// Deliberately NOT folded into [`AttemptEvent`](crate::attempt_queue::AttemptEvent),
/// for the same reason the pack manifest is not: `AttemptEvent` is the closed
/// four-variant operator intervention record, and flattening a structured
/// refusal into an operator note would erase the trigger, the status, and the
/// resume point that make a landing reviewable.
///
/// Which optional fields a row may carry is NOT free-form: every kind declares
/// its required/forbidden shape and both the write door and `decode_record`
/// enforce it (`validate::validate_cancel_receipt_fields`), so a persisted row
/// can never contradict its own kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCancelReceipt {
    pub sequence: u64,
    pub at: u64,
    /// Who authored the row. Runtime rows carry [`ATTEMPT_RUNTIME_ACTOR`].
    pub actor: String,
    pub kind: AttemptCancelReceiptKind,
    #[serde(default)]
    pub standing: Option<CancelStanding>,
    #[serde(default)]
    pub trigger: Option<LandingTrigger>,
    #[serde(default)]
    pub grounds: Option<ForceCancelGrounds>,
    /// The worker's status line, when it gave one.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// The resume point as it stood when this row was written.
    #[serde(default)]
    pub resume_point: Option<AttemptResumePoint>,
    /// Reserve units this row moved (`ReserveSpent`), or 0.
    #[serde(default)]
    pub reserve_units: u64,
    /// The `sequence` of the SoftRequested row this one ANSWERS, on the two
    /// answering kinds ([`AttemptCancelReceiptKind::answers_request`]).
    ///
    /// Requests are identified by their own receipt sequence rather than by
    /// recency: with two asks outstanding, "the last request" is not the one a
    /// refusal answered, and pairing by recency reported the refusal against a
    /// requester who is still waiting while the answered ask stayed pending
    /// forever.
    #[serde(default)]
    pub request_sequence: Option<u64>,
}

/// Two-rung cancel pressure counters carried on the row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCancelPressure {
    /// Soft requests recorded against this attempt, ever.
    #[serde(default)]
    pub requests: u32,
    /// Soft requests the worker refused. The pathology signal.
    #[serde(default)]
    pub rejections: u32,
    /// Recorded requests the worker has not yet answered.
    #[serde(default)]
    pub pending: u32,
}

impl AttemptCancelPressure {
    /// True once refusals have crossed
    /// [`SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`]. Observability only: it
    /// never terminates anything by itself.
    #[must_use]
    pub const fn is_pathological(&self) -> bool {
        self.rejections >= SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    }
}

/// Durable landing reserve accounting, in the same integer budget units as
/// [`crate::llm::BudgetRead`].
///
/// This is NOT a second budget meter. It holds back a slice and records what
/// the landing spent from it; ordinary execution is metered by the existing
/// [`crate::llm::BudgetGuard`], which is constructed with
/// [`Self::ordinary_limit_units`] and therefore never contains the reserve at
/// all. "Normal execution cannot spend it" is a property of what the ordinary
/// meter was built with, not a rule the meter has to remember.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptLandingReserve {
    /// Total budget units dialed for the attempt.
    #[serde(default)]
    pub limit_units: u64,
    /// Units held back for landing work.
    #[serde(default)]
    pub reserve_units: u64,
    /// Reserve units already spent, only ever inside `AttemptState::Landing`.
    #[serde(default)]
    pub spent_units: u64,
    /// The lease generation (`AttemptRecord::attempt_count`) this reserve was
    /// dialed at, and the durable ONE-SHOT mark.
    ///
    /// Two facts one boolean could not carry. First, it distinguishes a row
    /// deliberately dialed to a ZERO reserve (a budget too small to carve a
    /// slice from) from a row nothing has dialed yet — both leave
    /// `reserve_units == 0`, and only the second may still be dialed. Second,
    /// it fences the dial to ONE application per admitted generation: a later
    /// public or in-transaction call against the SAME generation is refused,
    /// so nothing can enlarge the reserve of an attempt that is already
    /// running against its ordinary limit. A fresh claim advances the
    /// generation, so the next admission dials its own row honestly.
    #[serde(default)]
    pub dial_generation: Option<u32>,
}

impl AttemptLandingReserve {
    /// Dials a reserve as an integer percent of `limit_units`, rounded DOWN so
    /// the reserve can never exceed the budget it is carved from.
    ///
    /// Pure arithmetic: the result carries NO dial mark, so it is the shape a
    /// caller uses to compute an ordinary meter limit, not a durable dial. The
    /// durable one is [`Self::dialed_at_generation`].
    #[must_use]
    pub const fn dialed(limit_units: u64, reserve_percent: u64) -> Self {
        Self {
            limit_units,
            reserve_units: reserve_units_for(limit_units, reserve_percent),
            spent_units: 0,
            dial_generation: None,
        }
    }

    /// The durable dial: the same arithmetic, MARKED with the lease generation
    /// it was applied at so a second dial against that generation is refused.
    #[must_use]
    pub const fn dialed_at_generation(
        limit_units: u64,
        reserve_percent: u64,
        generation: u32,
    ) -> Self {
        Self {
            limit_units,
            reserve_units: reserve_units_for(limit_units, reserve_percent),
            spent_units: 0,
            dial_generation: Some(generation),
        }
    }

    /// True once a dial has been durably applied, whatever it carved.
    #[must_use]
    pub const fn is_dialed(&self) -> bool {
        self.dial_generation.is_some()
    }

    /// The limit an ORDINARY execution meter must be built with: the dialed
    /// total minus the landing reserve.
    #[must_use]
    pub const fn ordinary_limit_units(&self) -> u64 {
        self.limit_units.saturating_sub(self.reserve_units)
    }

    /// Reserve units still available to a landing.
    #[must_use]
    pub const fn remaining_units(&self) -> u64 {
        self.reserve_units.saturating_sub(self.spent_units)
    }

    /// True once the landing has spent everything it was given.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.remaining_units() == 0
    }
}

/// Integer percent of a budget, rounded DOWN, in u128 so the product cannot
/// wrap before the division that brings it back into range.
const fn reserve_units_for(limit_units: u64, reserve_percent: u64) -> u64 {
    ((limit_units as u128 * reserve_percent as u128) / 100) as u64
}

/// The whole ONE-1896 graceful-cancel lifecycle carried by one attempt row.
///
/// One additive field rather than six: the protocol is a single coherent
/// sub-record, and rows written before it decode as [`Self::default`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCancelState {
    /// Present exactly while the row is landing, and preserved afterwards on a
    /// row that landed, so a terminal receipt can still name its trigger.
    #[serde(default)]
    pub landing: Option<AttemptLanding>,
    /// Set on a landing row when the worker records it, and COPIED onto the
    /// successor row so a handoff cannot lose it.
    #[serde(default)]
    pub resume_point: Option<AttemptResumePoint>,
    /// Terminal cancellation receipt. Only a `Cancelled` row may carry one.
    #[serde(default)]
    pub cancellation: Option<AttemptCancellation>,
    #[serde(default)]
    pub pressure: AttemptCancelPressure,
    /// Append-only protocol evidence, never drained.
    #[serde(default)]
    pub receipts: Vec<AttemptCancelReceipt>,
    #[serde(default)]
    pub reserve: AttemptLandingReserve,
}
