//! Durable wire, verb-input, and outcome types for the attempt queue.
//!
//! Storage mechanics live in [`super::encoding`], input validation in
//! [`super::validate`], and the queue handle itself in [`super::engine`].

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Error, Result};

/// Receipt-family ABI-pin rule: changing this requires a
/// [`crate::store::STORAGE_ABI_VERSION`] bump.
pub(crate) const ATTEMPT_RECORD_VERSION: u8 = 2;
const ERR_ATTEMPT_ID_LEN: &str = "attempt id must be 16 bytes";
pub(super) const MAX_ATTEMPT_EVENTS_PER_RECORD: usize = 256;
/// Defensive cap on [`AttemptRecord::manifest`] rows.
///
/// Deliberately NOT the `MAX_ATTEMPT_EVENTS_PER_RECORD` semantics: the
/// events field DRAINS its oldest rows above the cap, which would silently
/// violate the ARCH-0053 §3 append-only manifest invariant (an attribution
/// projector cannot tell a dropped skill from one that was never loaded).
/// The manifest door instead REFUSES at this cap — fail loud, never drain.
pub const MAX_ATTEMPT_MANIFEST_ENTRIES: usize = 4096;
pub(super) const ATTEMPT_QUEUE_RETRY_REASON_COUNT: usize = 2;

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

/// Stable identifier for a queued attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AttemptId {
    pub(super) bytes: [u8; 16],
}

impl AttemptId {
    /// Creates a new time-sortable v7 UUID-backed attempt id.
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    /// Returns the raw 16-byte storage key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    /// Parses a raw 16-byte storage key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::InvalidAttemptQueueRecord(ERR_ATTEMPT_ID_LEN))?;
        Ok(Self { bytes })
    }
}

/// Durable lifecycle state persisted on each attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttemptState {
    Queued,
    Leased,
    Paused,
    Completed,
    Failed,
    Cancelled,
    // Append-only: persisted unit-enum variants are encoded by index, so a new
    // variant may only be added AFTER every existing one. Reordering would
    // silently re-map already-written rows.
    /// Minted by [`crate::attempt_queue::AttemptQueue::retry`]: a fresh try
    /// waiting for its `scheduled_at` instant. Claimable only once
    /// `now >= scheduled_at`.
    Scheduled,
    /// ONE-1896: the worker accepted a stop and is finishing. It still HOLDS
    /// its lease, so it is neither queued work nor terminal work, and it is
    /// deliberately not [`Self::Completed`] — a landing is an honest,
    /// resumable stop, not a delivered result.
    Landing,
}

impl AttemptState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Scheduled => "scheduled",
            Self::Landing => "landing",
        }
    }

    /// True while the row can still reach a terminal state, so it still owns
    /// its advisory dedupe entry.
    pub(super) const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Leased | Self::Paused | Self::Scheduled | Self::Landing
        )
    }

    /// True for the two states a ready-index row may legitimately sit in.
    ///
    /// [`Self::Landing`] is deliberately absent: a landing attempt owns a live
    /// lease and is doing bounded finishing work, so handing it out as ordinary
    /// queued work would run it twice.
    pub(super) const fn is_ready_indexed(self) -> bool {
        matches!(self, Self::Queued | Self::Scheduled)
    }

    /// True while a worker holds this row's lease and runtime.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Leased | Self::Landing)
    }

    /// True once the row can never transition again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Durable intervention kind recorded on an attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptInterventionKind {
    Interrupt,
    Pause,
    Resume,
    Cancel,
}

impl AttemptInterventionKind {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Cancel => "cancel",
        }
    }
}

/// Durable intervention event appended to an attempt row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptEvent {
    pub sequence: u64,
    pub at: u64,
    pub actor: String,
    pub kind: AttemptInterventionKind,
    #[serde(default)]
    pub note: Option<String>,
}

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
        super::validate::validate_cancel_actor(actor)?;
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
/// Deliberately NOT folded into [`AttemptEvent`], for the same reason the pack
/// manifest is not: `AttemptEvent` is the closed four-variant operator
/// intervention record, and flattening a structured refusal into an operator
/// note would erase the trigger, the status, and the resume point that make a
/// landing reviewable.
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
    /// Total budget units dialed for the attempt. 0 means undialed.
    #[serde(default)]
    pub limit_units: u64,
    /// Units held back for landing work.
    #[serde(default)]
    pub reserve_units: u64,
    /// Reserve units already spent, only ever inside [`AttemptState::Landing`].
    #[serde(default)]
    pub spent_units: u64,
}

impl AttemptLandingReserve {
    /// Dials a reserve as an integer percent of `limit_units`, rounded DOWN so
    /// the reserve can never exceed the budget it is carved from.
    #[must_use]
    pub const fn dialed(limit_units: u64, reserve_percent: u64) -> Self {
        let reserve_units = ((limit_units as u128 * reserve_percent as u128) / 100) as u64;
        Self {
            limit_units,
            reserve_units,
            spent_units: 0,
        }
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

/// What one [`ManifestEntry`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ManifestKind {
    /// A SKILL pulled into the attempt's pack (`skill_id` + version).
    Skill,
    /// An `actor.*` claim row loaded into the attempt's pack.
    ActorClaim,
}

impl ManifestKind {
    /// Returns the stable wire string for this manifest kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::ActorClaim => "actor_claim",
        }
    }
}

/// One append-only row of an attempt's PACK MANIFEST (ARCH-0053 §2/§3).
///
/// The pack is alive: the tier-1 index is stamped at `t0` and every mid-run
/// tier-2 body pull appends its own row WHEN it happens, so the terminal
/// receipt carries the full accumulated manifest and attribution can name
/// what was actually loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub kind: ManifestKind,
    /// The loaded thing's stable identity (`skill_id`, claim id hex, …).
    pub reference: String,
    /// The loaded revision (`SkillRecord::version`, a claim revision, …).
    pub version: String,
    /// Unix seconds at which the pack loaded it.
    pub at: u64,
}

impl ManifestEntry {
    /// Builds one manifest row.
    #[must_use]
    pub fn new(
        kind: ManifestKind,
        reference: impl Into<String>,
        version: impl Into<String>,
        at: u64,
    ) -> Self {
        Self {
            kind,
            reference: reference.into(),
            version: version.into(),
            at,
        }
    }

    /// The `reference@version` wire form the terminal receipt projects.
    #[must_use]
    pub fn wire_form(&self) -> String {
        format!("{}@{}", self.reference, self.version)
    }

    /// Splits a [`Self::wire_form`] string back into `(reference, version)`.
    ///
    /// The delimiter is the FIRST `@` (owner ruling R-20260807-04). The
    /// grammar is asymmetric on purpose: a reference may not contain `@` —
    /// `validate::validate_manifest_entry` refuses one at the door — while a
    /// VERSION may, so `s@1@beta` is the skill `s` at revision
    /// `1@beta`. Splitting from the right instead read that row as skill `s@1`
    /// at revision `beta`, attributing an outcome to a skill that never
    /// existed.
    ///
    /// Returns `None` for a string carrying no `@` at all, which is not a
    /// wire form.
    #[must_use]
    pub fn parse_wire_form(wire_form: &str) -> Option<(&str, &str)> {
        wire_form.split_once('@')
    }
}

/// Durable attempt row stored in LMDB.
///
/// One synced TASK owns N node-local ATTEMPT rows. A retry never mutates a
/// failed try back into a ready one: it finalizes the source and mints a fresh
/// row linked by [`AttemptRecord::retry_of`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub id: AttemptId,
    pub kind: String,
    pub payload: Vec<u8>,
    pub state: AttemptState,
    pub lease_owner: Option<String>,
    /// Lease-generation fence WITHIN this one try. It does not count logical
    /// retries — those are separate rows.
    pub attempt_count: u32,
    #[serde(default)]
    pub claimed_at: Option<u64>,
    /// Instant a [`AttemptState::Scheduled`] row becomes claimable.
    #[serde(default)]
    pub scheduled_at: Option<u64>,
    /// The try this row retries, when it was minted by
    /// [`crate::attempt_queue::AttemptQueue::retry`].
    #[serde(default)]
    pub retry_of: Option<AttemptId>,
    /// Legacy read compatibility only. Rows written before ONE-1795 carry their
    /// readiness instant here; new retry rows use `scheduled_at`.
    #[serde(default)]
    pub backoff_until: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub task_ref: Option<String>,
    pub run_id: Option<String>,
    pub dedupe_key: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub events: Vec<AttemptEvent>,
    /// ARCH-0053 §2/§3 PACK MANIFEST: append-only, parallel to `events` and
    /// deliberately NOT folded into it (`AttemptEvent` is the closed
    /// four-variant intervention record). Rows without the key decode empty,
    /// so no migration is needed.
    #[serde(default)]
    pub manifest: Vec<ManifestEntry>,
    /// ONE-1896 two-rung graceful-cancel lifecycle: landing, resume point,
    /// terminal cancellation receipt, cancel pressure, and reserve accounting.
    /// Rows without the key decode as the default, so no migration is needed.
    #[serde(default)]
    pub cancel_state: AttemptCancelState,
}

impl AttemptRecord {
    /// The attempt's accumulated pack manifest, in append order.
    #[must_use]
    pub fn manifest(&self) -> &[ManifestEntry] {
        &self.manifest
    }

    /// The append-only graceful-cancel evidence, in append order.
    #[must_use]
    pub fn cancel_receipts(&self) -> &[AttemptCancelReceipt] {
        &self.cancel_state.receipts
    }

    /// The durable landing record, present while landing and preserved on a
    /// row that landed.
    #[must_use]
    pub const fn landing(&self) -> Option<&AttemptLanding> {
        self.cancel_state.landing.as_ref()
    }

    /// The exact point a successor resumes from, once recorded.
    #[must_use]
    pub const fn resume_point(&self) -> Option<&AttemptResumePoint> {
        self.cancel_state.resume_point.as_ref()
    }

    /// The terminal cancellation receipt, when this row was cancelled.
    #[must_use]
    pub const fn cancellation(&self) -> Option<&AttemptCancellation> {
        self.cancel_state.cancellation.as_ref()
    }

    /// This attempt's landing reserve accounting.
    #[must_use]
    pub const fn landing_reserve(&self) -> AttemptLandingReserve {
        self.cancel_state.reserve
    }

    /// The limit an ordinary execution meter for this attempt must use: the
    /// dialed budget MINUS the landing reserve.
    #[must_use]
    pub const fn ordinary_budget_limit_units(&self) -> u64 {
        self.cancel_state.reserve.ordinary_limit_units()
    }

    /// Soft-request pressure counters.
    #[must_use]
    pub const fn cancel_pressure(&self) -> AttemptCancelPressure {
        self.cancel_state.pressure
    }

    /// True once repeated refusal of soft requests is an observable pathology.
    #[must_use]
    pub const fn soft_cancel_pathology(&self) -> bool {
        self.cancel_state.pressure.is_pathological()
    }
}

/// Input for enqueueing an attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueAttempt {
    pub kind: String,
    pub payload: Vec<u8>,
    pub dedupe_key: Option<String>,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueOutcome {
    Enqueued(AttemptRecord),
    Existing(AttemptRecord),
}

/// Input for atomically claiming the next queued attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimAttempt {
    pub lease_owner: String,
    pub now: u64,
}

/// Typed claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum ClaimOutcome {
    Empty,
    Claimed(AttemptRecord),
}

/// Input for completing a leased attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Typed complete outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteOutcome {
    Completed(AttemptRecord),
    AlreadyCompleted(AttemptRecord),
}

/// Input for failing a leased attempt terminally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Typed fail outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailOutcome {
    Failed(AttemptRecord),
    AlreadyFailed(AttemptRecord),
}

/// Input for finalizing a leased attempt and scheduling its next try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryAttempt {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Field spelling is retained for source compatibility; it becomes the new
    /// row's `scheduled_at`.
    pub backoff_until: u64,
    pub last_error: Option<String>,
    pub now: u64,
}

/// Typed retry outcome, carrying the newly scheduled try (not the finalized
/// source, which stays point-readable by its own id).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryOutcome {
    Retried(AttemptRecord),
}

/// Input for interrupting, pausing, resuming, or cancelling an attempt row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneAttempt {
    pub id: AttemptId,
    pub kind: AttemptInterventionKind,
    pub actor: String,
    pub note: Option<String>,
    pub now: u64,
}

/// Observable effect of an intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptInterventionEffect {
    Interrupted,
    Paused,
    AlreadyPaused,
    Resumed,
    AlreadyResumed,
    Cancelled,
    AlreadyCancelled,
}

impl AttemptInterventionEffect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupted => "interrupted",
            Self::Paused => "paused",
            Self::AlreadyPaused => "already_paused",
            Self::Resumed => "resumed",
            Self::AlreadyResumed => "already_resumed",
            Self::Cancelled => "cancelled",
            Self::AlreadyCancelled => "already_cancelled",
        }
    }
}

/// Typed intervention outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterveneOutcome {
    pub effect: AttemptInterventionEffect,
    pub record: AttemptRecord,
}

/// Input for the SOFT rung: asking a running attempt to stop.
///
/// Soft is a request, never a mutation to terminal: the worker answers by
/// landing or by refusing with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAttemptCancel {
    pub id: AttemptId,
    /// The asking actor. [`ATTEMPT_RUNTIME_ACTOR`] is refused here: only the
    /// runtime's own warning doors may author runtime rows.
    pub actor: String,
    /// Standing the CALLER resolved. [`CancelStanding::None`] is refused.
    pub standing: CancelStanding,
    pub trigger: LandingTrigger,
    pub reason: Option<String>,
    pub now: u64,
}

/// Typed soft-request outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelRequestOutcome {
    /// Durably recorded against a running attempt; the worker owes an answer.
    Requested {
        record: AttemptRecord,
        pressure: AttemptCancelPressure,
    },
    /// The worker already accepted a stop. Asking again is idempotent.
    AlreadyLanding(AttemptRecord),
    /// The attempt is already terminal; there is nothing to ask.
    AlreadySettled(AttemptRecord),
    /// The caller established no standing. The attempt is UNCHANGED and the
    /// caller must fall back to its own proposal path.
    NoStanding(AttemptRecord),
    /// No worker holds this row's lease, so nobody can answer: a pre-lease
    /// attempt has no response door at all (`accept_landing` and
    /// `reject_cancel` both require a claimed lease). The attempt is UNCHANGED
    /// and NOTHING is recorded — a pending request against a queued row would
    /// be an ask addressed to no one, which the pathology counters would then
    /// read as a worker refusing to answer. Pre-lease work is stopped by
    /// `tasks.cancel`'s queue cancellation, not by asking.
    NotRunning(AttemptRecord),
}

/// Input for a worker ACCEPTING a stop and entering [`AttemptState::Landing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptAttemptLanding {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub trigger: LandingTrigger,
    /// The worker's own status — a complete "green + pushed + packet-only"
    /// answer is a valid landing.
    pub status: Option<String>,
    /// The resume point, when the worker already knows it. It may also be
    /// recorded later, inside the landing.
    pub resume_point: Option<AttemptResumePoint>,
    /// Which outstanding request this landing answers, by its receipt
    /// `sequence`. `None` answers the OLDEST outstanding one, which is the only
    /// order in which "the ask that has waited longest" is a stable meaning.
    /// An unknown or already-answered sequence is refused.
    pub request_sequence: Option<u64>,
    pub now: u64,
}

/// Typed landing-acceptance outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandingOutcome {
    Landing(AttemptRecord),
    AlreadyLanding(AttemptRecord),
}

/// Input for a worker REFUSING a soft request while staying at work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectAttemptCancel {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Why the worker will not stop yet. Required: a refusal without a reason
    /// is indistinguishable from a worker that ignored the request.
    pub reason: String,
    pub status: Option<String>,
    /// Which outstanding request this refusal answers, by its receipt
    /// `sequence`. `None` answers the OLDEST outstanding one. Exactly one
    /// request is consumed, so the others keep their provenance and stay owed
    /// an answer.
    pub request_sequence: Option<u64>,
    pub now: u64,
}

/// Typed refusal outcome. The attempt stays [`AttemptState::Leased`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRejectionOutcome {
    pub record: AttemptRecord,
    pub pressure: AttemptCancelPressure,
    /// Repeated refusal has crossed
    /// [`SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`].
    pub pathology: bool,
    /// The `sequence` of the request this refusal actually answered.
    pub answered_request_sequence: u64,
}

/// Input for recording the exact resume point inside a landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAttemptResumePoint {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub resume_point: AttemptResumePoint,
    pub now: u64,
}

/// Input for spending landing reserve units under a lease fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendAttemptLandingReserve {
    pub id: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub units: u64,
    pub now: u64,
}

/// Typed reserve-spend outcome. Both arms are exact: nothing is ever partially
/// spent.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandingReserveSpendOutcome {
    Spent {
        record: AttemptRecord,
        remaining_units: u64,
    },
    /// The request does not fit the remaining reserve, so NOTHING was spent.
    Exhausted {
        record: AttemptRecord,
        requested_units: u64,
        remaining_units: u64,
    },
}

/// Input for dialing an attempt's budget and its landing reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DialLandingReserve {
    pub id: AttemptId,
    /// Total budget units for the attempt.
    pub limit_units: u64,
    /// Percent held back for landing. `None` uses [`LANDING_RESERVE_PERCENT`].
    pub reserve_percent: Option<u64>,
    pub now: u64,
}

/// Input for finishing a landing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishAttemptLanding {
    pub id: AttemptId,
    /// The lease still held by the landing worker. Fenced exactly like
    /// `complete`: a stranger may not end someone else's landing early and
    /// strand the work it had not finished.
    pub lease_owner: String,
    pub attempt_count: u32,
    /// Mint a successor row that resumes from the recorded resume point.
    /// Refused when no resume point was recorded.
    pub hand_off: bool,
    /// Instant the successor becomes claimable. `None` means immediately.
    pub scheduled_at: Option<u64>,
    pub now: u64,
}

/// Typed landing-completion outcome. Neither arm is `Completed`: a landing is
/// an honest stop, and the successor — not the landed row — carries the work.
///
/// Both rows ride the outcome by value, exactly as [`ClaimOutcome`] carries its
/// claimed record: a handoff caller needs the landed row's accounting AND the
/// successor's resume point, and boxing either would trade a real invariant for
/// a stack byte count.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum FinishLandingOutcome {
    Landed(AttemptRecord),
    HandedOff {
        landed: AttemptRecord,
        successor: AttemptRecord,
    },
}

/// Input for the HARD rung. The authority token is the authorization; there is
/// no actor string to forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceAttemptCancel {
    pub id: AttemptId,
    pub authority: ForceCancelAuthority,
    pub reason: Option<String>,
    pub now: u64,
}

/// Typed hard-cancel outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForceCancelOutcome {
    /// Terminal, unrefusable, runtime-authored.
    Cancelled(AttemptRecord),
    /// Idempotent replay of an already-forced stop.
    AlreadyCancelled(AttemptRecord),
    /// Already terminal in another disposition; live state is unchanged.
    AlreadySettled(AttemptRecord),
}

/// Input for the runtime's lease-expiry WARNING — distinct from expiry itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarnAttemptLeaseExpiry {
    pub id: AttemptId,
    /// The same timeout [`CleanupAttemptLeases`] reclaims against.
    pub lease_timeout_secs: u64,
    pub now: u64,
}

/// Typed lease-warning outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseWarningOutcome {
    /// Inside the lease, before the warning window. Nothing recorded.
    NotDue(AttemptRecord),
    /// A runtime-authored landing request was recorded.
    LandingRequested(AttemptRecord),
    /// A request is already outstanding, or the worker is already landing.
    AlreadyRequested(AttemptRecord),
    /// The lease already expired: that is cleanup's force path, not a warning.
    Expired(AttemptRecord),
}

/// Input for the runtime's QUOTA/BUDGET warning: the pass counter this attempt
/// draws on is inside its land window, so the runtime asks the worker to land
/// before it starts work the budget cannot finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarnAttemptBudgetPressure {
    pub id: AttemptId,
    pub now: u64,
}

/// Typed outcome of a runtime-authored landing warning.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandingWarningOutcome {
    /// A runtime-authored landing request was recorded against a leased row.
    LandingRequested(AttemptRecord),
    /// A request is already outstanding, or the worker is already landing.
    /// Warning again would inflate the pressure counters that make repeated
    /// refusal legible.
    AlreadyRequested(AttemptRecord),
    /// No worker holds the lease, so there is nobody to warn.
    NotRunning(AttemptRecord),
}

/// Input for the runtime's lease-expiry warning SWEEP over live leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarnExpiringAttemptLeases {
    pub now: u64,
    /// The same timeout [`CleanupAttemptLeases`] reclaims against, so the
    /// warning window is derived from the very deadline that would otherwise
    /// take the work away.
    pub lease_timeout_secs: u64,
}

/// What one lease-warning sweep observed. Deliberately separate from
/// [`AttemptQueueCleanupReport`]: warning and expiry are different rungs, and a
/// warned lease is still live work, not reclaimed work.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttemptLeaseWarningReport {
    /// Leased rows inspected.
    pub scanned: u64,
    /// Rows that got a fresh runtime landing request.
    pub warned: u64,
    /// Rows already carrying an unanswered ask, or already landing.
    pub already_requested: u64,
    /// Rows still inside their lease and before the warning window.
    pub not_due: u64,
    /// Rows already past expiry: cleanup's hard rung, never a warning.
    pub expired: u64,
}

/// Input for returning stale leased attempts to the ready index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupAttemptLeases {
    /// Current wall-clock seconds chosen by the caller.
    pub now: u64,
    /// A leased attempt expires when `now - updated_at >= lease_timeout_secs`.
    pub lease_timeout_secs: u64,
}

/// Privacy-stable retry reason classes reported by attempt-queue cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptQueueRetryReason {
    LeaseTimeout,
    RetryBackoff,
}

impl AttemptQueueRetryReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseTimeout => "lease_timeout",
            Self::RetryBackoff => "retry_backoff",
        }
    }

    pub(super) const fn metric_index(self) -> usize {
        match self {
            Self::LeaseTimeout => 0,
            Self::RetryBackoff => 1,
        }
    }

    pub(super) const fn metric_values() -> [Self; ATTEMPT_QUEUE_RETRY_REASON_COUNT] {
        [Self::LeaseTimeout, Self::RetryBackoff]
    }
}

/// Count for one privacy-stable retry reason class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptQueueRetryReasonCount {
    pub reason: AttemptQueueRetryReason,
    pub count: u64,
}

impl AttemptQueueRetryReasonCount {
    const fn zero(reason: AttemptQueueRetryReason) -> Self {
        Self { reason, count: 0 }
    }
}

/// Queue cleanup report shaped for runner and run-tree surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptQueueCleanupReport {
    pub pending: u64,
    pub running: u64,
    pub failed: u64,
    pub done: u64,
    pub stale_requeued: u64,
    /// Landing rows whose lease expired mid-landing and were force-cancelled.
    /// A landing cannot be requeued as ordinary work, so it cannot be part of
    /// `stale_requeued`.
    pub landing_force_cancelled: u64,
    pub retry_reasons: [AttemptQueueRetryReasonCount; ATTEMPT_QUEUE_RETRY_REASON_COUNT],
}

impl Default for AttemptQueueCleanupReport {
    fn default() -> Self {
        Self {
            pending: 0,
            running: 0,
            failed: 0,
            done: 0,
            stale_requeued: 0,
            landing_force_cancelled: 0,
            retry_reasons: AttemptQueueRetryReason::metric_values()
                .map(AttemptQueueRetryReasonCount::zero),
        }
    }
}

impl AttemptQueueCleanupReport {
    #[must_use]
    pub fn retry_reason_count(&self, reason: AttemptQueueRetryReason) -> u64 {
        self.retry_reasons[reason.metric_index()].count
    }

    pub(super) fn increment_retry_reason(&mut self, reason: AttemptQueueRetryReason) {
        self.retry_reasons[reason.metric_index()].count += 1;
    }
}

pub(crate) fn attempt_record_order(
    left: &AttemptRecord,
    right: &AttemptRecord,
) -> std::cmp::Ordering {
    left.created_at
        .cmp(&right.created_at)
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}
