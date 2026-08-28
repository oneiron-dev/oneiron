//! Commitment schedule evaluation and durable projection (CMT-2, ONE-1539).
//!
//! CMT-1 ([`crate::commitment`]) stores the obligation as a type-0
//! `commitment.record` CLAIM whose `schedule` field is an OPAQUE
//! [`rmpv::Value`]. This module is the sibling that gives those bytes meaning
//! without touching the storage shape: a strict versioned MessagePack codec
//! into that same opaque slot, a pure evaluator over the shared recurrence
//! vocabulary, and a durable due-index projection built on the `vault_meta`
//! sidecar.
//!
//! Three rules shape everything here.
//!
//! * **The recurrence vocabulary is shared, not forked.** [`Schedule`] is
//!   re-exported verbatim from `oneiron_vault_contract::commitment` — the ICS
//!   poll cadence of ARCH-0060 [CAL-02] is an [`Schedule::Interval`] on THIS
//!   enum, and there is exactly one recurrence implementation with two
//!   consumers ([CAL-03]).
//! * **Series linkage lives inside the payload.** A series and its instances
//!   are related by `series_ref`/`occurrence` fields in the opaque value, never
//!   by a new [`crate::edge::EdgeKind`]. A series EDIT is a replacement claim
//!   plus the canonical `Supersedes` edge, which is a lifecycle mechanic that
//!   already exists.
//! * **There is no scheduler.** ARCH-0026 stands: nothing in this module polls,
//!   sleeps, or owns a thread. [`Vault::reconcile_commitment_schedule`] is the
//!   sole production projector and it runs INSIDE a driver deadline read.
//!
//! Rrule decodes but never evaluates in v1. Expansion is the calendar layer's
//! job ([`CAL_RRULE_ROUTE`]); a second parser vendored here is precisely the
//! fork the shared vocabulary exists to prevent, so the arm returns
//! [`ScheduleError::RruleNotImplemented`] and names the route instead.

mod due;
mod payload;
mod projection;

#[cfg(test)]
mod tests;

pub use due::{CommitmentDueEntry, CommitmentDueIndexSnapshot, CommitmentDuePhase};
pub use projection::{CommitmentProjectionReport, CommitmentSeriesWriteOutcome};

pub use oneiron_vault_contract::commitment::{QuotaWindow, Schedule};

use crate::calendar::CalendarError;
use crate::calendar::tz::{WallTime, utc_to_wall, wall_to_utc};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::commitment::CommitmentStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

/// Default projection lead: one day before the due instant.
pub const DEFAULT_LEAD: u64 = 86_400;

/// Upper bound on a [`Schedule::Quota`] count. A quota is a promise, not a
/// batch job; a four-figure count is a caller bug, and minting one window's
/// worth of instances in a single transaction makes the bound load-bearing.
pub const COMMITMENT_QUOTA_MAX_COUNT: u32 = 100;

/// Version of the MessagePack payload written into `CommitmentRecord.schedule`.
pub const COMMITMENT_SCHEDULE_PAYLOAD_SCHEMA_VERSION: u64 = 1;

/// Where an rrule schedule must be expanded. Named, not implemented: the
/// engine's one recurrence expander lives at this path (ONE-1785), and the
/// future route calls it rather than vendoring a second parser.
pub const CAL_RRULE_ROUTE: &str = "oneiron::calendar::expand_window";

/// Byte bound on every string inside a schedule payload (tz names, rrule text).
pub(crate) const COMMITMENT_SCHEDULE_STRING_MAX_BYTES: usize = 1_024;

/// BLAKE3 domain for the pinned System actor that owns engine projection
/// writes. Derived, not minted: the projector's identity must survive a reopen
/// and be the same on every device.
const COMMITMENT_PROJECTION_ACTOR_DOMAIN: &[u8] = b"oneiron.commitment.projection.actor.v1\0";

/// Provenance string stamped on every instance the projector mints.
pub const COMMITMENT_PROJECTION_PROVENANCE: &str = "oneiron.commitment.projection.v1";

/// BLAKE3 domain for deterministic instance ids.
const COMMITMENT_INSTANCE_ID_DOMAIN: &[u8] = b"oneiron.commitment.instance.v1\0";

/// Everything that can go wrong evaluating or projecting a schedule.
///
/// Deliberately its own type rather than more [`crate::Error`] arms: the
/// evaluator is pure and must be usable (and testable) without a vault, and
/// the rrule deferral needs to carry its route. [`From<ScheduleError>`] maps
/// back into the engine error for the callers that only speak
/// [`crate::Result`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScheduleError {
    /// A storage or claim-layer failure surfaced verbatim.
    #[error(transparent)]
    Engine(#[from] crate::Error),
    /// A time-zone conversion failed at the calendar border.
    #[error(transparent)]
    Calendar(#[from] CalendarError),
    /// The schedule or the request is structurally wrong.
    #[error("invalid commitment schedule: {0}")]
    Invalid(&'static str),
    /// A due/successor computation left the `u64` time model. Never wrapped,
    /// never saturated — an additive overflow is a typed refusal.
    #[error("commitment schedule arithmetic overflow")]
    ArithmeticOverflow,
    /// The schedule is an rrule. It decoded fine; evaluating it is the
    /// calendar layer's job and v1 does not route there yet.
    #[error("rrule schedules are expanded by {route}, not by the commitment evaluator")]
    RruleNotImplemented {
        /// The calendar entry point that owns expansion.
        route: &'static str,
    },
    /// The opaque schedule bytes are not a valid CMT-2 payload.
    #[error("invalid commitment schedule payload")]
    InvalidPayload,
    /// A deterministic instance id already exists carrying a DIFFERENT
    /// identity. Never coalesced: a matching retry is idempotent, a mismatch
    /// is a refusal.
    #[error("commitment instance id names a different identity")]
    InstanceIdentityCollision,
}

impl From<ScheduleError> for crate::Error {
    fn from(error: ScheduleError) -> Self {
        match error {
            ScheduleError::Engine(inner) => inner,
            ScheduleError::Calendar(_) => {
                Self::InvariantViolation("commitment schedule calendar conversion failed")
            }
            ScheduleError::Invalid(reason) => Self::InvariantViolation(reason),
            ScheduleError::ArithmeticOverflow => {
                Self::InvariantViolation("commitment schedule arithmetic overflow")
            }
            ScheduleError::RruleNotImplemented { .. } => {
                Self::InvariantViolation("commitment rrule schedule requires calendar expansion")
            }
            ScheduleError::InvalidPayload => {
                Self::InvariantViolation("commitment schedule payload is invalid")
            }
            ScheduleError::InstanceIdentityCollision => {
                Self::InvariantViolation("commitment instance id names a different identity")
            }
        }
    }
}

/// Result alias for the schedule layer.
pub type ScheduleResult<T> = std::result::Result<T, ScheduleError>;

/// One concrete occurrence of a series: the instant it is owed, the valid-time
/// window it covers, and which slot of that window it is.
///
/// `ordinal` matters only for [`Schedule::Quota`], where every slot of a window
/// shares one due instant (the window's inclusive end) and is distinguished
/// solely by its position. Once/Interval occurrences are always ordinal 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitmentOccurrence {
    /// When this occurrence is owed.
    pub due_at: u64,
    /// The occurrence's valid-time window; must contain `due_at`.
    pub window: TimeRange,
    /// Slot index inside `window`.
    pub ordinal: u32,
}

impl CommitmentOccurrence {
    /// Creates an occurrence, rejecting an inverted window or a `due_at`
    /// outside it.
    pub fn new(due_at: u64, window: TimeRange, ordinal: u32) -> ScheduleResult<Self> {
        let occurrence = Self {
            due_at,
            window,
            ordinal,
        };
        occurrence.validate()?;
        Ok(occurrence)
    }

    pub(crate) fn validate(&self) -> ScheduleResult<()> {
        if self.window.end < self.window.start {
            return Err(ScheduleError::Invalid(
                "commitment occurrence window is inverted",
            ));
        }
        if self.due_at < self.window.start || self.due_at > self.window.end {
            return Err(ScheduleError::Invalid(
                "commitment occurrence window must contain its due instant",
            ));
        }
        Ok(())
    }
}

/// The typed payload the CMT-2 codec writes into `CommitmentRecord.schedule`.
///
/// Exactly two legal shapes, and the codec enforces the pairing:
///
/// * **SERIES** — `series_ref` and `occurrence` both absent. The recurrence
///   itself; the thing the projector reads.
/// * **INSTANCE** — both present. One materialized occurrence pointing back at
///   its series. This is the only linkage; there is no series edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentSchedulePayload {
    /// The recurrence. An instance carries a copy of its series' schedule so
    /// the close hook can compute a successor from the instance alone.
    pub schedule: Schedule,
    /// Projection lead in seconds. `None` means [`DEFAULT_LEAD`]; `Some(0)`
    /// projects exactly at the due instant.
    pub lead_seconds: Option<u64>,
    /// The series this instance belongs to. Absent on a series.
    pub series_ref: Option<EntityId>,
    /// Which occurrence this instance is. Absent on a series.
    pub occurrence: Option<CommitmentOccurrence>,
}

impl CommitmentSchedulePayload {
    /// Builds a SERIES payload.
    #[must_use]
    pub const fn series(schedule: Schedule, lead_seconds: Option<u64>) -> Self {
        Self {
            schedule,
            lead_seconds,
            series_ref: None,
            occurrence: None,
        }
    }

    /// Builds an INSTANCE payload.
    #[must_use]
    pub const fn instance(
        schedule: Schedule,
        lead_seconds: Option<u64>,
        series_ref: EntityId,
        occurrence: CommitmentOccurrence,
    ) -> Self {
        Self {
            schedule,
            lead_seconds,
            series_ref: Some(series_ref),
            occurrence: Some(occurrence),
        }
    }

    /// The effective lead, defaulting to [`DEFAULT_LEAD`].
    #[must_use]
    pub const fn lead_seconds(&self) -> u64 {
        match self.lead_seconds {
            Some(lead) => lead,
            None => DEFAULT_LEAD,
        }
    }

    /// Whether this payload is a series head.
    #[must_use]
    pub const fn is_series(&self) -> bool {
        self.series_ref.is_none() && self.occurrence.is_none()
    }

    /// Whether this payload is a materialized instance.
    #[must_use]
    pub const fn is_instance(&self) -> bool {
        self.series_ref.is_some() && self.occurrence.is_some()
    }

    /// Encodes to the opaque MessagePack value CMT-1 stores.
    pub fn encode(&self) -> ScheduleResult<rmpv::Value> {
        payload::encode_schedule_payload(self)
    }

    /// Decodes an opaque `CommitmentRecord.schedule` value.
    ///
    /// # Errors
    ///
    /// [`ScheduleError::InvalidPayload`] for anything that is not a strict
    /// CMT-2 payload — including a plain CMT-1 schedule blob, which is a
    /// legitimate thing to find and is never mistaken for a broken one.
    pub fn decode(value: &rmpv::Value) -> ScheduleResult<Self> {
        payload::decode_schedule_payload(value)
    }
}

/// One already-known occurrence of a series, as [`next_due`] sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleHistoryEntry {
    /// The instance claim id.
    pub instance_ref: EntityId,
    /// The instant that instance was owed.
    pub due_at: u64,
    /// The instance's valid-time window.
    pub window: TimeRange,
    /// Slot index inside `window`.
    pub ordinal: u32,
    /// The instance's CMT-1 status.
    pub status: CommitmentStatus,
}

impl ScheduleHistoryEntry {
    /// Whether this occurrence is still open.
    #[must_use]
    pub const fn is_open(&self) -> bool {
        matches!(self.status, CommitmentStatus::Open)
    }
}

/// How an instance closed.
///
/// The distinction that matters is quota accounting: only [`Self::Fulfilled`]
/// COMPLETES a slot. A lapse, a release, and a supersession all close the row
/// without the promise having been kept, and none of them earns a replacement
/// slot inside the same window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommitmentInstanceOutcome {
    /// The promise was kept.
    Fulfilled,
    /// The window closed without it being kept.
    Lapsed,
    /// The obligation was let go.
    Released,
    /// A replacement took its place.
    Superseded,
}

impl CommitmentInstanceOutcome {
    /// The CMT-1 status this outcome corresponds to.
    #[must_use]
    pub const fn status(self) -> CommitmentStatus {
        match self {
            Self::Fulfilled => CommitmentStatus::Fulfilled,
            Self::Lapsed => CommitmentStatus::Lapsed,
            Self::Released => CommitmentStatus::Released,
            Self::Superseded => CommitmentStatus::Superseded,
        }
    }

    /// Whether this outcome completes a quota slot.
    #[must_use]
    pub const fn completes_slot(self) -> bool {
        matches!(self, Self::Fulfilled)
    }
}

/// The pinned System actor for engine projection writes.
///
/// Derived from a fixed domain string so every device and every reopen agrees,
/// with the same sentinel-perturbation fallback the rest of the crate uses for
/// derived ids.
#[must_use]
pub fn commitment_projection_actor() -> WriteActor {
    WriteActor::new(
        derive_entity_id(COMMITMENT_PROJECTION_ACTOR_DOMAIN, &[]),
        EdgeActorClass::System,
    )
}

/// The pinned envelope every projected instance is written under: System actor,
/// `Generated` source, a fixed provenance string, and `Auto` approval.
///
/// `Auto` is deliberate and narrow: the projector materializes an occurrence of
/// an obligation the OWNER already consented to when the series was written. It
/// is not a new fact, so it does not open a new consent question — no
/// pending-consent row is created for a mint.
pub fn commitment_projection_envelope() -> crate::Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        commitment_projection_actor(),
        ClaimSource::Generated,
        WriteProvenance::new(rmpv::Value::from(COMMITMENT_PROJECTION_PROVENANCE))?,
        ClaimApprovalStatus::Auto,
    ))
}

/// The deterministic id of one occurrence of one series.
///
/// The transcript is pinned: domain ‖ series_ref(16) ‖ due_at(u64 BE) ‖
/// window.start(BE) ‖ window.end(BE) ‖ ordinal(u32 BE), and the id is the FIRST
/// 16 raw BLAKE3 bytes — no RFC-4122 version/variant rewrite, because a rewrite
/// would make the id unreproducible from the transcript alone. A prefix landing
/// on a reserved sentinel (~2^-120) is perturbed by XOR-ing `0x01` into bytes 0
/// and 15 rather than falling back to a random id.
#[must_use]
pub fn commitment_instance_id(series_ref: &EntityId, occurrence: &CommitmentOccurrence) -> EntityId {
    let mut transcript = Vec::with_capacity(16 + 8 + 8 + 8 + 4);
    transcript.extend_from_slice(series_ref.as_bytes());
    transcript.extend_from_slice(&occurrence.due_at.to_be_bytes());
    transcript.extend_from_slice(&occurrence.window.start.to_be_bytes());
    transcript.extend_from_slice(&occurrence.window.end.to_be_bytes());
    transcript.extend_from_slice(&occurrence.ordinal.to_be_bytes());
    derive_entity_id(COMMITMENT_INSTANCE_ID_DOMAIN, &transcript)
}

fn derive_entity_id(domain: &[u8], body: &[u8]) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(body);
    let mut raw = [0_u8; 16];
    raw.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(raw).unwrap_or_else(|_| {
        raw[0] ^= 0x01;
        raw[15] ^= 0x01;
        EntityId::from_bytes(raw).expect("perturbed derived commitment id is non-reserved")
    })
}

/// The next instant this schedule is owed, given everything already known
/// about it.
///
/// PURE: no LMDB, no clock read, no allocation of durable state. `history` is
/// the caller's view of the series' already-materialized occurrences, in any
/// order.
///
/// * [`Schedule::Once`] — `Some(due)` while unmaterialized, EVEN IF `due` is
///   already in the past (an overdue single promise is still owed); `None`
///   once any occurrence exists.
/// * [`Schedule::Interval`] — with no history, the anchor itself if it has not
///   passed, otherwise the first anchor-grid point at or after `now`. With
///   history, the greatest known occurrence plus one period, so a retainer
///   cycle anchors to the LAST due instant and cannot drift off the grid by
///   accumulating close-time offsets.
/// * [`Schedule::Quota`] — the inclusive end of the ISO week that still owes
///   slots, computed in the window's own zone.
/// * [`Schedule::Rrule`] — [`ScheduleError::RruleNotImplemented`], without
///   parsing the rule text.
///
/// # Errors
///
/// Returns [`ScheduleError::Invalid`] for a malformed schedule or a stored
/// occurrence that is not on the schedule's grid — a non-congruent occurrence
/// is rejected rather than quietly re-basing the series onto it.
pub fn next_due(
    schedule: &Schedule,
    now: u64,
    history: &[ScheduleHistoryEntry],
) -> ScheduleResult<Option<u64>> {
    match schedule {
        Schedule::Once { due } => Ok(history.is_empty().then_some(*due)),
        Schedule::Interval { period, anchor } => next_interval_due(*period, *anchor, now, history),
        Schedule::Quota { count, window } => next_quota_due(*count, window, now, history),
        Schedule::Rrule { .. } => Err(ScheduleError::RruleNotImplemented {
            route: CAL_RRULE_ROUTE,
        }),
    }
}

fn next_interval_due(
    period: u64,
    anchor: u64,
    now: u64,
    history: &[ScheduleHistoryEntry],
) -> ScheduleResult<Option<u64>> {
    if period == 0 {
        return Err(ScheduleError::Invalid(
            "interval schedule period must be positive",
        ));
    }
    let Some(last) = history.iter().map(|entry| entry.due_at).max() else {
        if anchor >= now {
            return Ok(Some(anchor));
        }
        // Checked ceil-division onto the anchor grid: the first grid point at
        // or after `now`, never a walk.
        let elapsed = now - anchor;
        let steps = elapsed.div_ceil(period);
        return steps
            .checked_mul(period)
            .and_then(|offset| anchor.checked_add(offset))
            .map(Some)
            .ok_or(ScheduleError::ArithmeticOverflow);
    };
    if last < anchor || (last - anchor) % period != 0 {
        return Err(ScheduleError::Invalid(
            "interval occurrence is not on the schedule grid",
        ));
    }
    last.checked_add(period)
        .map(Some)
        .ok_or(ScheduleError::ArithmeticOverflow)
}

fn next_quota_due(
    count: u32,
    window: &QuotaWindow,
    now: u64,
    history: &[ScheduleHistoryEntry],
) -> ScheduleResult<Option<u64>> {
    validate_quota_count(count)?;
    let QuotaWindow::IsoWeek { tz } = window;
    let current = iso_week_window(now, tz)?;
    let slots: Vec<&ScheduleHistoryEntry> = history
        .iter()
        .filter(|entry| entry.window.start == current.start)
        .collect();
    let minted = u32::try_from(slots.len()).unwrap_or(u32::MAX);
    if minted < count || slots.iter().any(|entry| entry.is_open()) {
        return Ok(Some(current.end));
    }
    // Every slot in this week is terminal: the quota rolls to the NEXT week,
    // and only the next one. Skipped weeks are never back-filled.
    let following = iso_week_window(current.end.saturating_add(1), tz)?;
    Ok(Some(following.end))
}

pub(crate) fn validate_quota_count(count: u32) -> ScheduleResult<()> {
    if count == 0 || count > COMMITMENT_QUOTA_MAX_COUNT {
        return Err(ScheduleError::Invalid("quota count exceeds maximum"));
    }
    Ok(())
}

/// The ISO week (Monday 00:00 local, inclusive, through the instant before the
/// following Monday 00:00 local) containing `at`, in `tz`.
///
/// USER-LOCAL by construction. A week is never `now / 604_800`: that stride
/// starts on a Thursday in UTC and ignores the owner's zone entirely, so a
/// quota computed that way would roll over at the wrong moment for everyone.
/// Both borders go through the calendar layer's single conversion seam.
pub(crate) fn iso_week_window(at: u64, tz: &str) -> ScheduleResult<TimeRange> {
    let wall = utc_to_wall(at, tz)?;
    let days = days_from_civil(i64::from(wall.y), wall.mo, wall.d);
    // days_from_civil is epoch-anchored at 1970-01-01, a Thursday, so
    // rem_euclid(7) yields 0 = Thursday; shifting by 3 makes 0 = Monday.
    let weekday_from_monday = (days + 3).rem_euclid(7);
    let monday = civil_from_days(days - weekday_from_monday);
    let next_monday = civil_from_days(days - weekday_from_monday + 7);
    let start = wall_to_utc(&midnight(monday), tz)?;
    let next_start = wall_to_utc(&midnight(next_monday), tz)?;
    if next_start <= start {
        return Err(ScheduleError::Invalid("iso week window is inverted"));
    }
    Ok(TimeRange {
        start,
        end: next_start - 1,
    })
}

const fn midnight((y, mo, d): (i32, u8, u8)) -> WallTime {
    WallTime {
        y,
        mo,
        d,
        h: 0,
        mi: 0,
        s: 0,
    }
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Hinnant).
fn days_from_civil(y: i64, m: u8, d: u8) -> i64 {
    let m = i64::from(m);
    let d = i64::from(d);
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i32, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        i32::try_from(if m <= 2 { y + 1 } else { y }).unwrap_or(i32::MAX),
        u8::try_from(m).unwrap_or(1),
        u8::try_from(d).unwrap_or(1),
    )
}
