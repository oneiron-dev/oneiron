//! ONE-1823 [BK-00] availability solver and slot-mask projection.
//!
//! [`BookingSolver`] is the real [`SlotOracle`]: it binds a vault, a booking
//! page, the request-time host→calendar selector binding, and a request-time
//! `now_utc`, then runs one deterministic, side-effect-free pipeline of eight
//! pure stages, in this order:
//!
//! 1. [`working_hours_mask`] — host wall windows become UTC intervals.
//! 2. [`attach_busy_union`] — CAL's normalized busy union joins each host.
//! 3. [`apply_buffers`] — busy intervals grow by the required meeting gap.
//! 4. [`enforce_notice_and_window`] — minimum notice and booking horizon clip.
//! 5. [`apply_event_type_knobs`] — candidates are cut on the step grid and
//!    charged against the visitor-local daily/weekly caps.
//! 6. [`subtract_live_holds`] — unexpired holds remove candidates.
//! 7. [`route_host_masks`] — `Either` unions the hosts, `Both` intersects them.
//! 8. [`rank_and_emit`] — the visitor's constraint filters, the ranking orders,
//!    and the result leaves in UTC.
//!
//! Every stage is a pure function of its arguments. Storage and the network are
//! touched exactly once each, before stage 1, so the pipeline is reproducible
//! from its inputs alone.
//!
//! # Interval convention
//!
//! [`TimeRange`] is inclusive on both ends in the engine core, and every
//! interval crossing a stage boundary HERE is half-open `[start, end)` — the
//! convention CAL's [`BusyInterval`](crate::calendar::BusyInterval) and the
//! seam's [`SlotMask`] already use. The conversion therefore happens exactly
//! twice: once when [`SolveRequest::window`] is ingested, and once when the
//! window is handed back to CAL's `freebusy`. Nothing in between mixes the two.
//!
//! # Time zones
//!
//! The core is `u64` UTC. Every IANA conversion goes through
//! [`crate::calendar::tz`], the engine's one border, so no third-party time
//! type appears in any signature here. Host wall windows convert forward
//! ([`wall_to_utc`]); visitor-local placement — caps, constraint weekdays and
//! local windows — converts backward ([`utc_to_wall`]), which is total and so
//! never invents an instant.

use serde::{Deserialize, Serialize};

use crate::booking::config::{
    DAYS_PER_WEEK, EventTypeConfig, MINUTES_PER_DAY, RoutingMode, load_event_type_config,
};
use crate::booking::constraint::{ConstraintWeekday, validate_visitor_tz};
use crate::booking::{
    BookingError, ConstraintObject, EventTypeKey, RankedSlot, SlotMask, SlotOracle, SolveRequest,
    SolveResult,
};
use crate::calendar::CalendarError;
use crate::calendar::freebusy::{BusyUnion, freebusy};
use crate::calendar::query::CalendarSel;
use crate::calendar::tz::{WallTime, utc_to_wall, wall_to_utc};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Seconds in a minute — the unit every configuration knob is written in.
const SECS_PER_MINUTE: u64 = 60;

/// Rank of a slot inside a host's preferred hours.
const PREFERRED_RANK: f32 = 1.0;

/// Rank of a slot that is merely bookable.
const ORDINARY_RANK: f32 = 0.5;

/// Days from the UNIX epoch to Monday of the epoch week. `1970-01-01` was a
/// Thursday, so a Monday-anchored week index is `(days + 3) / 7`.
const EPOCH_WEEKDAY_OFFSET: i64 = 3;

// -------------------------------------------------------------------------
// Confirmed-booking counts
// -------------------------------------------------------------------------

/// Confirmed bookings inside one visitor-local period.
///
/// The bucket's own UTC span is what a caller reads; which cap it is charged
/// against is decided from `window_start_utc`'s visitor-local day, so a table
/// built in one zone cannot be silently applied in another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCountBucket {
    pub window_start_utc: u64,
    /// Half-open `[window_start_utc, window_end_utc)`.
    pub window_end_utc: u64,
    pub confirmed: u16,
}

/// The typed cap input. Sparse by construction: a period with no bucket has no
/// confirmed bookings, which is zero, not unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCounts {
    pub daily: Vec<BookingCountBucket>,
    pub weekly: Vec<BookingCountBucket>,
}

/// Loads confirmed-booking counts for `(page_ref, event_type)` over `window`.
///
/// STACK SEAM. Confirmed bookings live in the session-keyed lifecycle rows
/// ONE-1813 lands in BK-A layer 2; on this layer there is no such store, so
/// there is nothing to count and the table is empty. An empty table binds no
/// cap — deliberately, because a missing bucket is zero confirmed bookings.
/// The visitor-local day/week identity that decides which bucket a candidate is
/// charged against lives in the cap stage, so layer 2 supplies `confirmed` here
/// and changes nothing else.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] once layer 2 reads storage here.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the fallible signature is the ratified layer-2 contract; the lint \
              fires only while the body is storage-free, and unfulfilling it is \
              how ONE-1813 is told to delete this attribute"
)]
pub(crate) fn load_booking_counts(
    _vault: &Vault,
    _page_ref: EntityId,
    _event_type: &EventTypeKey,
    _window: TimeRange,
    _visitor_tz: &str,
) -> Result<BookingCounts, BookingError> {
    Ok(BookingCounts {
        daily: Vec::new(),
        weekly: Vec::new(),
    })
}

// -------------------------------------------------------------------------
// Live holds
// -------------------------------------------------------------------------

/// The narrow read the solver needs from the hold store.
///
/// Ranges are half-open `[start, end)`, matching the rest of this module.
/// `exclude_session_key` lets the session that is confirming its own hold see
/// the slot it already reserved, so a confirm never fails against itself.
///
/// `Send + Sync` for the same reason [`SlotOracle`] carries them: a
/// [`BookingSolver`] holds `&dyn ActiveHoldSource`, and a solver that is not
/// `Sync` cannot be a `SlotOracle` at all.
pub trait ActiveHoldSource: Send + Sync {
    /// Unexpired holds on `page_ref` overlapping `window` as of `now_utc`.
    ///
    /// # Errors
    ///
    /// [`BookingError::SlotOracle`] when the hold store cannot be read.
    fn active_holds(
        &self,
        page_ref: EntityId,
        window: TimeRange,
        now_utc: u64,
        exclude_session_key: Option<&[u8; 32]>,
    ) -> Result<Vec<TimeRange>, BookingError>;
}

/// A page with no hold store.
///
/// BK-A layer 1's stack scaffolding: ONE-1813 supplies the vault-meta
/// implementation in layer 2 without changing the solver contract. This is not
/// a second hold store — it holds nothing.
pub struct NoActiveHolds;

impl ActiveHoldSource for NoActiveHolds {
    fn active_holds(
        &self,
        _page_ref: EntityId,
        _window: TimeRange,
        _now_utc: u64,
        _exclude_session_key: Option<&[u8; 32]>,
    ) -> Result<Vec<TimeRange>, BookingError> {
        Ok(Vec::new())
    }
}

// -------------------------------------------------------------------------
// The solver
// -------------------------------------------------------------------------

/// The production [`SlotOracle`].
pub struct BookingSolver<'a> {
    pub vault: &'a Vault,
    /// The booking-page subject. For page-less presets (ONE-1821) this is the
    /// companion/owner scoping subject; it is used only to scope holds, counts,
    /// and the configuration claim.
    pub page_ref: EntityId,
    /// Request-time host→calendar selector binding. CAL is asked once per host,
    /// so a host's availability is never contaminated by another host's feed.
    pub calendars_by_host: &'a [(EntityId, Vec<CalendarSel>)],
    pub holds: &'a dyn ActiveHoldSource,
    pub now_utc: u64,
    /// Synthetic-configuration arm (ONE-1821 companion presets): when `Some`,
    /// the solve uses this configuration verbatim and never reads a
    /// `booking.event_type` claim, because a page-less preset has none. When
    /// `None`, the configuration resolves from the page claim.
    pub synthetic_config: Option<EventTypeConfig>,
}

impl SlotOracle for BookingSolver<'_> {
    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        // The visitor zone is validated at the calendar border, not guessed:
        // a malformed zone fails typed here rather than falling back to UTC.
        validate_visitor_tz(&req.visitor_tz)?;
        utc_to_wall(self.now_utc, &req.visitor_tz).map_err(visitor_zone_error)?;
        if let Some(constraint) = &req.constraint {
            constraint.validate()?;
        }

        let window = half_open(req.window)?;
        let config = match &self.synthetic_config {
            Some(config) => config.clone(),
            None => load_event_type_config(self.vault, self.page_ref, &req.event_type)?,
        };
        config.validate()?;
        if config.key != req.event_type {
            return Err(BookingError::InvalidConfig(format!(
                "configuration is for event type {}, not {}",
                config.key.0, req.event_type.0
            )));
        }

        let busy_by_host = self.busy_by_host(&config, window)?;
        let counts = load_booking_counts(
            self.vault,
            self.page_ref,
            &req.event_type,
            req.window,
            &req.visitor_tz,
        )?;
        let holds = self
            .holds
            .active_holds(self.page_ref, window, self.now_utc, None)?;

        let primary = run_pipeline(
            &config,
            &busy_by_host,
            window,
            req,
            &counts,
            &holds,
            self.now_utc,
        )?;
        // The flex pool surfaces only after the ordinary mask comes back empty,
        // and only when the visitor's constraint allows it. Re-running the whole
        // pipeline on the widened configuration — rather than threading a flag
        // through eight stages — is what keeps every stage a pure function of a
        // single configuration.
        if !primary.slots.is_empty()
            || config.flex_windows.is_empty()
            || !req
                .constraint
                .as_ref()
                .is_none_or(|constraint| constraint.allow_flex_pool)
        {
            return Ok(primary);
        }
        let mut fallback = run_pipeline(
            &with_flex_pool(&config),
            &busy_by_host,
            window,
            req,
            &counts,
            &holds,
            self.now_utc,
        )?;
        fallback.flex_used = !fallback.slots.is_empty();
        Ok(fallback)
    }
}

impl BookingSolver<'_> {
    /// Asks CAL for one busy union per host.
    ///
    /// An unbound host is a wiring defect, not a free host: an absent projection
    /// must never read as "available all day". A binding that resolved to NO
    /// selectors is the same defect and is refused the same way — an empty
    /// selector slice asks `freebusy` for the unfiltered all-calendar union, so
    /// accepting it would make every event in the vault that host's busy time.
    fn busy_by_host(
        &self,
        config: &EventTypeConfig,
        window: TimeRange,
    ) -> Result<Vec<(EntityId, BusyUnion)>, BookingError> {
        config
            .hosts
            .iter()
            .map(|host| {
                let selectors = self
                    .calendars_by_host
                    .iter()
                    .find(|(id, _)| *id == host.host_ref)
                    .map(|(_, selectors)| selectors.as_slice())
                    .filter(|selectors| !selectors.is_empty())
                    .ok_or_else(|| {
                        BookingError::InvalidConfig(format!(
                            "host {} has no calendar selector binding",
                            host.host_ref.to_hex()
                        ))
                    })?;
                let union = freebusy(self.vault, selectors, inclusive(window))
                    .map_err(|error| BookingError::SlotOracle(format!("freebusy: {error}")))?;
                Ok((host.host_ref, union))
            })
            .collect()
    }
}

/// The eight stages, in the ratified order.
fn run_pipeline(
    config: &EventTypeConfig,
    busy_by_host: &[(EntityId, BusyUnion)],
    window: TimeRange,
    req: &SolveRequest,
    counts: &BookingCounts,
    holds: &[TimeRange],
    now_utc: u64,
) -> Result<SolveResult, BookingError> {
    let hours = working_hours_mask(config, window)?;
    let attached = attach_busy_union(hours, busy_by_host.to_vec())?;
    let buffered = apply_buffers(attached, config);
    let noticed = enforce_notice_and_window(buffered, now_utc, window, config);
    let knobbed = apply_event_type_knobs(noticed, config, &req.visitor_tz, counts);
    let held = subtract_live_holds(knobbed, holds);
    let routed = route_host_masks(held, config.routing);
    Ok(rank_and_emit(
        routed,
        config,
        req.constraint.as_ref(),
        &req.visitor_tz,
        counts,
    ))
}

/// The configuration the flex fallback runs on: every host's working hours
/// widened by the shared flex windows, read in that host's own zone.
fn with_flex_pool(config: &EventTypeConfig) -> EventTypeConfig {
    let mut widened = config.clone();
    for host in &mut widened.hosts {
        host.working_hours
            .extend(config.flex_windows.iter().cloned());
    }
    widened
}

// -------------------------------------------------------------------------
// Stage 1 — working hours
// -------------------------------------------------------------------------

/// Turns each host's recurring wall windows into UTC intervals inside
/// `requested`.
///
/// A window boundary that falls in a spring-forward gap has no UTC instant, so
/// that occurrence of that window is skipped. It is never shifted into the
/// adjacent hour and never silently widened: the border reports the gap, and
/// skipping is the policy this layer applies to it.
///
/// The configuration is trusted already validated — [`solve`](SlotOracle::solve)
/// is the one door in, and it validates before the pipeline runs.
///
/// # Errors
///
/// [`BookingError::InvalidConfig`] on an unresolvable host zone.
pub(crate) fn working_hours_mask(
    config: &EventTypeConfig,
    requested: TimeRange,
) -> Result<Vec<(EntityId, Vec<TimeRange>)>, BookingError> {
    let mut per_host = Vec::with_capacity(config.hosts.len());
    for host in &config.hosts {
        let mut ranges = Vec::new();
        if requested.start < requested.end {
            let first = local_day(requested.start, &host.host_tz).map_err(host_zone_error)?;
            let last = local_day(requested.end - 1, &host.host_tz).map_err(host_zone_error)?;
            for day in first..=last {
                let weekday = weekday_of(day);
                for window in host
                    .working_hours
                    .iter()
                    .filter(|window| window.weekday == weekday)
                {
                    if let Some(range) = wall_window_to_utc(
                        day,
                        window.start_minute,
                        window.end_minute,
                        &host.host_tz,
                    )? && let Some(clipped) = intersect(range, requested)
                    {
                        ranges.push(clipped);
                    }
                }
            }
            normalize(&mut ranges);
        }
        per_host.push((host.host_ref, ranges));
    }
    Ok(per_host)
}

// -------------------------------------------------------------------------
// Stage 2 — busy union
// -------------------------------------------------------------------------

/// Joins CAL's busy union to each host's mask.
///
/// The union arrives normalized, merged, sorted, and busy-only — CAL applied
/// the Busy-only law at ingest, expanded series masters, and converted to
/// half-open intervals. Nothing here re-filters on transparency or status; a
/// second filter would be a second projection.
///
/// # Errors
///
/// [`BookingError::InvalidConfig`] when a host has no projection. An absent
/// union is a wiring defect, never an empty one.
pub(crate) fn attach_busy_union(
    host_masks: Vec<(EntityId, Vec<TimeRange>)>,
    busy_by_host: Vec<(EntityId, BusyUnion)>,
) -> Result<Vec<(EntityId, Vec<TimeRange>, BusyUnion)>, BookingError> {
    host_masks
        .into_iter()
        .map(|(host, mask)| {
            let busy = busy_by_host
                .iter()
                .find(|(id, _)| *id == host)
                .map(|(_, union)| union.clone())
                .ok_or_else(|| {
                    BookingError::InvalidConfig(format!(
                        "host {} has no freebusy projection",
                        host.to_hex()
                    ))
                })?;
            Ok((host, mask, busy))
        })
        .collect()
}

// -------------------------------------------------------------------------
// Stage 3 — buffers
// -------------------------------------------------------------------------

/// Removes busy time and the buffers around it from each host's mask.
///
/// Both the existing meeting and the candidate carry this event type's buffers,
/// so the gap either side of a busy interval must hold one meeting's
/// `post_buffer_min` and the other's `pre_buffer_min` — `pre + post` seconds,
/// on both sides. Growing the busy interval by that amount and then requiring
/// the UNPADDED candidate to fit is exactly that rule, and it keeps the
/// candidate's own footprint equal to its booked duration.
#[must_use]
pub(crate) fn apply_buffers(
    host_inputs: Vec<(EntityId, Vec<TimeRange>, BusyUnion)>,
    config: &EventTypeConfig,
) -> Vec<(EntityId, Vec<TimeRange>)> {
    let pad = (u64::from(config.pre_buffer_min) + u64::from(config.post_buffer_min))
        .saturating_mul(SECS_PER_MINUTE);
    host_inputs
        .into_iter()
        .map(|(host, mask, busy)| {
            let blockers: Vec<TimeRange> = busy
                .iter()
                .map(|interval| TimeRange {
                    start: interval.start_utc.saturating_sub(pad),
                    end: interval.end_utc.saturating_add(pad),
                })
                .collect();
            (host, subtract(mask, &blockers))
        })
        .collect()
}

// -------------------------------------------------------------------------
// Stage 4 — notice and horizon
// -------------------------------------------------------------------------

/// Clips every mask to `[now + min_notice, now + booking_window]`, intersected
/// with the requested window.
///
/// Both bounds are measured from request time, so the same configuration
/// answers differently as `now_utc` moves — and identically for a fixed
/// `now_utc`, which is what makes the solve reproducible.
#[must_use]
pub(crate) fn enforce_notice_and_window(
    host_masks: Vec<(EntityId, Vec<TimeRange>)>,
    now_utc: u64,
    request_window: TimeRange,
    config: &EventTypeConfig,
) -> Vec<(EntityId, Vec<TimeRange>)> {
    let bounds = TimeRange {
        start: now_utc
            .saturating_add(config.min_notice_secs)
            .max(request_window.start),
        end: now_utc
            .saturating_add(config.booking_window_secs)
            .min(request_window.end),
    };
    host_masks
        .into_iter()
        .map(|(host, mask)| {
            let clipped = mask
                .into_iter()
                .filter_map(|range| intersect(range, bounds))
                .collect();
            (host, clipped)
        })
        .collect()
}

// -------------------------------------------------------------------------
// Stage 5 — event-type knobs
// -------------------------------------------------------------------------

/// Cuts candidate slots out of each host's mask and charges them against the
/// visitor-local caps.
///
/// Starts are aligned to `slot_step_min` on a UTC grid anchored at the epoch,
/// not at each mask's own start: a per-mask grid would give two hosts different
/// candidate instants and make `Both` routing intersect to nothing even where
/// the hosts genuinely share time.
#[must_use]
pub(crate) fn apply_event_type_knobs(
    host_masks: Vec<(EntityId, Vec<TimeRange>)>,
    config: &EventTypeConfig,
    visitor_tz: &str,
    counts: &BookingCounts,
) -> Vec<(EntityId, Vec<TimeRange>)> {
    let duration = u64::from(config.duration_min).saturating_mul(SECS_PER_MINUTE);
    let step = u64::from(config.slot_step_min).saturating_mul(SECS_PER_MINUTE);
    host_masks
        .into_iter()
        .map(|(host, mask)| {
            let mut slots = Vec::new();
            for range in mask {
                let mut start = range.start.div_ceil(step).saturating_mul(step);
                while let Some(end) = start.checked_add(duration) {
                    if end > range.end {
                        break;
                    }
                    slots.push(TimeRange { start, end });
                    let Some(next) = start.checked_add(step) else {
                        break;
                    };
                    start = next;
                }
            }
            (host, retain_under_caps(slots, config, visitor_tz, counts))
        })
        .collect()
}

/// Drops candidates whose visitor-local day or week is already at its cap.
///
/// A bucket is charged to the visitor-local day its `window_start_utc` falls
/// in, so the same table read in a different `visitor_tz` charges different
/// days — which is the point: the caps are the visitor's, not UTC's.
fn retain_under_caps(
    slots: Vec<TimeRange>,
    config: &EventTypeConfig,
    visitor_tz: &str,
    counts: &BookingCounts,
) -> Vec<TimeRange> {
    if config.daily_cap.is_none() && config.weekly_cap.is_none() {
        return slots;
    }
    slots
        .into_iter()
        .filter(|slot| {
            let Ok(day) = local_day(slot.start, visitor_tz) else {
                // A candidate whose visitor-local placement is unrepresentable
                // cannot be charged against a visitor-local cap, so it is not
                // offered.
                return false;
            };
            under_cap(config.daily_cap, &counts.daily, visitor_tz, |bucket_day| {
                bucket_day == day
            }) && under_cap(
                config.weekly_cap,
                &counts.weekly,
                visitor_tz,
                |bucket_day| week_of(bucket_day) == week_of(day),
            )
        })
        .collect()
}

fn under_cap(
    cap: Option<u16>,
    buckets: &[BookingCountBucket],
    visitor_tz: &str,
    same_period: impl Fn(i64) -> bool,
) -> bool {
    let Some(cap) = cap else {
        return true;
    };
    let confirmed: u32 = buckets
        .iter()
        .filter(|bucket| local_day(bucket.window_start_utc, visitor_tz).is_ok_and(&same_period))
        .map(|bucket| u32::from(bucket.confirmed))
        .sum();
    confirmed < u32::from(cap)
}

// -------------------------------------------------------------------------
// Stage 6 — live holds
// -------------------------------------------------------------------------

/// Removes every candidate a live hold overlaps.
///
/// By this stage the per-host entries are discrete candidates, so a hold takes
/// whole candidates rather than carving a mask — a partially held slot is not
/// bookable at all. Holds are page-scoped: a hold blocks every host, because it
/// reserves the meeting, not a calendar.
#[must_use]
pub(crate) fn subtract_live_holds(
    host_masks: Vec<(EntityId, Vec<TimeRange>)>,
    holds: &[TimeRange],
) -> Vec<(EntityId, Vec<TimeRange>)> {
    host_masks
        .into_iter()
        .map(|(host, slots)| {
            let free = slots
                .into_iter()
                .filter(|slot| !holds.iter().any(|hold| overlaps(*slot, *hold)))
                .collect();
            (host, free)
        })
        .collect()
}

// -------------------------------------------------------------------------
// Stage 7 — routing
// -------------------------------------------------------------------------

/// Collapses the per-host candidates into the offered set.
///
/// `Either` is the union — any one host can take the meeting. `Both` is the
/// intersection — every host must be free. No round-robin, weighting, or pool
/// shaping happens here: those are later picks over this result.
#[must_use]
pub(crate) fn route_host_masks(
    host_masks: Vec<(EntityId, Vec<TimeRange>)>,
    mode: RoutingMode,
) -> Vec<TimeRange> {
    let mut routed = match mode {
        RoutingMode::Either => host_masks
            .into_iter()
            .flat_map(|(_, slots)| slots)
            .collect(),
        RoutingMode::Both => {
            let mut hosts = host_masks.into_iter();
            let Some((_, first)) = hosts.next() else {
                return Vec::new();
            };
            hosts.fold(first, |common, (_, slots)| {
                common
                    .into_iter()
                    .filter(|slot| slots.contains(slot))
                    .collect()
            })
        }
    };
    routed.sort_unstable_by_key(|slot| (slot.start, slot.end));
    routed.dedup();
    routed
}

// -------------------------------------------------------------------------
// Stage 8 — rank and emit
// -------------------------------------------------------------------------

/// Applies the visitor's constraint, ranks what survives, and emits UTC.
///
/// The caps are re-applied here because this is the one stage that sees the
/// FINAL offered set: stage 5 prunes per host, before routing, and making the
/// cap a property of what leaves the solver keeps the guarantee true whatever
/// routing mode ran.
///
/// Ordering is total and stable: rank descending by [`f32::total_cmp`], then
/// start, then end. A non-finite rank has no deterministic place in that order,
/// so it never reaches a caller.
#[must_use]
pub(crate) fn rank_and_emit(
    slots: Vec<TimeRange>,
    config: &EventTypeConfig,
    constraint: Option<&ConstraintObject>,
    visitor_tz: &str,
    counts: &BookingCounts,
) -> SolveResult {
    let admitted: Vec<TimeRange> = slots
        .into_iter()
        .filter(|slot| satisfies_constraint(*slot, constraint, visitor_tz))
        .collect();
    let mut ranked: Vec<RankedSlot> = retain_under_caps(admitted, config, visitor_tz, counts)
        .into_iter()
        .map(|slot| RankedSlot {
            start_utc: slot.start,
            end_utc: slot.end,
            rank: rank_of(slot, config),
        })
        .filter(|slot| slot.rank.is_finite())
        .collect();
    ranked.sort_by(|left, right| {
        right
            .rank
            .total_cmp(&left.rank)
            .then(left.start_utc.cmp(&right.start_utc))
            .then(left.end_utc.cmp(&right.end_utc))
    });
    SolveResult {
        slots: ranked,
        flex_used: false,
    }
}

/// Whether the visitor's normalized constraint admits `slot`.
///
/// Only the serialized [`ConstraintObject`] reaches here: there is no text
/// field to read and no model call in this module.
fn satisfies_constraint(
    slot: TimeRange,
    constraint: Option<&ConstraintObject>,
    visitor_tz: &str,
) -> bool {
    let Some(constraint) = constraint else {
        return true;
    };
    if let Some(window) = constraint.utc_window {
        // The seam's window is an inclusive engine `TimeRange`.
        let Some(end) = window.end.checked_add(1) else {
            return false;
        };
        if slot.start < window.start || slot.end > end {
            return false;
        }
    }
    let Ok(wall) = utc_to_wall(slot.start, visitor_tz) else {
        return false;
    };
    let weekday = weekday_of(days_from_civil(wall.y, wall.mo, wall.d));
    if !constraint.weekdays.is_empty()
        && !constraint
            .weekdays
            .iter()
            .any(|day| weekday_index(*day) == weekday)
    {
        return false;
    }
    let minute = u16::from(wall.h) * 60 + u16::from(wall.mi);
    constraint.local_time_windows.is_empty()
        || constraint
            .local_time_windows
            .iter()
            .any(|window| window.start_minute <= minute && minute < window.end_minute)
}

/// A slot inside any host's preferred hours outranks one that is merely
/// bookable. Placement is read from the slot's START, which is the instant a
/// visitor chooses.
fn rank_of(slot: TimeRange, config: &EventTypeConfig) -> f32 {
    let preferred = config.hosts.iter().any(|host| {
        utc_to_wall(slot.start, &host.host_tz).is_ok_and(|wall| {
            let weekday = weekday_of(days_from_civil(wall.y, wall.mo, wall.d));
            let minute = u16::from(wall.h) * 60 + u16::from(wall.mi);
            host.preferred_hours.iter().any(|window| {
                window.weekday == weekday
                    && window.start_minute <= minute
                    && minute < window.end_minute
            })
        })
    });
    if preferred {
        PREFERRED_RANK
    } else {
        ORDINARY_RANK
    }
}

// -------------------------------------------------------------------------
// Slot mask
// -------------------------------------------------------------------------

/// Projects a solve into the seam's public availability mask.
///
/// The mask carries the event type, the half-open window, the ranked UTC slots,
/// and whether the flex pool answered — and nothing else. No event title, body,
/// attendee, raw busy interval, or calendar identity has a field to travel in.
#[must_use]
pub fn slot_mask(req: &SolveRequest, solved: SolveResult) -> SlotMask {
    SlotMask {
        event_type: req.event_type.clone(),
        window_start_utc: req.window.start,
        window_end_utc: req.window.end.saturating_add(1),
        slots: solved.slots,
        flex_used: solved.flex_used,
    }
}

// -------------------------------------------------------------------------
// Interval algebra (half-open)
// -------------------------------------------------------------------------

/// Inclusive engine range → half-open solver range.
fn half_open(range: TimeRange) -> Result<TimeRange, BookingError> {
    let end = range.end.checked_add(1).ok_or_else(|| {
        BookingError::InvalidConstraint(
            "solve window ends at the last representable second".to_owned(),
        )
    })?;
    Ok(TimeRange {
        start: range.start,
        end,
    })
}

/// Half-open solver range → inclusive engine range, for the CAL call.
const fn inclusive(range: TimeRange) -> TimeRange {
    TimeRange {
        start: range.start,
        end: range.end.saturating_sub(1),
    }
}

fn intersect(left: TimeRange, right: TimeRange) -> Option<TimeRange> {
    let start = left.start.max(right.start);
    let end = left.end.min(right.end);
    if start < end {
        Some(TimeRange { start, end })
    } else {
        None
    }
}

const fn overlaps(left: TimeRange, right: TimeRange) -> bool {
    left.start < right.end && right.start < left.end
}

/// Sorts and merges overlapping or touching ranges.
fn normalize(ranges: &mut Vec<TimeRange>) {
    ranges.retain(|range| range.start < range.end);
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<TimeRange> = Vec::with_capacity(ranges.len());
    for range in ranges.iter().copied() {
        match merged.last_mut() {
            Some(open) if range.start <= open.end => open.end = open.end.max(range.end),
            _ => merged.push(range),
        }
    }
    *ranges = merged;
}

/// Removes every blocker from `mask`, returning the normalized remainder.
fn subtract(mask: Vec<TimeRange>, blockers: &[TimeRange]) -> Vec<TimeRange> {
    let mut remaining = mask;
    for blocker in blockers {
        let mut next = Vec::with_capacity(remaining.len());
        for range in remaining {
            if !overlaps(range, *blocker) {
                next.push(range);
                continue;
            }
            if range.start < blocker.start {
                next.push(TimeRange {
                    start: range.start,
                    end: blocker.start,
                });
            }
            if blocker.end < range.end {
                next.push(TimeRange {
                    start: blocker.end,
                    end: range.end,
                });
            }
        }
        remaining = next;
    }
    normalize(&mut remaining);
    remaining
}

// -------------------------------------------------------------------------
// Civil-date arithmetic
//
// The calendar border hands out and takes back civil fields; turning those
// fields into a day number, a weekday, and back is pure integer arithmetic
// (Howard Hinnant's `days_from_civil` / `civil_from_days`) with no database
// behind it. Doing it here rather than reaching for a third-party date type is
// what keeps every signature in this module free of one.
// -------------------------------------------------------------------------

/// Days since `1970-01-01` for a proleptic Gregorian civil date.
fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let month = i64::from(month);
    let day = i64::from(day);
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    // Every cast is lossless: `month` is 1..=12 and `day` is 1..=31 by
    // construction, and the year is bounded by the border's own range.
    (
        (year + i64::from(month <= 2)) as i32,
        month as u8,
        day as u8,
    )
}

/// `0 = Monday ..= 6 = Sunday`.
const fn weekday_of(days: i64) -> u8 {
    ((days + EPOCH_WEEKDAY_OFFSET).rem_euclid(DAYS_PER_WEEK as i64)) as u8
}

/// Monday-anchored week index for a day number.
const fn week_of(days: i64) -> i64 {
    (days + EPOCH_WEEKDAY_OFFSET).div_euclid(DAYS_PER_WEEK as i64)
}

const fn weekday_index(weekday: ConstraintWeekday) -> u8 {
    match weekday {
        ConstraintWeekday::Monday => 0,
        ConstraintWeekday::Tuesday => 1,
        ConstraintWeekday::Wednesday => 2,
        ConstraintWeekday::Thursday => 3,
        ConstraintWeekday::Friday => 4,
        ConstraintWeekday::Saturday => 5,
        ConstraintWeekday::Sunday => 6,
    }
}

/// The civil day number `utc` falls on in `tz`.
fn local_day(utc: u64, tz: &str) -> Result<i64, CalendarError> {
    let wall = utc_to_wall(utc, tz)?;
    Ok(days_from_civil(wall.y, wall.mo, wall.d))
}

/// One occurrence of a wall window, as a half-open UTC range.
///
/// `None` when a boundary falls in a spring-forward gap, or when the zone maps
/// the window to nothing.
fn wall_window_to_utc(
    day: i64,
    start_minute: u16,
    end_minute: u16,
    tz: &str,
) -> Result<Option<TimeRange>, BookingError> {
    let (Some(start), Some(end)) = (
        wall_minute_to_utc(day, start_minute, tz)?,
        wall_minute_to_utc(day, end_minute, tz)?,
    ) else {
        return Ok(None);
    };
    Ok((start < end).then_some(TimeRange { start, end }))
}

/// A minute-of-day in a zone, as a UTC instant.
///
/// `end_minute == MINUTES_PER_DAY` denotes the following midnight and carries
/// into the next civil day. A fall-back fold resolves to the earliest offset
/// (the border's policy); a spring-forward gap yields `None`, which the caller
/// reads as "this occurrence does not exist".
fn wall_minute_to_utc(day: i64, minute: u16, tz: &str) -> Result<Option<u64>, BookingError> {
    let carry = i64::from(minute / MINUTES_PER_DAY);
    let minute = minute % MINUTES_PER_DAY;
    let (year, month, civil_day) = civil_from_days(day + carry);
    let wall = WallTime {
        y: year,
        mo: month,
        d: civil_day,
        h: (minute / 60) as u8,
        mi: (minute % 60) as u8,
        s: 0,
    };
    match wall_to_utc(&wall, tz) {
        Ok(utc) => Ok(Some(utc)),
        Err(CalendarError::NonexistentWallTime { .. }) => Ok(None),
        Err(error) => Err(host_zone_error(error)),
    }
}

/// The one calendar-error wrapper for a HOST zone.
///
/// [`BookingError`] deliberately does not restate the TZ taxonomy: whose zone
/// failed is what picks the variant, and the border's own `Display` carries
/// every detail a caller needs.
fn host_zone_error(error: CalendarError) -> BookingError {
    BookingError::InvalidConfig(format!("host time zone: {error}"))
}

/// The same wrapper for the VISITOR zone, which is request data rather than
/// configuration.
fn visitor_zone_error(error: CalendarError) -> BookingError {
    BookingError::InvalidConstraint(format!("visitor time zone: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::booking::config::{
        DEFAULT_INTRO_DURATION_MIN, HostAvailabilityConfig, WeeklyWallWindow,
    };
    use crate::booking::constraint::LocalMinuteWindow;
    use crate::test_util::entity as id;

    const HOST_A: u8 = 0x52;
    const HOST_B: u8 = 0x55;
    const CALENDAR: u8 = 0x53;

    /// `2026-03-02T00:00:00Z`, a Monday.
    const MONDAY: u64 = 1_772_409_600;

    fn window(weekday: u8, start_hour: u16, end_hour: u16) -> WeeklyWallWindow {
        WeeklyWallWindow {
            weekday,
            start_minute: start_hour * 60,
            end_minute: end_hour * 60,
        }
    }

    fn host(seed: u8, tz: &str, working: Vec<WeeklyWallWindow>) -> HostAvailabilityConfig {
        HostAvailabilityConfig {
            host_ref: id(seed),
            calendar_refs: vec![id(CALENDAR)],
            host_tz: tz.to_owned(),
            working_hours: working,
            preferred_hours: Vec::new(),
        }
    }

    fn config(hosts: Vec<HostAvailabilityConfig>) -> EventTypeConfig {
        EventTypeConfig {
            key: EventTypeKey("intro-call".to_owned()),
            duration_min: DEFAULT_INTRO_DURATION_MIN,
            slot_step_min: 30,
            pre_buffer_min: 0,
            post_buffer_min: 0,
            min_notice_secs: 0,
            booking_window_secs: 30 * 24 * 3_600,
            daily_cap: None,
            weekly_cap: None,
            routing: RoutingMode::Either,
            hosts,
            flex_windows: Vec::new(),
        }
    }

    fn utc_host_config() -> EventTypeConfig {
        config(vec![host(HOST_A, "UTC", vec![window(0, 9, 11)])])
    }

    /// The whole Monday, half-open.
    const fn monday() -> TimeRange {
        TimeRange {
            start: MONDAY,
            end: MONDAY + 86_400,
        }
    }

    fn empty_counts() -> BookingCounts {
        BookingCounts {
            daily: Vec::new(),
            weekly: Vec::new(),
        }
    }

    fn starts(masks: &[(EntityId, Vec<TimeRange>)]) -> Vec<(u64, u64)> {
        masks
            .iter()
            .flat_map(|(_, ranges)| ranges.iter().map(|range| (range.start, range.end)))
            .collect()
    }

    #[test]
    fn civil_date_arithmetic_round_trips_and_names_weekdays() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(weekday_of(0), 3, "1970-01-01 was a Thursday");
        for days in [-100_000_i64, -1, 0, 1, 20_000, 100_000] {
            let (y, mo, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, mo, d), days, "{y}-{mo}-{d}");
        }
        // 2026-03-02 is a Monday, and the week index is Monday-anchored.
        let monday = days_from_civil(2026, 3, 2);
        assert_eq!(weekday_of(monday), 0);
        assert_eq!(week_of(monday), week_of(monday + 6));
        assert_ne!(week_of(monday), week_of(monday + 7));
        assert_ne!(week_of(monday), week_of(monday - 1));
    }

    #[test]
    fn working_hours_convert_wall_windows_through_the_border() {
        let masks = working_hours_mask(&utc_host_config(), monday()).expect("mask");
        assert_eq!(starts(&masks), [(MONDAY + 9 * 3_600, MONDAY + 11 * 3_600)]);

        // The same civil window in a zone with an offset lands elsewhere in UTC,
        // so the conversion is real rather than an identity.
        let shifted = config(vec![host(HOST_A, "Asia/Tokyo", vec![window(0, 9, 11)])]);
        let masks = working_hours_mask(&shifted, monday()).expect("mask");
        assert_eq!(starts(&masks), [(MONDAY, MONDAY + 2 * 3_600)]);

        // A window ending at midnight carries into the next civil day.
        let midnight = config(vec![host(
            HOST_A,
            "UTC",
            vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 23 * 60,
                end_minute: MINUTES_PER_DAY,
            }],
        )]);
        let masks = working_hours_mask(&midnight, monday()).expect("mask");
        assert_eq!(starts(&masks), [(MONDAY + 23 * 3_600, MONDAY + 86_400)]);

        // A window on another weekday contributes nothing.
        let tuesday_only = config(vec![host(HOST_A, "UTC", vec![window(1, 9, 11)])]);
        assert!(starts(&working_hours_mask(&tuesday_only, monday()).expect("mask")).is_empty());
    }

    #[test]
    fn nonexistent_wall_boundary_skips_the_occurrence_without_shifting() {
        // Europe/London springs forward 2026-03-29 at 01:00 local; 01:00-02:00
        // does not exist. A window anchored inside the gap has no instants and
        // is skipped; the neighbouring hour converts normally.
        let sunday = MONDAY + 27 * 86_400; // 2026-03-29
        let gap_window = TimeRange {
            start: sunday,
            end: sunday + 86_400,
        };
        let gapped = config(vec![host(HOST_A, "Europe/London", vec![window(6, 1, 2)])]);
        assert!(
            starts(&working_hours_mask(&gapped, gap_window).expect("mask")).is_empty(),
            "a skipped hour is never shifted into the adjacent one"
        );

        let ordinary = config(vec![host(HOST_A, "Europe/London", vec![window(6, 3, 4)])]);
        assert_eq!(
            starts(&working_hours_mask(&ordinary, gap_window).expect("mask")).len(),
            1,
            "the rejection is the gap, not the whole day"
        );
    }

    #[test]
    fn unresolvable_host_zone_is_a_typed_config_error() {
        let bogus = config(vec![host(
            HOST_A,
            "Mars/Olympus_Mons",
            vec![window(0, 9, 11)],
        )]);
        assert!(matches!(
            working_hours_mask(&bogus, monday()),
            Err(BookingError::InvalidConfig(_))
        ));
    }

    #[test]
    fn attach_busy_union_refuses_a_host_with_no_projection() {
        let masks = vec![(id(HOST_A), vec![monday()])];
        assert!(matches!(
            attach_busy_union(masks.clone(), Vec::new()),
            Err(BookingError::InvalidConfig(_))
        ));
        assert!(attach_busy_union(masks, vec![(id(HOST_A), Vec::new())]).is_ok());
    }

    #[test]
    fn buffers_expand_existing_and_candidate_meetings() {
        let busy = vec![crate::calendar::BusyInterval {
            start_utc: MONDAY + 10 * 3_600,
            end_utc: MONDAY + 11 * 3_600,
            source: id(0x56),
        }];
        let mask = vec![TimeRange {
            start: MONDAY + 9 * 3_600,
            end: MONDAY + 12 * 3_600,
        }];
        let apply = |pre: u16, post: u16| {
            let mut config = utc_host_config();
            config.pre_buffer_min = pre;
            config.post_buffer_min = post;
            starts(&apply_buffers(
                vec![(id(HOST_A), mask.clone(), busy.clone())],
                &config,
            ))
        };

        // No buffers: the busy hour alone is removed.
        assert_eq!(
            apply(0, 0),
            [
                (MONDAY + 9 * 3_600, MONDAY + 10 * 3_600),
                (MONDAY + 11 * 3_600, MONDAY + 12 * 3_600)
            ]
        );
        // The required gap either side is one meeting's post-buffer plus the
        // other's pre-buffer, so pre-only and post-only shrink both sides.
        assert_eq!(
            apply(15, 0),
            [
                (MONDAY + 9 * 3_600, MONDAY + 10 * 3_600 - 900),
                (MONDAY + 11 * 3_600 + 900, MONDAY + 12 * 3_600)
            ]
        );
        assert_eq!(apply(0, 15), apply(15, 0), "the gap is pre + post");
        assert_eq!(
            apply(15, 15),
            [
                (MONDAY + 9 * 3_600, MONDAY + 10 * 3_600 - 1_800),
                (MONDAY + 11 * 3_600 + 1_800, MONDAY + 12 * 3_600)
            ]
        );
        // A buffer wide enough to reach the mask edges clips rather than
        // underflowing, and adjacent busy runs coalesce.
        assert!(apply(180, 180).is_empty());
    }

    #[test]
    fn notice_24h_and_48h_presets_clip_candidates() {
        let mask = vec![(id(HOST_A), vec![monday()])];
        let clip = |notice: u64, horizon: u64| {
            let mut config = utc_host_config();
            config.min_notice_secs = notice;
            config.booking_window_secs = horizon;
            starts(&enforce_notice_and_window(
                mask.clone(),
                MONDAY,
                monday(),
                &config,
            ))
        };
        assert_eq!(clip(0, 30 * 86_400), [(MONDAY, MONDAY + 86_400)]);
        assert_eq!(
            clip(24 * 3_600, 30 * 86_400),
            [],
            "a 24h notice consumes the whole first day"
        );
        assert_eq!(
            clip(12 * 3_600, 30 * 86_400),
            [(MONDAY + 12 * 3_600, MONDAY + 86_400)]
        );
        assert_eq!(clip(48 * 3_600, 30 * 86_400), []);
    }

    #[test]
    fn constrained_booking_window_clips_far_future_slots() {
        let far = TimeRange {
            start: MONDAY,
            end: MONDAY + 30 * 86_400,
        };
        let mut config = utc_host_config();
        config.booking_window_secs = 7 * 86_400;
        let clipped =
            enforce_notice_and_window(vec![(id(HOST_A), vec![far])], MONDAY, far, &config);
        assert_eq!(starts(&clipped), [(MONDAY, MONDAY + 7 * 86_400)]);
    }

    #[test]
    fn duration_and_step_cut_candidates_on_the_epoch_grid() {
        let mask = vec![(
            id(HOST_A),
            vec![TimeRange {
                start: MONDAY + 9 * 3_600,
                end: MONDAY + 10 * 3_600 + 1_800,
            }],
        )];
        let config = utc_host_config();
        assert_eq!(config.duration_min, 30);
        let slots = apply_event_type_knobs(mask, &config, "UTC", &empty_counts());
        assert_eq!(
            starts(&slots),
            [
                (MONDAY + 9 * 3_600, MONDAY + 9 * 3_600 + 1_800),
                (MONDAY + 9 * 3_600 + 1_800, MONDAY + 10 * 3_600),
                (MONDAY + 10 * 3_600, MONDAY + 10 * 3_600 + 1_800),
            ]
        );

        // An unaligned mask start snaps forward onto the shared grid, so two
        // hosts always propose the same instants.
        let ragged = vec![(
            id(HOST_A),
            vec![TimeRange {
                start: MONDAY + 9 * 3_600 + 300,
                end: MONDAY + 10 * 3_600 + 1_800,
            }],
        )];
        assert_eq!(
            starts(&apply_event_type_knobs(
                ragged,
                &config,
                "UTC",
                &empty_counts()
            ))[0]
                .0,
            MONDAY + 9 * 3_600 + 1_800
        );
    }

    #[test]
    fn visitor_local_daily_and_weekly_caps_use_typed_booking_counts() {
        let mask = vec![(
            id(HOST_A),
            vec![TimeRange {
                start: MONDAY + 9 * 3_600,
                end: MONDAY + 10 * 3_600,
            }],
        )];
        let mut config = utc_host_config();
        config.daily_cap = Some(1);

        // One confirmed booking on the visitor's Monday fills the daily cap.
        let counts = BookingCounts {
            daily: vec![BookingCountBucket {
                window_start_utc: MONDAY + 3_600,
                window_end_utc: MONDAY + 86_400,
                confirmed: 1,
            }],
            weekly: Vec::new(),
        };
        assert!(
            apply_event_type_knobs(mask.clone(), &config, "UTC", &counts)
                .iter()
                .all(|(_, slots)| slots.is_empty())
        );

        // The SAME table, read in a zone eight hours behind. There the bucket's
        // 01:00Z start is the previous local day while the 09:00Z candidates are
        // this one, so the bucket charges a different day and the candidates
        // survive. In UTC both fall on one day and the cap binds — which is what
        // proves the cap is the VISITOR's, not UTC's.
        assert_eq!(
            starts(&apply_event_type_knobs(
                mask.clone(),
                &config,
                "America/Los_Angeles",
                &counts
            ))
            .len(),
            2
        );

        // Sparse table: a period with no bucket has zero confirmed bookings.
        assert_eq!(
            starts(&apply_event_type_knobs(
                mask.clone(),
                &config,
                "UTC",
                &empty_counts()
            ))
            .len(),
            2
        );

        // Weekly caps aggregate every bucket in the Monday-anchored week.
        let mut weekly = config;
        weekly.daily_cap = None;
        weekly.weekly_cap = Some(3);
        let spread = BookingCounts {
            daily: Vec::new(),
            weekly: vec![
                BookingCountBucket {
                    window_start_utc: MONDAY + 3_600,
                    window_end_utc: MONDAY + 86_400,
                    confirmed: 2,
                },
                BookingCountBucket {
                    window_start_utc: MONDAY + 3 * 86_400,
                    window_end_utc: MONDAY + 4 * 86_400,
                    confirmed: 1,
                },
            ],
        };
        assert!(
            apply_event_type_knobs(mask.clone(), &weekly, "UTC", &spread)
                .iter()
                .all(|(_, slots)| slots.is_empty()),
            "2 + 1 confirmed reaches a weekly cap of 3"
        );
        // A bucket in the FOLLOWING week does not charge this one.
        let next_week = BookingCounts {
            daily: Vec::new(),
            weekly: vec![BookingCountBucket {
                window_start_utc: MONDAY + 8 * 86_400,
                window_end_utc: MONDAY + 9 * 86_400,
                confirmed: 3,
            }],
        };
        assert_eq!(
            starts(&apply_event_type_knobs(mask, &weekly, "UTC", &next_week)).len(),
            2
        );
    }

    #[test]
    fn live_hold_fixture_removes_only_unexpired_overlap() {
        let slots = vec![(
            id(HOST_A),
            vec![
                TimeRange {
                    start: MONDAY + 9 * 3_600,
                    end: MONDAY + 9 * 3_600 + 1_800,
                },
                TimeRange {
                    start: MONDAY + 10 * 3_600,
                    end: MONDAY + 10 * 3_600 + 1_800,
                },
            ],
        )];
        let hold = TimeRange {
            start: MONDAY + 9 * 3_600 + 900,
            end: MONDAY + 9 * 3_600 + 1_200,
        };
        assert_eq!(
            starts(&subtract_live_holds(slots.clone(), &[hold])),
            [(MONDAY + 10 * 3_600, MONDAY + 10 * 3_600 + 1_800)],
            "a partially held candidate is not bookable"
        );
        // A hold that merely touches a candidate boundary does not take it.
        let touching = TimeRange {
            start: MONDAY + 9 * 3_600 + 1_800,
            end: MONDAY + 10 * 3_600,
        };
        assert_eq!(starts(&subtract_live_holds(slots, &[touching])).len(), 2);
        // The layer-1 source holds nothing; the confirming session's own hold is
        // excludable through the same door ONE-1813 implements.
        assert_eq!(
            NoActiveHolds
                .active_holds(id(0x57), monday(), MONDAY, Some(&[7_u8; 32]))
                .expect("empty source"),
            Vec::new()
        );
    }

    #[test]
    fn routing_either_is_union_and_both_is_intersection() {
        let slot = |hour: u64| TimeRange {
            start: MONDAY + hour * 3_600,
            end: MONDAY + hour * 3_600 + 1_800,
        };
        let a = (id(HOST_A), vec![slot(9), slot(10)]);
        let b = (id(HOST_B), vec![slot(10), slot(11)]);
        let c = (id(0x58), vec![slot(11)]);

        let flat = |routed: Vec<TimeRange>| routed.into_iter().map(|r| r.start).collect::<Vec<_>>();
        assert_eq!(
            flat(route_host_masks(
                vec![a.clone(), b.clone()],
                RoutingMode::Either
            )),
            [slot(9).start, slot(10).start, slot(11).start],
            "union is sorted and duplicate-free"
        );
        assert_eq!(
            flat(route_host_masks(
                vec![a.clone(), b.clone()],
                RoutingMode::Both
            )),
            [slot(10).start]
        );
        // Disjoint hosts, three hosts, and an empty host.
        assert!(
            flat(route_host_masks(
                vec![(id(HOST_A), vec![slot(9)]), (id(HOST_B), vec![slot(11)])],
                RoutingMode::Both
            ))
            .is_empty()
        );
        assert!(flat(route_host_masks(vec![a.clone(), b, c], RoutingMode::Both)).is_empty());
        let empty_host = (id(HOST_B), Vec::new());
        assert!(
            flat(route_host_masks(
                vec![a.clone(), empty_host.clone()],
                RoutingMode::Both
            ))
            .is_empty()
        );
        assert_eq!(
            flat(route_host_masks(vec![a, empty_host], RoutingMode::Either)).len(),
            2
        );
        assert!(flat(route_host_masks(Vec::new(), RoutingMode::Both)).is_empty());
        assert!(flat(route_host_masks(Vec::new(), RoutingMode::Either)).is_empty());
    }

    #[test]
    fn ranked_emit_is_deterministic() {
        let slot = |hour: u64| TimeRange {
            start: MONDAY + hour * 3_600,
            end: MONDAY + hour * 3_600 + 1_800,
        };
        let mut config = utc_host_config();
        config.hosts[0].preferred_hours = vec![window(0, 11, 12)];
        let result = rank_and_emit(
            vec![slot(11), slot(9), slot(10)],
            &config,
            None,
            "UTC",
            &empty_counts(),
        );
        assert!(result.slots.iter().all(|slot| slot.rank.is_finite()));
        assert_eq!(
            result
                .slots
                .iter()
                .map(|slot| slot.start_utc)
                .collect::<Vec<_>>(),
            [slot(11).start, slot(9).start, slot(10).start],
            "preferred first, then ascending UTC start"
        );
        assert!((result.slots[0].rank - PREFERRED_RANK).abs() < f32::EPSILON);
        assert!(!result.flex_used);

        // Identical inputs serialize byte-identically.
        let again = rank_and_emit(
            vec![slot(10), slot(11), slot(9)],
            &config,
            None,
            "UTC",
            &empty_counts(),
        );
        assert_eq!(
            serde_json::to_vec(&result).expect("serialize"),
            serde_json::to_vec(&again).expect("serialize")
        );
    }

    #[test]
    fn constraint_object_masks_deterministically() {
        let slot = |day: u64, hour: u64| TimeRange {
            start: MONDAY + day * 86_400 + hour * 3_600,
            end: MONDAY + day * 86_400 + hour * 3_600 + 1_800,
        };
        let all = vec![slot(0, 9), slot(0, 15), slot(1, 9)];
        let emit = |constraint: Option<&ConstraintObject>, tz: &str| {
            rank_and_emit(
                all.clone(),
                &utc_host_config(),
                constraint,
                tz,
                &empty_counts(),
            )
            .slots
            .into_iter()
            .map(|slot| slot.start_utc)
            .collect::<Vec<_>>()
        };
        assert_eq!(emit(None, "UTC").len(), 3);

        let weekday_only = ConstraintObject {
            schema_version: 1,
            weekdays: vec![ConstraintWeekday::Tuesday],
            local_time_windows: Vec::new(),
            utc_window: None,
            allow_flex_pool: false,
        }
        .canonicalize()
        .expect("canonical");
        assert_eq!(emit(Some(&weekday_only), "UTC"), [slot(1, 9).start]);

        let mornings = ConstraintObject {
            schema_version: 1,
            weekdays: Vec::new(),
            local_time_windows: vec![LocalMinuteWindow {
                start_minute: 8 * 60,
                end_minute: 12 * 60,
            }],
            utc_window: None,
            allow_flex_pool: false,
        }
        .canonicalize()
        .expect("canonical");
        assert_eq!(
            emit(Some(&mornings), "UTC"),
            [slot(0, 9).start, slot(1, 9).start]
        );
        // The same constraint in a zone five hours behind selects the 15:00Z
        // slot instead, because there it IS 10:00 local. The window is the
        // VISITOR's local time, never UTC.
        assert_eq!(
            emit(Some(&mornings), "America/New_York"),
            [slot(0, 15).start]
        );

        let utc_window = ConstraintObject {
            schema_version: 1,
            weekdays: Vec::new(),
            local_time_windows: Vec::new(),
            // Inclusive at the seam; the slot must fit inside it.
            utc_window: Some(TimeRange {
                start: slot(0, 9).start,
                end: slot(0, 9).end - 1,
            }),
            allow_flex_pool: false,
        }
        .canonicalize()
        .expect("canonical");
        assert_eq!(emit(Some(&utc_window), "UTC"), [slot(0, 9).start]);
    }

    #[test]
    fn slot_mask_carries_the_half_open_window_and_nothing_else() {
        let req = SolveRequest {
            event_type: EventTypeKey("intro-call".to_owned()),
            window: TimeRange {
                start: MONDAY,
                end: MONDAY + 86_399,
            },
            constraint: None,
            visitor_tz: "UTC".to_owned(),
        };
        let solved = SolveResult {
            slots: vec![RankedSlot {
                start_utc: MONDAY + 9 * 3_600,
                end_utc: MONDAY + 9 * 3_600 + 1_800,
                rank: ORDINARY_RANK,
            }],
            flex_used: true,
        };
        let mask = slot_mask(&req, solved);
        assert_eq!(mask.window_start_utc, MONDAY);
        assert_eq!(
            mask.window_end_utc,
            MONDAY + 86_400,
            "the inclusive request window becomes a half-open mask window"
        );
        assert!(mask.flex_used);
        let json = serde_json::to_value(&mask).expect("serialize");
        assert_eq!(
            json.as_object()
                .expect("object")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "event_type",
                "window_start_utc",
                "window_end_utc",
                "slots",
                "flex_used"
            ]
        );
    }
}
