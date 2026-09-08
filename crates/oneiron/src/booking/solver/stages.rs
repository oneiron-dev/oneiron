//! The eight pure pipeline stages and their small helpers.

use super::civil_date::{
    days_from_civil, host_zone_error, local_day, wall_window_to_utc, week_of, weekday_index,
    weekday_of,
};
use super::counts::{BookingCountBucket, BookingCounts};
use super::interval::{intersect, normalize, overlaps, subtract};
use crate::booking::config::{EventTypeConfig, RoutingMode};
use crate::booking::constraint::ConstraintObject;
use crate::booking::{BookingError, RankedSlot, SlotHostBinding, SolveResult};
use crate::calendar::freebusy::BusyUnion;
use crate::calendar::tz::utc_to_wall;
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;

/// Rank of a slot inside a host's preferred hours.
pub(super) const PREFERRED_RANK: f32 = 1.0;

/// Rank of a slot that is merely bookable.
pub(super) const ORDINARY_RANK: f32 = 0.5;

/// Seconds in a minute — the unit every configuration knob is written in.
const SECS_PER_MINUTE: u64 = 60;

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
pub(super) fn working_hours_mask(
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
pub(super) fn attach_busy_union(
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

/// The free time this event type needs on each side of a busy interval.
///
/// Both the existing meeting and the candidate carry the buffers, so the gap
/// either side must hold one meeting's `post_buffer_min` and the other's
/// `pre_buffer_min` — `pre + post` seconds. This is also exactly how far
/// OUTSIDE the bookable extent a busy interval can still reach, which is why
/// [`SlotOracle::solve`] pads its freebusy query by the same amount.
pub(super) fn buffer_pad(config: &EventTypeConfig) -> u64 {
    (u64::from(config.pre_buffer_min) + u64::from(config.post_buffer_min))
        .saturating_mul(SECS_PER_MINUTE)
}

/// Removes busy time and the buffers around it from each host's mask.
///
/// Growing each busy interval by [`buffer_pad`] on both sides and then requiring
/// the UNPADDED candidate to fit is exactly the required-gap rule, and it keeps
/// the candidate's own footprint equal to its booked duration.
#[must_use]
pub(super) fn apply_buffers(
    host_inputs: Vec<(EntityId, Vec<TimeRange>, BusyUnion)>,
    config: &EventTypeConfig,
) -> Vec<(EntityId, Vec<TimeRange>)> {
    let pad = buffer_pad(config);
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

/// What `requested` leaves of `[now + min_notice, now + booking_window]`.
///
/// Both bounds are measured from request time, so the same configuration answers
/// differently as `now_utc` moves — and identically for a fixed `now_utc`, which
/// is what makes the solve reproducible. `None` means the horizon and the
/// request do not overlap: nothing is bookable, and nothing needs reading.
///
/// The rule lives here, in stage 4, and [`SlotOracle::solve`] applies it once
/// more BEFORE the pipeline. That is not a second rule: it is idempotent, and
/// applying it early is what keeps one solve's storage reads and per-local-day
/// walks proportional to the page's own bounded horizon rather than to whatever
/// window a caller named.
pub(super) fn bookable_extent(
    requested: TimeRange,
    now_utc: u64,
    config: &EventTypeConfig,
) -> Option<TimeRange> {
    intersect(
        requested,
        TimeRange {
            start: now_utc.saturating_add(config.min_notice_secs),
            end: now_utc.saturating_add(config.booking_window_secs),
        },
    )
}

/// Clips every mask to the bookable extent.
#[must_use]
pub(super) fn enforce_notice_and_window(
    host_masks: Vec<(EntityId, Vec<TimeRange>)>,
    now_utc: u64,
    request_window: TimeRange,
    config: &EventTypeConfig,
) -> Vec<(EntityId, Vec<TimeRange>)> {
    let bounds = bookable_extent(request_window, now_utc, config);
    host_masks
        .into_iter()
        .map(|(host, mask)| {
            let clipped = bounds
                .map(|bounds| {
                    mask.into_iter()
                        .filter_map(|range| intersect(range, bounds))
                        .collect()
                })
                .unwrap_or_default();
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
pub(super) fn apply_event_type_knobs(
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
pub(super) fn subtract_live_holds(
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

/// Collapses the per-host candidates and retains the exact routing choice.
/// Either selects the lowest entity ID among hosts offering the whole slot;
/// Both retains every host only when all offer it. Input order is irrelevant.
#[must_use]
pub(super) fn route_host_masks(
    host_masks: Vec<(EntityId, Vec<TimeRange>)>,
    mode: RoutingMode,
) -> Vec<SlotHostBinding> {
    let host_count = host_masks.len();
    let mut routed = std::collections::BTreeMap::<(u64, u64), Vec<String>>::new();
    for (host, slots) in host_masks {
        for slot in slots {
            routed
                .entry((slot.start, slot.end))
                .or_default()
                .push(host.to_hex());
        }
    }
    routed
        .into_iter()
        .filter_map(|((start_utc, end_utc), mut host_refs)| {
            host_refs.sort();
            host_refs.dedup();
            match mode {
                RoutingMode::Either => host_refs.truncate(1),
                RoutingMode::Both if host_refs.len() != host_count => return None,
                RoutingMode::Both => {}
            }
            Some(SlotHostBinding {
                start_utc,
                end_utc,
                host_refs,
            })
        })
        .collect()
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
pub(super) fn rank_and_emit(
    slots: Vec<SlotHostBinding>,
    config: &EventTypeConfig,
    constraint: Option<&ConstraintObject>,
    visitor_tz: &str,
    counts: &BookingCounts,
) -> SolveResult {
    let admitted: Vec<TimeRange> = slots
        .iter()
        .map(|slot| TimeRange {
            start: slot.start_utc,
            end: slot.end_utc,
        })
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
    let host_bindings = slots
        .into_iter()
        .filter(|binding| {
            ranked
                .iter()
                .any(|slot| slot.start_utc == binding.start_utc && slot.end_utc == binding.end_utc)
        })
        .collect();
    SolveResult {
        slots: ranked,
        flex_used: false,
        host_bindings,
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
