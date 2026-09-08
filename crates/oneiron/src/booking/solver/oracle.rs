//! BookingSolver: the SlotOracle implementation and pipeline driver.

use super::civil_date::visitor_zone_error;
use super::{BookingCounts, load_booking_counts};
use super::hold_source::ActiveHoldSource;
use super::interval::{half_open, inclusive};
use super::stages::{
    apply_buffers, apply_event_type_knobs, attach_busy_union, bookable_extent, buffer_pad,
    enforce_notice_and_window, rank_and_emit, route_host_masks, subtract_live_holds,
    working_hours_mask,
};
use crate::booking::config::{EventTypeConfig, RoutingMode, load_event_type_config};
use crate::booking::constraint::validate_visitor_tz;
use crate::booking::{BookingError, SlotOracle, SolveRequest, SolveResult};
use crate::calendar::freebusy::{BusyUnion, freebusy};
use crate::calendar::query::CalendarSel;
use crate::calendar::tz::utc_to_wall;
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;

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
    fn solve_bound(
        &self,
        req: &SolveRequest,
        hosts: &[String],
    ) -> Result<SolveResult, BookingError> {
        let mut config = match &self.synthetic_config {
            Some(config) => config.clone(),
            None => load_event_type_config(self.vault, self.page_ref, &req.event_type)?,
        };
        if hosts.is_empty()
            || hosts.iter().any(|owner| {
                !config
                    .hosts
                    .iter()
                    .any(|host| host.host_ref.to_hex() == *owner)
            })
        {
            return Err(BookingError::InvalidConfig(
                "bound booking hosts are unavailable".to_owned(),
            ));
        }
        config
            .hosts
            .retain(|host| hosts.contains(&host.host_ref.to_hex()));
        config.routing = if hosts.len() == 1 {
            RoutingMode::Either
        } else {
            RoutingMode::Both
        };
        BookingSolver {
            vault: self.vault,
            page_ref: self.page_ref,
            calendars_by_host: self.calendars_by_host,
            holds: self.holds,
            now_utc: self.now_utc,
            synthetic_config: Some(config),
        }
        .solve(req)
    }

    fn solve(&self, req: &SolveRequest) -> Result<SolveResult, BookingError> {
        // The visitor zone is validated at the calendar border, not guessed:
        // a malformed zone fails typed here rather than falling back to UTC.
        validate_visitor_tz(&req.visitor_tz)?;
        utc_to_wall(self.now_utc, &req.visitor_tz).map_err(visitor_zone_error)?;
        if let Some(constraint) = &req.constraint {
            constraint.validate()?;
        }

        let requested = half_open(req.window)?;
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

        // The bookable extent is settled BEFORE anything is read, because it is
        // what bounds the read. A caller may ask for centuries; the horizon is
        // configuration, and configuration is bounded.
        let Some(window) = bookable_extent(requested, self.now_utc, &config) else {
            return Ok(SolveResult {
                slots: Vec::new(),
                flex_used: false,
                host_bindings: Vec::new(),
            });
        };
        // CAL is asked over the extent PADDED by this event type's buffers: a
        // busy interval just outside the horizon still casts its buffer inside
        // it, and an unpadded query would drop exactly those blockers.
        let pad = buffer_pad(&config);
        let busy_by_host = self.busy_by_host(
            &config,
            TimeRange {
                start: window.start.saturating_sub(pad),
                end: window.end.saturating_add(pad),
            },
        )?;
        let counts = load_booking_counts(
            self.vault,
            self.page_ref,
            &req.event_type,
            inclusive(window),
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
