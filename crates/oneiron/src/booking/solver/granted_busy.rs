//! A booking caller's own calendar view (ARCH-0062 #grant-view; owner ruling
//! BOOKING-GRANT-VIEW = A, 2026-10-20).
//!
//! A caller whose live calendar grants name every calendar a host binds sees
//! that host's busy blocks beside the slots; a caller without such grants sees
//! the public default. EVENTs are not yet tied to their calendar entity: the
//! solver asks CAL through one unfiltered selector per host, CAL-02's calendar
//! selector being unbuilt. So the view is held to what the slot answer already
//! implies (Engine ruling L3-10, 2026-11-13): the solver's own busy union,
//! clipped to the host's working hours over the bookable part of the asked
//! window, at the `Busy` rung at most. Titles and details wait for that
//! selector.

use super::interval::{half_open, intersect};
use super::oracle::BookingSolver;
use super::stages::{bookable_extent, working_hours_mask};
use crate::access_grant::CalendarAccessGrantRow;
use crate::booking::agent_api::GrantedBusyView;
use crate::booking::config::HostAvailabilityConfig;
use crate::booking::disclosure_rung::{
    DisclosureRung, EventDetailsRow, EventRow, RungProjection, SurfaceClass, project_at_rung,
};
use crate::booking::{BookingError, SolveRequest};
use crate::entity_id::EntityId;
use crate::memory::ProducerRows;
use crate::temporal::TimeRange;

impl BookingSolver<'_> {
    /// The busy blocks `caller`'s live calendar grants show on this solver's
    /// page for `req`: one view per host whose every bound calendar a grant
    /// names at `Busy` or above, in configuration order. `None` when no host
    /// qualifies, so the answer reads exactly as a caller's without a grant.
    ///
    /// Each grant is judged at `now_utc` through
    /// [`AccessGrant::calendar_disclosure_rung`](crate::access_grant::AccessGrant::calendar_disclosure_rung)
    /// (active, unexpired, a read grant naming `caller` and the calendar), on
    /// every call: nothing here is cached. The grants that decided are listed
    /// in `producers` beside the rows the busy union read.
    ///
    /// # Errors
    ///
    /// [`BookingError`] for an unusable configuration, a grant or calendar
    /// read that fails, or a projection the `Busy` rung refuses.
    pub fn granted_busy(
        &self,
        req: &SolveRequest,
        caller: &EntityId,
        producers: Option<&ProducerRows>,
    ) -> Result<Option<Vec<GrantedBusyView>>, BookingError> {
        let requested = half_open(req.window)?;
        let mut config = self.resolved_config(req, producers)?;
        let mut calendars: Vec<EntityId> = config
            .hosts
            .iter()
            .flat_map(|host| host.calendar_refs.iter().copied())
            .collect();
        calendars.sort_unstable();
        calendars.dedup();
        let grants = self
            .vault
            .list_calendar_access_grants_naming(&calendars)
            .map_err(|error| BookingError::SlotOracle(format!("calendar grants: {error}")))?;
        let mut deciding = Vec::new();
        config.hosts.retain(|host| {
            granted_host_rung(host, &grants, caller, self.now_utc, &mut deciding)
                .is_some_and(|rung| DisclosureRung::Busy.narrower(rung) == DisclosureRung::Busy)
        });
        if config.hosts.is_empty() {
            return Ok(None);
        }
        if let Some(producers) = producers {
            producers.list(deciding);
        }
        let Some(window) = bookable_extent(requested, self.now_utc, &config) else {
            return Ok(Some(
                config
                    .hosts
                    .iter()
                    .map(|host| busy_view(host, Vec::new()))
                    .collect(),
            ));
        };
        let hours = working_hours_mask(&config, window)?;
        let busy = self.busy_by_host(&config, window, producers)?;
        config
            .hosts
            .iter()
            .map(|host| {
                let hours = hours
                    .iter()
                    .find(|(id, _)| *id == host.host_ref)
                    .map_or(&[][..], |(_, ranges)| ranges.as_slice());
                let union = busy
                    .iter()
                    .find(|(id, _)| *id == host.host_ref)
                    .map_or(&[][..], |(_, union)| union.as_slice());
                let rows: Vec<EventRow> = union
                    .iter()
                    .flat_map(|interval| {
                        let occupied = TimeRange {
                            start: interval.start_utc,
                            end: interval.end_utc,
                        };
                        hours.iter().filter_map(move |range| {
                            intersect(occupied, *range).map(|piece| EventRow {
                                event_ref: interval.source,
                                start_utc: piece.start,
                                end_utc: piece.end,
                                title: None,
                                details: EventDetailsRow {
                                    description: None,
                                    location: None,
                                    attendee_refs: Vec::new(),
                                },
                            })
                        })
                    })
                    .collect();
                let RungProjection::Busy(blocks) =
                    project_at_rung(&rows, DisclosureRung::Busy, SurfaceClass::CrossVault, None)?
                else {
                    return Err(BookingError::Surface(
                        "a granted busy view projected off the busy rung".to_owned(),
                    ));
                };
                Ok(busy_view(host, blocks))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }
}

/// The rung `caller`'s live grants give one host: for each calendar the host
/// binds, the widest rung a grant naming it gives; across them, the narrowest.
/// `None` when any bound calendar has no live grant for `caller`. The grant
/// that gave each calendar its rung is pushed to `deciding`.
fn granted_host_rung(
    host: &HostAvailabilityConfig,
    grants: &[CalendarAccessGrantRow],
    caller: &EntityId,
    now: u64,
    deciding: &mut Vec<EntityId>,
) -> Option<DisclosureRung> {
    let mut host_rung: Option<DisclosureRung> = None;
    let mut used = Vec::with_capacity(host.calendar_refs.len());
    for calendar in &host.calendar_refs {
        let (grant_ref, rung) = grants
            .iter()
            .filter_map(|row| {
                row.grant
                    .calendar_disclosure_rung(caller, calendar, now)
                    .map(|rung| (row.grant_ref, rung))
            })
            .reduce(|widest, next| {
                if widest.1.narrower(next.1) == widest.1 {
                    next
                } else {
                    widest
                }
            })?;
        used.push(grant_ref);
        host_rung = Some(host_rung.map_or(rung, |narrowest| narrowest.narrower(rung)));
    }
    deciding.extend(used);
    host_rung
}

/// One host's view: its bound calendars by hex id, beside its busy blocks.
fn busy_view(
    host: &HostAvailabilityConfig,
    busy: Vec<crate::booking::BusyBlockRow>,
) -> GrantedBusyView {
    GrantedBusyView {
        calendar_refs: host.calendar_refs.iter().map(EntityId::to_hex).collect(),
        busy,
    }
}
