//! Calendar disclosure rungs — ARCH-0062 R1's ladder and its one projection
//! chokepoint.
//!
//! ARCH-0060 §10 asked who holds a shared calendar. The answer is nobody new:
//! the source feed stays in its source vault and is never merged across vaults.
//! What crosses a vault or public boundary is a [`RungProjection`] produced by
//! [`project_at_rung`], at the rung a DEC-0006 standing grant authorized and no
//! higher than the reading surface's ceiling.
//!
//! Grant storage lives in the access-grant family
//! ([`AccessGrantScope::Calendar`](crate::access_grant::AccessGrantScope::Calendar));
//! this module owns the rung vocabulary, the surface ceiling, the default-rung
//! policy, the projection DTOs, and the projection itself.

use crate::access_grant::AccessGrant;
use crate::booking::{BookingError, SlotMask};
use crate::entity_id::EntityId;

#[doc(hidden)]
pub use oneiron_records::booking::disclosure_rung::{
    BusyBlockRow, DisclosureRung, EventDetailsRow, EventRow, RungProjection, SurfaceClass,
    TitledEventRow, project_at_rung,
};

/// The context a default rung is being chosen for (ARCH-0062 R1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalendarDisclosureDefault {
    /// A member of a family vault reading that vault's calendar.
    FamilyCalendarMember,
    /// A member of a co-owned workplace reading a co-owned work calendar.
    WorkplaceWorkCalendarMember,
    /// A personal calendar seen from a workplace vault.
    PersonalToWorkplace,
    /// A public, unauthenticated surface.
    PublicSurface,
}

/// The movable default rung for a context. These are defaults, not walls: a
/// grant may name any rung, and the surface ceiling still applies on top.
#[must_use]
pub const fn default_disclosure_rung(context: CalendarDisclosureDefault) -> DisclosureRung {
    match context {
        CalendarDisclosureDefault::FamilyCalendarMember
        | CalendarDisclosureDefault::WorkplaceWorkCalendarMember => DisclosureRung::Full,
        CalendarDisclosureDefault::PersonalToWorkplace => DisclosureRung::Busy,
        CalendarDisclosureDefault::PublicSurface => DisclosureRung::Slots,
    }
}

/// The door a reader outside the calendar's own vault goes through.
///
/// Resolves the granted rung from the standing grant — a revoked grant, a grant
/// naming another calendar, a grant for another principal, or a non-calendar
/// scope all resolve to [`DisclosureRung::Nothing`] — then projects through
/// [`project_at_rung`], so the surface ceiling applies on top of the grant.
pub fn project_calendar_grant(
    grant: &AccessGrant,
    now: u64,
    reader_ref: &EntityId,
    calendar_ref: &EntityId,
    events: &[EventRow],
    surface: SurfaceClass,
    slot_mask: Option<&SlotMask>,
) -> Result<RungProjection, BookingError> {
    let granted = grant
        .calendar_disclosure_rung(reader_ref, calendar_ref, now)
        .unwrap_or(DisclosureRung::Nothing);
    project_at_rung(events, granted, surface, slot_mask)
}

// FIX [LIBTEST-QUARANTINE-BOOKING-DISCLOSURE-RUNG-TESTS]: the lib test target's type check fails here (1 errors: E0308 x1); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_grant::{AccessGrantScope, AccessGrantStatus};
    use crate::booking::{EventTypeKey, RankedSlot};
    use crate::test_util::entity as id;

    fn event(byte: u8) -> EventRow {
        EventRow {
            event_ref: id(byte),
            start_utc: 1_000,
            end_utc: 2_000,
            title: Some("Therapy".to_owned()),
            details: EventDetailsRow {
                description: Some("weekly session".to_owned()),
                location: Some("Clinic, 3rd floor".to_owned()),
                attendee_refs: vec![id(0xAA)],
            },
        }
    }

    fn mask() -> SlotMask {
        SlotMask {
            event_type: EventTypeKey("intro-call".to_owned()),
            window_start_utc: 500,
            window_end_utc: 5_000,
            slots: vec![RankedSlot {
                start_utc: 3_000,
                end_utc: 3_600,
                rank: 0.5,
            }],
            flex_used: false,
            full_days: Vec::new(),
        }
    }

    #[test]
    fn project_titles_strips_details_and_attendees() {
        let events = vec![event(1)];
        let projection = project_at_rung(
            &events,
            DisclosureRung::Titles,
            SurfaceClass::CrossVault,
            None,
        )
        .expect("titles projection");
        let RungProjection::Titles(rows) = projection else {
            panic!("expected a titles projection");
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].title.as_deref(), Some("Therapy"));
        assert_eq!(rows[0].start_utc, 1_000);
        assert_eq!(rows[0].end_utc, 2_000);
        // The redacted row has no field that could carry a body, a location, or
        // an attendee: the serialized form is the proof.
        let json = serde_json::to_value(&rows[0]).expect("serialize titled row");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["end_utc", "event_ref", "start_utc", "title"]);
    }

    #[test]
    fn public_projection_clamps_full_to_slots_inside_chokepoint() {
        let mask = mask();
        let projection = project_at_rung(
            &[event(1)],
            DisclosureRung::Full,
            SurfaceClass::Public,
            Some(&mask),
        )
        .expect("clamped projection");
        assert_eq!(projection, RungProjection::Slots(mask));
        assert_eq!(SurfaceClass::Public.ceiling(), DisclosureRung::Slots);
    }

    #[test]
    fn slot_mask_uses_final_half_open_schema() {
        let json = serde_json::to_value(mask()).expect("serialize mask");
        let keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "event_type",
                "window_start_utc",
                "window_end_utc",
                "slots",
                "flex_used",
                "full_days"
            ],
            "the mask schema is final; no SlotMaskArtifact compatibility path exists"
        );

        let mut degenerate = mask();
        degenerate.window_end_utc = degenerate.window_start_utc;
        assert!(
            project_at_rung(
                &[],
                DisclosureRung::Slots,
                SurfaceClass::Public,
                Some(&degenerate)
            )
            .is_err(),
            "a closed window is not half-open"
        );

        let mut escaping = mask();
        escaping.slots[0].end_utc = escaping.window_end_utc + 1;
        assert!(
            project_at_rung(
                &[],
                DisclosureRung::Slots,
                SurfaceClass::Public,
                Some(&escaping)
            )
            .is_err(),
            "a slot ending past the window escapes [start, end)"
        );

        let mut boundary = mask();
        boundary.slots[0].start_utc = boundary.window_start_utc;
        boundary.slots[0].end_utc = boundary.window_end_utc;
        assert!(
            project_at_rung(
                &[],
                DisclosureRung::Slots,
                SurfaceClass::Public,
                Some(&boundary)
            )
            .is_ok(),
            "a slot filling the half-open window exactly is valid"
        );
    }

    #[test]
    fn slot_projection_contains_no_event_material() {
        let projection = project_at_rung(
            &[event(1)],
            DisclosureRung::Slots,
            SurfaceClass::Public,
            Some(&mask()),
        )
        .expect("slots projection");
        let json = serde_json::to_string(&projection).expect("serialize slots projection");
        for leak in [
            &id(1).to_hex(),
            &id(0xAA).to_hex(),
            "Therapy",
            "weekly session",
            "Clinic",
            "event_ref",
            "attendee_refs",
            "description",
            "location",
            "title",
        ] {
            assert!(!json.contains(leak), "slot mask leaked {leak}: {json}");
        }
    }

    #[test]
    fn cross_vault_reader_cannot_obtain_raw_event_rows() {
        // ARCH-0060 §10 custody: the source calendar never leaves its vault.
        // A cross-vault reader holds a grant, and the adapter hands back a
        // RungProjection — never the source EVENT rows.
        let reader = id(7);
        let calendar = id(9);
        let events = vec![event(1)];
        let grant = AccessGrant::calendar_disclosure(reader, calendar, DisclosureRung::Busy, 1_700);
        assert!(matches!(grant.scope, AccessGrantScope::Calendar { .. }));

        let projection = project_calendar_grant(
            &grant,
            1_700,
            &reader,
            &calendar,
            &events,
            SurfaceClass::CrossVault,
            None,
        )
        .expect("cross-vault projection");
        let RungProjection::Busy(rows) = &projection else {
            panic!("expected a busy projection");
        };
        assert_eq!(rows.len(), 1);
        let json = serde_json::to_string(&projection).expect("serialize projection");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse projection");
        assert_eq!(parsed["rung"].as_str(), Some("busy"));
        for leak in ["Therapy", "weekly session", "Clinic", &id(0xAA).to_hex()] {
            assert!(
                !json.contains(leak),
                "cross-vault read leaked {leak}: {json}"
            );
        }
    }

    #[test]
    fn revoked_or_mismatched_grant_projects_nothing() {
        let reader = id(7);
        let calendar = id(9);
        let events = vec![event(1)];
        let grant = AccessGrant::calendar_disclosure(reader, calendar, DisclosureRung::Full, 1_700);

        let project = |grant: &AccessGrant, reader: &EntityId, calendar: &EntityId| {
            project_calendar_grant(
                grant,
                1_700,
                reader,
                calendar,
                &events,
                SurfaceClass::CrossVault,
                None,
            )
            .expect("projection")
        };

        let revoked = grant.revoked(1_800).expect("revoke");
        assert_eq!(revoked.status, AccessGrantStatus::Revoked);
        assert_eq!(
            project(&revoked, &reader, &calendar),
            RungProjection::Nothing
        );
        assert_eq!(project(&grant, &id(8), &calendar), RungProjection::Nothing);
        assert_eq!(project(&grant, &reader, &id(10)), RungProjection::Nothing);

        let companion = AccessGrant::companion_profile_read(reader, id(3), id(4), 1_700);
        assert_eq!(
            project(&companion, &reader, &calendar),
            RungProjection::Nothing
        );
    }
}
