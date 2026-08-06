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

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::access_grant::AccessGrant;
use crate::booking::{BookingError, SlotMask};
use crate::entity_id::EntityId;

/// How much of a calendar one audience may see.
///
/// The ladder descends: `Full` discloses the most, `Nothing` the least. Compare
/// rungs with [`DisclosureRung::narrower`] — never with a derived `Ord`, whose
/// direction would read backwards against declaration order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureRung {
    /// Event titles and details.
    Full,
    /// Busy blocks with titles, but no bodies or attendees.
    Titles,
    /// Opaque intervals only.
    Busy,
    /// Derived bookable slots only; never events, never busy intervals.
    Slots,
    /// No rows.
    Nothing,
}

impl DisclosureRung {
    /// How much this rung discloses. Higher discloses more.
    const fn disclosure_level(self) -> u8 {
        match self {
            Self::Full => 4,
            Self::Titles => 3,
            Self::Busy => 2,
            Self::Slots => 1,
            Self::Nothing => 0,
        }
    }

    /// The rung that discloses less — the `min` every boundary clamp applies.
    #[must_use]
    pub const fn narrower(self, other: Self) -> Self {
        if other.disclosure_level() < self.disclosure_level() {
            other
        } else {
            self
        }
    }

    /// The pinned on-disk/on-wire string for this rung.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Titles => "titles",
            Self::Busy => "busy",
            Self::Slots => "slots",
            Self::Nothing => "nothing",
        }
    }

    /// Parses a pinned rung string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full" => Some(Self::Full),
            "titles" => Some(Self::Titles),
            "busy" => Some(Self::Busy),
            "slots" => Some(Self::Slots),
            "nothing" => Some(Self::Nothing),
            _ => None,
        }
    }
}

/// The boundary a read crosses.
///
/// The ceiling is applied INSIDE [`project_at_rung`], so no caller can raise a
/// surface above its class by forgetting to clamp: a public page is capped at
/// [`DisclosureRung::Slots`] however generous the grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceClass {
    /// The reader is inside the calendar's own vault.
    SameVault,
    /// An authenticated reader in a different vault — family, workplace, peer.
    CrossVault,
    /// An unauthenticated public surface. Hard ceiling: `Slots`.
    Public,
}

impl SurfaceClass {
    /// The highest rung this surface may ever show, whatever was granted.
    #[must_use]
    pub const fn ceiling(self) -> DisclosureRung {
        match self {
            Self::SameVault | Self::CrossVault => DisclosureRung::Full,
            Self::Public => DisclosureRung::Slots,
        }
    }
}

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

/// The detail half of a source event row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventDetailsRow {
    pub description: Option<String>,
    pub location: Option<String>,
    #[serde(with = "entity_refs_serde")]
    pub attendee_refs: Vec<EntityId>,
}

/// One source event, as an adapter prepares it for projection.
///
/// A projection DTO, not an entity kind: nothing here allocates an entity byte
/// and nothing here is stored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EventRow {
    #[serde(with = "entity_ref_serde")]
    pub event_ref: EntityId,
    pub start_utc: u64,
    /// Half-open `[start_utc, end_utc)`.
    pub end_utc: u64,
    pub title: Option<String>,
    pub details: EventDetailsRow,
}

/// A `Titles`-rung row: interval and title, no body and no attendees.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TitledEventRow {
    #[serde(with = "entity_ref_serde")]
    pub event_ref: EntityId,
    pub start_utc: u64,
    pub end_utc: u64,
    pub title: Option<String>,
}

/// A `Busy`-rung row: an opaque interval carrying no event material at all.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BusyBlockRow {
    pub start_utc: u64,
    pub end_utc: u64,
}

/// What crosses a vault or public boundary. Never source event bytes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "rung", content = "rows", rename_all = "snake_case")]
pub enum RungProjection {
    Full(Vec<EventRow>),
    Titles(Vec<TitledEventRow>),
    Busy(Vec<BusyBlockRow>),
    Slots(SlotMask),
    Nothing,
}

impl RungProjection {
    /// The rung this projection was produced at.
    #[must_use]
    pub const fn rung(&self) -> DisclosureRung {
        match self {
            Self::Full(_) => DisclosureRung::Full,
            Self::Titles(_) => DisclosureRung::Titles,
            Self::Busy(_) => DisclosureRung::Busy,
            Self::Slots(_) => DisclosureRung::Slots,
            Self::Nothing => DisclosureRung::Nothing,
        }
    }
}

/// The single projection entry point.
///
/// The effective rung is `min(granted, surface.ceiling())` — computed HERE, so
/// a server caller that forgets the public ceiling still cannot leak above it.
/// Adapters may prepare [`EventRow`]s and the solver may prepare a
/// [`SlotMask`], but no caller may hand-roll a weaker redaction.
///
/// Every non-`Full` arm constructs fresh redacted values rather than handing
/// back raw rows. The `Slots` arm requires a caller-precomputed, solver-produced
/// mask: `None` is a [`BookingError`], never a silently empty mask that would
/// read as "no availability".
pub fn project_at_rung(
    events: &[EventRow],
    granted: DisclosureRung,
    surface: SurfaceClass,
    slot_mask: Option<&SlotMask>,
) -> Result<RungProjection, BookingError> {
    match granted.narrower(surface.ceiling()) {
        DisclosureRung::Full => Ok(RungProjection::Full(events.to_vec())),
        DisclosureRung::Titles => Ok(RungProjection::Titles(
            events.iter().map(TitledEventRow::redacted_from).collect(),
        )),
        DisclosureRung::Busy => Ok(RungProjection::Busy(
            events.iter().map(BusyBlockRow::opaque_from).collect(),
        )),
        DisclosureRung::Slots => {
            let mask = slot_mask.ok_or_else(|| {
                BookingError::Surface(
                    "slots projection requires a solver-precomputed slot mask".to_owned(),
                )
            })?;
            validate_slot_mask(mask)?;
            Ok(RungProjection::Slots(mask.clone()))
        }
        DisclosureRung::Nothing => Ok(RungProjection::Nothing),
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
    reader_ref: &EntityId,
    calendar_ref: &EntityId,
    events: &[EventRow],
    surface: SurfaceClass,
    slot_mask: Option<&SlotMask>,
) -> Result<RungProjection, BookingError> {
    let granted = grant
        .calendar_disclosure_rung(reader_ref, calendar_ref)
        .unwrap_or(DisclosureRung::Nothing);
    project_at_rung(events, granted, surface, slot_mask)
}

impl TitledEventRow {
    /// Builds a fresh titled row, dropping body, location, and attendees.
    fn redacted_from(row: &EventRow) -> Self {
        Self {
            event_ref: row.event_ref,
            start_utc: row.start_utc,
            end_utc: row.end_utc,
            title: row.title.clone(),
        }
    }
}

impl BusyBlockRow {
    /// Builds a fresh opaque interval, dropping the event's identity entirely.
    fn opaque_from(row: &EventRow) -> Self {
        Self {
            start_utc: row.start_utc,
            end_utc: row.end_utc,
        }
    }
}

/// Rejects a mask whose window or slots are not half-open `[start, end)`.
///
/// The `Slots` rung is the one that reaches public surfaces, so a degenerate or
/// out-of-window mask must not leave this chokepoint as "availability".
fn validate_slot_mask(mask: &SlotMask) -> Result<(), BookingError> {
    if mask.window_start_utc >= mask.window_end_utc {
        return Err(BookingError::Surface(format!(
            "slot mask window is not half-open: [{}, {})",
            mask.window_start_utc, mask.window_end_utc
        )));
    }
    for slot in &mask.slots {
        if slot.start_utc >= slot.end_utc
            || slot.start_utc < mask.window_start_utc
            || slot.end_utc > mask.window_end_utc
        {
            return Err(BookingError::Surface(format!(
                "slot [{}, {}) escapes the mask window [{}, {})",
                slot.start_utc, slot.end_utc, mask.window_start_utc, mask.window_end_utc
            )));
        }
    }
    Ok(())
}

/// `EntityId` carries no serde derives, so projection DTOs cross the wire as
/// lowercase hex — the same `serde(with = ...)` shape ONE-1816 uses for
/// `TimeRange` in [`crate::booking::constraint`].
mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

mod entity_refs_serde {
    use super::{Deserialize, Deserializer, EntityId, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &[EntityId],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|hex| EntityId::from_hex(hex).map_err(serde::de::Error::custom))
            .collect()
    }
}

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
        }
    }

    #[test]
    fn default_disclosure_rung_matches_arch0062_r1() {
        assert_eq!(
            default_disclosure_rung(CalendarDisclosureDefault::FamilyCalendarMember),
            DisclosureRung::Full
        );
        assert_eq!(
            default_disclosure_rung(CalendarDisclosureDefault::WorkplaceWorkCalendarMember),
            DisclosureRung::Full
        );
        assert_eq!(
            default_disclosure_rung(CalendarDisclosureDefault::PersonalToWorkplace),
            DisclosureRung::Busy
        );
        assert_eq!(
            default_disclosure_rung(CalendarDisclosureDefault::PublicSurface),
            DisclosureRung::Slots
        );
    }

    #[test]
    fn narrower_descends_the_ladder_in_both_argument_orders() {
        assert_eq!(
            DisclosureRung::Full.narrower(DisclosureRung::Slots),
            DisclosureRung::Slots
        );
        assert_eq!(
            DisclosureRung::Slots.narrower(DisclosureRung::Full),
            DisclosureRung::Slots
        );
        assert_eq!(
            DisclosureRung::Nothing.narrower(DisclosureRung::Full),
            DisclosureRung::Nothing
        );
        assert_eq!(
            DisclosureRung::Busy.narrower(DisclosureRung::Busy),
            DisclosureRung::Busy
        );
    }

    #[test]
    fn project_full_keeps_title_and_details() {
        let events = vec![event(1)];
        let projection =
            project_at_rung(&events, DisclosureRung::Full, SurfaceClass::SameVault, None)
                .expect("full projection");
        assert_eq!(projection, RungProjection::Full(events));
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
        let keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["event_ref", "start_utc", "end_utc", "title"]);
    }

    #[test]
    fn project_busy_is_opaque_intervals_only() {
        let events = vec![event(1)];
        let projection = project_at_rung(
            &events,
            DisclosureRung::Busy,
            SurfaceClass::CrossVault,
            None,
        )
        .expect("busy projection");
        let json = serde_json::to_string(&projection).expect("serialize busy projection");
        for leak in [
            "Therapy",
            "weekly session",
            "Clinic",
            &id(1).to_hex(),
            &id(0xAA).to_hex(),
            "event_ref",
            "title",
        ] {
            assert!(
                !json.contains(leak),
                "busy projection leaked {leak}: {json}"
            );
        }
        assert_eq!(
            projection,
            RungProjection::Busy(vec![BusyBlockRow {
                start_utc: 1_000,
                end_utc: 2_000
            }])
        );
    }

    #[test]
    fn project_nothing_returns_no_rows() {
        let projection = project_at_rung(
            &[event(1)],
            DisclosureRung::Nothing,
            SurfaceClass::SameVault,
            Some(&mask()),
        )
        .expect("nothing projection");
        assert_eq!(projection, RungProjection::Nothing);
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
    fn public_projection_clamps_titles_and_busy_to_slots_inside_chokepoint() {
        let mask = mask();
        for granted in [DisclosureRung::Titles, DisclosureRung::Busy] {
            let projection =
                project_at_rung(&[event(1)], granted, SurfaceClass::Public, Some(&mask))
                    .expect("clamped projection");
            assert_eq!(
                projection.rung(),
                DisclosureRung::Slots,
                "{granted:?} must clamp to slots on a public surface"
            );
        }
    }

    #[test]
    fn slots_projection_without_precomputed_mask_returns_booking_error() {
        let error = project_at_rung(
            &[event(1)],
            DisclosureRung::Full,
            SurfaceClass::Public,
            None,
        )
        .expect_err("public projection without a mask must fail");
        assert!(matches!(error, BookingError::Surface(_)), "{error:?}");

        // And never a silently empty mask.
        let error = project_at_rung(
            &[event(1)],
            DisclosureRung::Slots,
            SurfaceClass::SameVault,
            None,
        )
        .expect_err("slots projection without a mask must fail");
        assert!(matches!(error, BookingError::Surface(_)), "{error:?}");
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
                "flex_used"
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
            &reader,
            &calendar,
            &events,
            SurfaceClass::CrossVault,
            None,
        )
        .expect("cross-vault projection");
        let json = serde_json::to_string(&projection).expect("serialize projection");
        assert!(json.contains("\"rung\":\"busy\""), "{json}");
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

    #[test]
    fn projection_dtos_round_trip_through_serde() {
        let events = vec![event(1)];
        for projection in [
            RungProjection::Full(events.clone()),
            RungProjection::Titles(vec![TitledEventRow::redacted_from(&events[0])]),
            RungProjection::Busy(vec![BusyBlockRow::opaque_from(&events[0])]),
            RungProjection::Slots(mask()),
            RungProjection::Nothing,
        ] {
            let json = serde_json::to_string(&projection).expect("serialize");
            let restored: RungProjection = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, projection);
        }
    }
}
