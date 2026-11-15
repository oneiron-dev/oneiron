//! Moved from `crates/oneiron/src/booking/disclosure_rung.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::constraint::SlotMask;
use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::booking::constraint::BookingError;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

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
pub fn validate_slot_mask(mask: &SlotMask) -> Result<(), BookingError> {
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
/// `TimeRange` in `constraint`.
pub mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub fn serialize<S: Serializer>(value: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

pub mod entity_refs_serde {
    use super::{Deserialize, Deserializer, EntityId, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &[EntityId], serializer: S) -> Result<S::Ok, S::Error> {
        value
            .iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|hex| EntityId::from_hex(&hex).map_err(serde::de::Error::custom))
            .collect()
    }
}
