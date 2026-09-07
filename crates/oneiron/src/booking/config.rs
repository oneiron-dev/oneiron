//! ONE-1823 [BK-00] booking-page event-type configuration.
//!
//! One live `booking.event_type` claim configures one `(page_ref,
//! EventTypeKey)` pair: durations, buffers, notice, caps, routing, and the
//! per-host working/preferred/flex wall-clock windows the solver turns into UTC
//! availability. Updating a configuration supersedes the previous claim; there
//! is no second store and no configuration entity.
//!
//! The claim subject is an existing booking-page/lens `EntityId` supplied by the
//! caller. No entity byte is allocated here and no registry row is added.
//!
//! # Wall time stays wall time
//!
//! [`WeeklyWallWindow`] rows are civil minute-of-day windows in a host's IANA
//! zone. Nothing in this module converts them: conversion happens once, in
//! [`crate::booking::solver`], through the calendar TZ border. A configuration
//! is therefore portable across DST transitions — the same "09:00-17:00 Monday"
//! row means 09:00-17:00 local on both sides of a transition.

use std::io::Cursor;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::booking::{BookingError, EventTypeKey};
use crate::claim::{ClaimBody, ClaimSubject, claim_surfaceable};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// The one booking-page configuration predicate. Matching is exact everywhere:
/// no `booking.` prefix is ever accepted as family membership.
pub const BOOKING_EVENT_TYPE_PREDICATE: &str = "booking.event_type";

/// Wire version of a [`BookingEventTypeClaimValue`]. Any other version fails
/// closed rather than being coerced.
pub const BOOKING_EVENT_TYPE_SCHEMA_VERSION: u64 = 1;

/// Node-local `vault_meta` index prefix for the `(page_ref, key)` shortcut,
/// mirroring `comm.rs`'s `PARTY_INDEX_PREFIX`.
pub const BOOKING_EVENT_TYPE_META_PREFIX: &[u8] = b"booking.event_type.v1:";

/// Ratified intro-call default. 25-30 minutes; never 15.
pub const DEFAULT_INTRO_DURATION_MIN: u16 = 30;

/// Ratified default minimum notice: 24 hours.
pub const DEFAULT_MIN_NOTICE_SECS: u64 = 24 * 3_600;

/// Ratified high-value preset minimum notice: 48 hours.
pub const HIGH_VALUE_MIN_NOTICE_SECS: u64 = 48 * 3_600;

/// The furthest ahead a page may open.
///
/// The horizon is what bounds ONE solve: the solver reaches over it to ask CAL
/// for a busy union and to walk each host's local days, so an unbounded horizon
/// is an unbounded read and an unbounded loop. A year and a day is far past any
/// real booking page — the ratified deployment default is this week and next —
/// and keeps the day walk under four hundred iterations per host.
pub const MAX_BOOKING_WINDOW_SECS: u64 = 366 * 24 * 3_600;

/// Exclusive upper bound for a civil minute-of-day. `1440` is admissible as an
/// *end* minute and denotes the following midnight.
pub(crate) const MINUTES_PER_DAY: u16 = 1_440;

/// Weekday axis width. Rows are `0 = Monday ..= 6 = Sunday`.
pub(crate) const DAYS_PER_WEEK: u8 = 7;

/// Bound on an [`EventTypeKey`], matching the seam's timezone-identifier bound.
const MAX_EVENT_TYPE_KEY_BYTES: usize = 64;

/// How a multi-host event type turns per-host availability into offered slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Any one host suffices: the union of the hosts' slots.
    Either,
    /// Every host must attend: the intersection of the hosts' slots.
    Both,
}

/// One recurring civil window in a host's zone.
///
/// Half-open `[start_minute, end_minute)` minutes from local midnight, so
/// `end_minute == MINUTES_PER_DAY` means "to the following midnight" and two
/// adjacent rows never double-count the boundary minute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeeklyWallWindow {
    /// `0 = Monday ..= 6 = Sunday`.
    pub weekday: u8,
    /// Inclusive, `0..MINUTES_PER_DAY`.
    pub start_minute: u16,
    /// Exclusive, `start_minute < end_minute <= MINUTES_PER_DAY`.
    pub end_minute: u16,
}

impl WeeklyWallWindow {
    fn defect(&self) -> Option<&'static str> {
        if self.weekday >= DAYS_PER_WEEK {
            return Some("booking.event_type weekday must be 0 (Monday) through 6 (Sunday)");
        }
        if self.start_minute >= self.end_minute || self.end_minute > MINUTES_PER_DAY {
            return Some("booking.event_type wall window must satisfy 0 <= start < end <= 1440");
        }
        None
    }
}

/// One host's availability configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAvailabilityConfig {
    #[serde(with = "entity_ref_serde")]
    pub host_ref: EntityId,
    /// The calendars whose busy union occupies this host's time.
    #[serde(with = "entity_refs_serde")]
    pub calendar_refs: Vec<EntityId>,
    /// IANA zone the wall windows below are written in.
    pub host_tz: String,
    /// When this host is bookable at all.
    pub working_hours: Vec<WeeklyWallWindow>,
    /// A subset of bookable time this host would rather be booked in. Ranking
    /// only: a preferred window never widens availability.
    pub preferred_hours: Vec<WeeklyWallWindow>,
}

impl HostAvailabilityConfig {
    fn defect(&self) -> Option<&'static str> {
        if self.host_tz.is_empty() {
            return Some("booking.event_type host_tz must name an IANA zone");
        }
        if self.calendar_refs.is_empty() {
            return Some("booking.event_type host must bind at least one calendar");
        }
        self.working_hours
            .iter()
            .chain(&self.preferred_hours)
            .find_map(WeeklyWallWindow::defect)
    }
}

/// The full configuration for one event type on one booking page.
///
/// No `Eq`: the seam's [`EventTypeKey`] carries only `PartialEq`, and this
/// module does not widen a seam derive it does not own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventTypeConfig {
    pub key: EventTypeKey,
    pub duration_min: u16,
    /// Candidate starts are aligned to this step on a UTC grid anchored at the
    /// epoch, so every host offers the same instants and routing is set algebra.
    pub slot_step_min: u16,
    /// Free time required before a meeting.
    pub pre_buffer_min: u16,
    /// Free time required after a meeting.
    pub post_buffer_min: u16,
    /// Earliest a visitor may book, measured from request time.
    pub min_notice_secs: u64,
    /// How far ahead the page opens, measured from request time.
    pub booking_window_secs: u64,
    /// Confirmed bookings allowed per visitor-local day.
    pub daily_cap: Option<u16>,
    /// Confirmed bookings allowed per visitor-local week (Monday-anchored).
    pub weekly_cap: Option<u16>,
    pub routing: RoutingMode,
    pub hosts: Vec<HostAvailabilityConfig>,
    /// Extra host-local windows offered only when ordinary availability is
    /// empty. Interpreted in each host's own zone, exactly like working hours.
    pub flex_windows: Vec<WeeklyWallWindow>,
}

impl EventTypeConfig {
    /// The one defect table for a configuration.
    ///
    /// `None` means usable. Both public skins — [`Self::validate`] for the
    /// solver and [`validate_event_type_claim`] for the claim write door — read
    /// this table, so a configuration the write door accepted is one the solver
    /// can run, by construction.
    fn defect(&self) -> Option<&'static str> {
        let key = self.key.0.as_str();
        if key.trim().is_empty() || key.len() > MAX_EVENT_TYPE_KEY_BYTES {
            return Some("booking.event_type key must be 1..=64 non-blank bytes");
        }
        if self.duration_min == 0 {
            return Some("booking.event_type duration_min must be positive");
        }
        if self.slot_step_min == 0 {
            return Some("booking.event_type slot_step_min must be positive");
        }
        if self.booking_window_secs == 0 || self.booking_window_secs > MAX_BOOKING_WINDOW_SECS {
            return Some("booking.event_type booking_window_secs must be 1 second to 366 days");
        }
        if self.hosts.is_empty() {
            return Some("booking.event_type must configure at least one host");
        }
        if let Some(defect) = self
            .hosts
            .iter()
            .find_map(HostAvailabilityConfig::defect)
            .or_else(|| self.flex_windows.iter().find_map(WeeklyWallWindow::defect))
        {
            return Some(defect);
        }
        let mut hosts: Vec<&EntityId> = self.hosts.iter().map(|host| &host.host_ref).collect();
        hosts.sort_unstable();
        if hosts.windows(2).any(|pair| pair[0] == pair[1]) {
            return Some("booking.event_type host_ref must be unique");
        }
        None
    }

    /// Solver-facing validation.
    ///
    /// # Errors
    ///
    /// [`BookingError::InvalidConfig`] naming the first defect found.
    pub fn validate(&self) -> std::result::Result<(), BookingError> {
        self.defect().map_or(Ok(()), |reason| {
            Err(BookingError::InvalidConfig(reason.to_owned()))
        })
    }
}

/// The stored `booking.event_type` claim value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingEventTypeClaimValue {
    pub schema_version: u64,
    /// The booking page this configuration belongs to; equals the claim subject.
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
    pub config: EventTypeConfig,
}

// -------------------------------------------------------------------------
// Claim codec
//
// `ClaimBody::value` is opaque MessagePack. The typed value above already
// derives serde, so the codec bridges through `rmp_serde`'s named encoding
// rather than hand-rolling a nested `rmpv` walk — the same bridge
// `companion.rs` uses for its opaque record values.
// -------------------------------------------------------------------------

/// Encodes a claim value to the opaque MessagePack a `ClaimBody` carries.
///
/// # Errors
///
/// [`BookingError::InvalidConfig`] when the value is not encodable.
pub fn encode_event_type_claim_value(
    value: &BookingEventTypeClaimValue,
) -> std::result::Result<rmpv::Value, BookingError> {
    let bytes = rmp_serde::to_vec_named(value).map_err(|error| {
        BookingError::InvalidConfig(format!("booking.event_type value does not encode: {error}"))
    })?;
    rmpv::decode::read_value(&mut Cursor::new(bytes.as_slice())).map_err(|error| {
        BookingError::InvalidConfig(format!("booking.event_type value does not encode: {error}"))
    })
}

/// Decodes and structurally validates a stored claim value.
///
/// # Errors
///
/// [`BookingError::InvalidConfig`] on a malformed value, an unsupported schema
/// version, or a configuration defect.
pub fn decode_event_type_claim_value(
    value: &rmpv::Value,
) -> std::result::Result<BookingEventTypeClaimValue, BookingError> {
    let decoded = decode_claim_value_shape(value)
        .map_err(|reason| BookingError::InvalidConfig(reason.to_owned()))?;
    decoded.config.validate()?;
    Ok(decoded)
}

/// The shape half of the decode, sharing one reason table with the claim
/// write door.
fn decode_claim_value_shape(
    value: &rmpv::Value,
) -> std::result::Result<BookingEventTypeClaimValue, &'static str> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| "booking.event_type value is not encodable MessagePack")?;
    let decoded: BookingEventTypeClaimValue = rmp_serde::from_slice(&bytes)
        .map_err(|_| "booking.event_type value does not match the pinned schema")?;
    if decoded.schema_version != BOOKING_EVENT_TYPE_SCHEMA_VERSION {
        return Err("booking.event_type schema_version is unsupported");
    }
    Ok(decoded)
}

// -------------------------------------------------------------------------
// Claim family door
// -------------------------------------------------------------------------

/// Whether `predicate` is the booking claim family.
///
/// Exact match against the one predicate this family owns. A permissive
/// `booking.` prefix would silently adopt every future booking predicate into
/// this validator, so the family is a table, not a namespace.
#[must_use]
pub fn is_booking_claim_predicate(predicate: &str) -> bool {
    predicate == BOOKING_EVENT_TYPE_PREDICATE
        || predicate == crate::booking::publication::BOOKING_PUBLIC_PAGE_PREDICATE
}

/// One pure-data descriptor row, mirroring ARCH-0057 §4 fields.
///
/// No descriptor runtime exists in engine Rust yet; this table is ready to
/// register when the registry lands and is authoritative documentation until
/// then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimClassDescriptorRow {
    /// The predicate this row describes.
    pub predicate: &'static str,
    /// One of `"recorded"`, `"human_ruled"`, or `"ordinary"`.
    pub write_class: &'static str,
    /// Whether writes are enforcement-gated.
    pub enforcement: bool,
    /// Whether the class is restrictive (consent-bearing).
    pub restrictive: bool,
    /// Whether only an engine projector may write the class.
    pub projector_only: bool,
}

/// Descriptor rows for the whole `booking.*` family, one per exact predicate.
///
/// `booking.event_type` is ordinary host configuration: an owner writes it from
/// a page editor, no projector owns it, and it carries no consent axis of its
/// own — the disclosure rung and the access grant are where consent lives.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    vec![
        ClaimClassDescriptorRow {
            predicate: BOOKING_EVENT_TYPE_PREDICATE,
            write_class: "ordinary",
            enforcement: false,
            restrictive: false,
            projector_only: false,
        },
        ClaimClassDescriptorRow {
            predicate: crate::booking::publication::BOOKING_PUBLIC_PAGE_PREDICATE,
            write_class: "human_ruled",
            enforcement: true,
            restrictive: true,
            projector_only: false,
        },
    ]
}

/// Validates one `booking.event_type` claim body's subject and value shape.
///
/// Structural only, and exact: an unknown `booking.*` predicate is rejected
/// here rather than accepted as a family member.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] naming the defect.
pub(crate) fn validate_event_type_claim(body: &ClaimBody) -> Result<()> {
    if body.predicate == crate::booking::publication::BOOKING_PUBLIC_PAGE_PREDICATE {
        return crate::booking::publication::validate_public_booking_page_claim(body);
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(Error::InvalidClaimBody(
            "booking claim subject must be an entity",
        ));
    };
    if !is_booking_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody("unknown booking claim predicate"));
    }
    let decoded = decode_claim_value_shape(&body.value).map_err(Error::InvalidClaimBody)?;
    if decoded.page_ref != subject {
        return Err(Error::InvalidClaimBody(
            "booking.event_type page_ref must match the claim subject",
        ));
    }
    decoded
        .config
        .defect()
        .map_or(Ok(()), |reason| Err(Error::InvalidClaimBody(reason)))
}

// -------------------------------------------------------------------------
// Configuration lookup
// -------------------------------------------------------------------------

/// The node-local shortcut key for one `(page_ref, key)` pair.
///
/// Public because the page editor that writes the configuration maintains the
/// shortcut, and it must key it exactly as the read side resolves it.
#[must_use]
pub fn event_type_index_key(page_ref: EntityId, key: &EventTypeKey) -> Vec<u8> {
    let mut material = Vec::with_capacity(page_ref.as_bytes().len() + key.0.len());
    material.extend_from_slice(page_ref.as_bytes());
    material.extend_from_slice(key.0.as_bytes());
    let digest = blake3::hash(&material);
    let mut index_key = Vec::with_capacity(BOOKING_EVENT_TYPE_META_PREFIX.len() + 32);
    index_key.extend_from_slice(BOOKING_EVENT_TYPE_META_PREFIX);
    index_key.extend_from_slice(digest.as_bytes());
    index_key
}

/// Resolves the live configuration for `(page_ref, key)`.
///
/// The `vault_meta` shortcut is node-local cache state; the synced truth is the
/// surfaceable `booking.event_type` claim attached to `page_ref`. A shortcut miss —
/// or a shortcut naming a superseded or mismatched claim — therefore means
/// "look again", never "absent": a claim that arrived by replication
/// materializes its entity and `claim_of` edge but no local index row, and
/// treating that as absence would report a configured page as unconfigured.
///
/// When several surfaceable claims share a key the lexicographically smallest
/// claim id wins, so every node resolves the same configuration.
///
/// # Errors
///
/// [`BookingError::InvalidConfig`] when no live configuration exists or the
/// stored one is malformed; [`BookingError::SlotOracle`] on a storage failure.
pub(crate) fn load_event_type_config(
    vault: &Vault,
    page_ref: EntityId,
    key: &EventTypeKey,
) -> std::result::Result<EventTypeConfig, BookingError> {
    let rtxn = vault.store.env.read_txn().map_err(storage_failure)?;
    load_event_type_config_in_txn(vault, &rtxn, page_ref, key)
}

pub(super) fn load_event_type_config_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    page_ref: EntityId,
    key: &EventTypeKey,
) -> std::result::Result<EventTypeConfig, BookingError> {
    let shortcut = vault
        .store
        .vault_meta
        .get(rtxn, &event_type_index_key(page_ref, key))
        .map_err(storage_failure)?
        .and_then(|raw| <[u8; 16]>::try_from(raw.as_ref()).ok())
        .and_then(|bytes| EntityId::from_bytes(bytes).ok());
    if let Some(id) = shortcut
        && let Some(config) = live_config_in_txn(vault, rtxn, &id, page_ref, key)?
    {
        return Ok(config);
    }

    let mut claims = vault
        .claims_for_subject_in_txn(rtxn, &page_ref)
        .map_err(storage_failure)?;
    claims.sort_unstable();
    for id in &claims {
        if let Some(config) = live_config_in_txn(vault, rtxn, id, page_ref, key)? {
            return Ok(config);
        }
    }
    Err(BookingError::InvalidConfig(format!(
        "no live booking.event_type configuration for event type {}",
        key.0
    )))
}

/// The configuration `id` carries, when `id` is a live `booking.event_type`
/// claim on `page_ref` for `key`. Any other row is `None`, not an error: a page
/// carries claims from many families.
///
/// Liveness is the engine's canonical read gate, [`claim_surfaceable`], not
/// lifecycle alone: approval, lifecycle, and staleness are independent axes, and
/// a page's public availability must not be driven by a configuration that is
/// merely proposed, was rejected, or has gone stale.
fn live_config_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    page_ref: EntityId,
    key: &EventTypeKey,
) -> std::result::Result<Option<EventTypeConfig>, BookingError> {
    let Ok(Some(body)) = vault.get_claim_in_txn(rtxn, id) else {
        return Ok(None);
    };
    if body.predicate != BOOKING_EVENT_TYPE_PREDICATE
        || body.subject != ClaimSubject::Entity(page_ref)
        || !claim_surfaceable(&body)
    {
        return Ok(None);
    }
    // Past this point the row IS this page's live configuration claim, so a
    // malformed body is a typed failure rather than a silent miss that would
    // fall through to "unconfigured".
    let decoded = decode_event_type_claim_value(&body.value)?;
    Ok((decoded.config.key == *key).then_some(decoded.config))
}

fn storage_failure<E>(_: E) -> BookingError {
    BookingError::SlotOracle("booking configuration lookup failed to read the vault".to_owned())
}

// -------------------------------------------------------------------------
// serde adapters
//
// `EntityId` carries no serde impl, so configuration values cross the wire as
// lowercase hex — the same `serde(with = ...)` shape ONE-1812 uses in
// `crate::booking::disclosure_rung`.
// -------------------------------------------------------------------------

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
            .into_iter()
            .map(|hex| EntityId::from_hex(&hex).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::ClaimLifecycleStatus;
    use crate::test_util::entity as id;

    const PAGE: u8 = 0x51;
    const HOST: u8 = 0x52;
    const CALENDAR: u8 = 0x53;

    pub(super) fn intro_config() -> EventTypeConfig {
        EventTypeConfig {
            key: EventTypeKey("intro-call".to_owned()),
            duration_min: DEFAULT_INTRO_DURATION_MIN,
            slot_step_min: 30,
            pre_buffer_min: 0,
            post_buffer_min: 0,
            min_notice_secs: DEFAULT_MIN_NOTICE_SECS,
            booking_window_secs: 14 * 24 * 3_600,
            daily_cap: None,
            weekly_cap: None,
            routing: RoutingMode::Either,
            hosts: vec![HostAvailabilityConfig {
                host_ref: id(HOST),
                calendar_refs: vec![id(CALENDAR)],
                host_tz: "UTC".to_owned(),
                working_hours: vec![WeeklyWallWindow {
                    weekday: 0,
                    start_minute: 9 * 60,
                    end_minute: 17 * 60,
                }],
                preferred_hours: Vec::new(),
            }],
            flex_windows: Vec::new(),
        }
    }

    fn claim_value(config: EventTypeConfig) -> BookingEventTypeClaimValue {
        BookingEventTypeClaimValue {
            schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
            page_ref: id(PAGE),
            config,
        }
    }

    pub(super) fn claim_body(value: &BookingEventTypeClaimValue) -> ClaimBody {
        ClaimBody::new(
            BOOKING_EVENT_TYPE_PREDICATE,
            ClaimSubject::Entity(value.page_ref),
            encode_event_type_claim_value(value).expect("encode claim value"),
            1.0,
            crate::claim::ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
    }

    #[test]
    fn intro_default_is_30_minutes_and_never_15() {
        assert_eq!(DEFAULT_INTRO_DURATION_MIN, 30);
        assert_ne!(DEFAULT_INTRO_DURATION_MIN, 15);
        assert_eq!(intro_config().duration_min, 30);
        assert_eq!(DEFAULT_MIN_NOTICE_SECS, 86_400);
        assert_eq!(HIGH_VALUE_MIN_NOTICE_SECS, 172_800);
    }

    #[test]
    fn claim_value_round_trips_through_messagepack() {
        let value = claim_value(intro_config());
        let encoded = encode_event_type_claim_value(&value).expect("encode");
        assert_eq!(
            decode_event_type_claim_value(&encoded).expect("decode"),
            value
        );
    }

    #[test]
    fn booking_event_type_validator_is_exact() {
        let value = claim_value(intro_config());
        let body = claim_body(&value);
        validate_event_type_claim(&body).expect("a structurally valid configuration is accepted");

        // An unknown `booking.*` predicate is NOT family membership.
        let mut foreign = claim_body(&value);
        foreign.predicate = "booking.hold".to_owned();
        assert!(!is_booking_claim_predicate(&foreign.predicate));
        assert!(validate_event_type_claim(&foreign).is_err());

        // Subject mismatch, malformed value, and every configuration defect.
        let mut wrong_subject = claim_body(&value);
        wrong_subject.subject = ClaimSubject::Entity(id(0x54));
        assert!(validate_event_type_claim(&wrong_subject).is_err());

        let mut junk = claim_body(&value);
        junk.value = rmpv::Value::from("not a configuration");
        assert!(validate_event_type_claim(&junk).is_err());

        let mut stale_version = claim_value(intro_config());
        stale_version.schema_version = BOOKING_EVENT_TYPE_SCHEMA_VERSION + 1;
        assert!(validate_event_type_claim(&claim_body(&stale_version)).is_err());
    }

    /// One named mutation that must turn a valid configuration invalid.
    type Defect = (&'static str, Box<dyn Fn(&mut EventTypeConfig)>);

    #[test]
    fn configuration_defects_are_named_by_one_table() {
        let cases: Vec<Defect> = vec![
            (
                "blank key",
                Box::new(|c| c.key = EventTypeKey("  ".to_owned())),
            ),
            ("zero duration", Box::new(|c| c.duration_min = 0)),
            ("zero step", Box::new(|c| c.slot_step_min = 0)),
            ("zero window", Box::new(|c| c.booking_window_secs = 0)),
            (
                "unbounded window",
                Box::new(|c| c.booking_window_secs = MAX_BOOKING_WINDOW_SECS + 1),
            ),
            ("no hosts", Box::new(|c| c.hosts.clear())),
            ("blank tz", Box::new(|c| c.hosts[0].host_tz.clear())),
            (
                "no calendars",
                Box::new(|c| c.hosts[0].calendar_refs.clear()),
            ),
            (
                "weekday out of range",
                Box::new(|c| c.hosts[0].working_hours[0].weekday = 7),
            ),
            (
                "inverted window",
                Box::new(|c| c.hosts[0].working_hours[0].end_minute = 0),
            ),
            (
                "window past midnight",
                Box::new(|c| c.hosts[0].working_hours[0].end_minute = MINUTES_PER_DAY + 1),
            ),
            (
                "duplicate host",
                Box::new(|c| {
                    let host = c.hosts[0].clone();
                    c.hosts.push(host);
                }),
            ),
            (
                "flex window defect",
                Box::new(|c| {
                    c.flex_windows.push(WeeklyWallWindow {
                        weekday: 0,
                        start_minute: 60,
                        end_minute: 60,
                    });
                }),
            ),
        ];
        for (label, break_it) in cases {
            let mut config = intro_config();
            break_it(&mut config);
            assert!(config.validate().is_err(), "{label} must be rejected");
            // The write door and the solver read the same table.
            let value = claim_value(config);
            assert!(
                validate_event_type_claim(&claim_body(&value)).is_err(),
                "{label}"
            );
        }
        // The boundary case a half-open end minute must ACCEPT.
        let mut midnight = intro_config();
        midnight.hosts[0].working_hours[0].end_minute = MINUTES_PER_DAY;
        midnight
            .validate()
            .expect("a window ending at midnight is valid");
        // The longest horizon a page may open, which bounds one solve's work.
        let mut widest = intro_config();
        widest.booking_window_secs = MAX_BOOKING_WINDOW_SECS;
        widest
            .validate()
            .expect("a year-and-a-day horizon is valid");
    }

    #[test]
    fn booking_claim_descriptor_rows_are_complete() {
        let rows = claim_class_descriptors();
        assert_eq!(rows.len(), 2, "one row per exact predicate");
        assert_eq!(rows[0].predicate, BOOKING_EVENT_TYPE_PREDICATE);
        assert!(is_booking_claim_predicate(rows[0].predicate));
        for row in &rows {
            assert!(
                ["recorded", "human_ruled", "ordinary"].contains(&row.write_class),
                "{} carries an unknown write class",
                row.predicate
            );
        }
    }

    #[test]
    fn booking_event_type_index_uses_canonical_prefix() {
        let key = EventTypeKey("intro-call".to_owned());
        let index_key = event_type_index_key(id(PAGE), &key);
        assert!(index_key.starts_with(BOOKING_EVENT_TYPE_META_PREFIX));
        assert_eq!(BOOKING_EVENT_TYPE_META_PREFIX, b"booking.event_type.v1:");
        assert_eq!(
            index_key.len(),
            BOOKING_EVENT_TYPE_META_PREFIX.len() + 32,
            "the shortcut key is the prefix plus one digest"
        );
        // Both axes of the pair are in the digest.
        assert_ne!(index_key, event_type_index_key(id(0x54), &key));
        assert_ne!(
            index_key,
            event_type_index_key(id(PAGE), &EventTypeKey("deep-dive".to_owned()))
        );
    }
}
