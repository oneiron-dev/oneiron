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
use crate::side_table::{self, Raw, SideTable};
use crate::vault::Vault;

#[doc(hidden)]
pub(super) use oneiron_records::booking::config::DAYS_PER_WEEK;
#[doc(hidden)]
pub(crate) use oneiron_records::booking::config::MINUTES_PER_DAY;
#[doc(hidden)]
pub use oneiron_records::booking::config::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    EventTypeConfig, HostAvailabilityConfig, MAX_BOOKING_WINDOW_SECS, RoutingMode,
    WeeklyWallWindow, decode_event_type_claim_value,
};
#[doc(hidden)]
use oneiron_records::booking::config::{
    decode_claim_value_shape, entity_ref_serde, entity_refs_serde, event_type_index_digest,
    storage_failure,
};

/// Node-local `vault_meta` index prefix for the `(page_ref, key)` shortcut,
/// mirroring `comm.rs`'s `PARTY_INDEX_PREFIX`.
pub const BOOKING_EVENT_TYPE_META_PREFIX: &[u8] = b"booking.event_type.v1:";

/// Ratified intro-call default. 25-30 minutes; never 15.
pub const DEFAULT_INTRO_DURATION_MIN: u16 = 30;

/// Ratified default minimum notice: 24 hours.
pub const DEFAULT_MIN_NOTICE_SECS: u64 = 24 * 3_600;

/// Ratified high-value preset minimum notice: 48 hours.
pub const HIGH_VALUE_MIN_NOTICE_SECS: u64 = 48 * 3_600;

// -------------------------------------------------------------------------
// Claim codec
//
// `ClaimBody::value` is opaque MessagePack. The typed value above already
// derives serde, so the codec bridges through `rmp_serde`'s named encoding
// rather than hand-rolling a nested `rmpv` walk.
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
    let mut index_key = Vec::with_capacity(BOOKING_EVENT_TYPE_META_PREFIX.len() + 32);
    index_key.extend_from_slice(BOOKING_EVENT_TYPE_META_PREFIX);
    index_key.extend_from_slice(&event_type_index_digest(page_ref, key));
    index_key
}

/// The node-local `(page_ref, key)` shortcut: the entity id of the live
/// configuration claim last resolved for this pair. Key: hash32
/// ([`event_type_index_digest`]).
const EVENT_TYPE_SHORTCUT: SideTable<[u8; 32], EntityId, Raw> =
    SideTable::new(&side_table::BOOKING_EVENT_TYPE_CONFIG_SHORTCUT);

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
pub(super) fn load_event_type_config(
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
    load_event_type_config_listed_in_txn(vault, rtxn, page_ref, key).map(|(config, _)| config)
}

/// [`load_event_type_config`], beside the `booking.event_type` claim it
/// decoded the configuration from (FIX 4777).
pub(super) fn load_event_type_config_listed(
    vault: &Vault,
    page_ref: EntityId,
    key: &EventTypeKey,
) -> std::result::Result<(EventTypeConfig, EntityId), BookingError> {
    let rtxn = vault.store.env.read_txn().map_err(storage_failure)?;
    load_event_type_config_listed_in_txn(vault, &rtxn, page_ref, key)
}

/// [`load_event_type_config_in_txn`], beside the claim it decoded.
pub(super) fn load_event_type_config_listed_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    page_ref: EntityId,
    key: &EventTypeKey,
) -> std::result::Result<(EventTypeConfig, EntityId), BookingError> {
    // A malformed shortcut is a cache miss like any other: the scan below is
    // always the authoritative fallback.
    let shortcut = EVENT_TYPE_SHORTCUT
        .get_lenient(&vault.store, rtxn, &event_type_index_digest(page_ref, key))
        .map_err(storage_failure)?;
    if let Some(id) = shortcut
        && let Some(config) = live_config_in_txn(vault, rtxn, &id, page_ref, key)?
    {
        return Ok((config, id));
    }

    let mut claims = vault
        .claims_for_subject_in_txn(rtxn, &page_ref)
        .map_err(storage_failure)?;
    claims.sort_unstable();
    for id in &claims {
        if let Some(config) = live_config_in_txn(vault, rtxn, id, page_ref, key)? {
            return Ok((config, *id));
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
    if decoded.config.key != *key {
        return Ok(None);
    }
    // A configuration both opens the page and carries its limits, so a held
    // one neither applies nor lets another configuration stand in for it.
    if !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, rtxn, id)
        .map_err(storage_failure)?
    {
        return Err(BookingError::InvalidConfig(format!(
            "the booking.event_type configuration for event type {} awaits its owner's confirm",
            key.0
        )));
    }
    Ok(Some(decoded.config))
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
        .unwrap()
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

    #[test]
    fn a_held_configuration_neither_applies_nor_lets_a_wider_one_win() {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
        let at = crate::temporal::TimeRange { start: 1, end: 1 };
        vault
            .put_entity(
                &id(PAGE),
                crate::registry::ENTITY_TYPE_ASSET,
                at,
                1,
                b"page",
            )
            .expect("page");
        // The lower claim id decides: the capped configuration sorts first.
        let mut capped = intro_config();
        capped.daily_cap = Some(1);
        let narrow = id(0x61);
        for (claim, config) in [(narrow, capped), (id(0x62), intro_config())] {
            vault
                .put_claim(&claim, &claim_body(&claim_value(config)), at, 1)
                .expect("config claim");
        }
        let key = EventTypeKey("intro-call".to_owned());
        let settled = load_event_type_config(&vault, id(PAGE), &key).expect("settled config");
        assert_eq!(settled.daily_cap, Some(1));

        crate::test_util::hold_claim_for_critical_confirm(&vault, narrow, 0x71);
        assert!(
            matches!(
                load_event_type_config(&vault, id(PAGE), &key),
                Err(BookingError::InvalidConfig(_))
            ),
            "a held deciding configuration opens nothing, and the uncapped one must not win"
        );
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
