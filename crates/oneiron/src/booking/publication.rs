//! Owner-controlled public booking publication on the ordinary claim store.
//!
//! `booking.public_page` is a single-cardinality claim on the existing page.
//! Publish/update uses `Memory::claim_upsert` (or `commit`); revoke uses the same
//! write with `published = false`, or `claim_retract`. Claim validity is the
//! capability's half-open lifetime. No index, grant inference, or allowlist is
//! publication authority. Theme and human copy are supplied by the owner.

use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::booking::agent_api::BookingAvailabilityInput;
use crate::booking::{
    BookingError, ConstraintFieldConfig, EventTypeCard, EventTypeKey, MAX_BOOKING_WINDOW_SECS,
    ThemeTokens,
};
use crate::claim::{ClaimBody, ClaimSource, ClaimSubject, claim_surfaceable};
use crate::edge::EdgeActorClass;
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY,
};
use crate::{EntityId, Error, Result, TimeRange, Vault};

pub const BOOKING_PUBLIC_PAGE_PREDICATE: &str = "booking.public_page";
pub const BOOKING_PUBLIC_PAGE_SCHEMA_VERSION: u64 = 1;

/// Relative, bounded initial availability. It advances with the request clock,
/// rather than persisting stale slots or an absolute window that runs out.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBookingAvailability {
    pub event_type: EventTypeKey,
    pub start_after_secs: u64,
    pub window_secs: u64,
    pub visitor_tz: String,
}

impl PublicBookingAvailability {
    pub fn request(
        &self,
        now: u64,
        session_ref: String,
    ) -> std::result::Result<BookingAvailabilityInput, BookingError> {
        self.validate()
            .map_err(|reason| BookingError::InvalidConfig(reason.to_owned()))?;
        let start = now.checked_add(self.start_after_secs).ok_or_else(|| {
            BookingError::InvalidConfig("public booking window overflow".to_owned())
        })?;
        let end = start.checked_add(self.window_secs - 1).ok_or_else(|| {
            BookingError::InvalidConfig("public booking window overflow".to_owned())
        })?;
        Ok(BookingAvailabilityInput {
            event_type: self.event_type.clone(),
            window: TimeRange { start, end },
            visitor_tz: self.visitor_tz.clone(),
            constraint: None,
            session_ref,
        })
    }

    fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.window_secs < 2
            || self
                .start_after_secs
                .checked_add(self.window_secs)
                .is_none_or(|end| end > MAX_BOOKING_WINDOW_SECS)
        {
            return Err("public booking initial window must be bounded to 366 days");
        }
        if crate::calendar::tz::utc_to_wall(86_400, &self.visitor_tz).is_err() {
            return Err("public booking visitor_tz must name an IANA zone");
        }
        Ok(())
    }
}

/// Stored value, not a second public render protocol. The render model adds
/// ONLY the solver's final Slots projection to this author-owned presentation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingPagePublication {
    pub schema_version: u64,
    pub published: bool,
    pub owner_display: String,
    pub event_types: Vec<EventTypeCard>,
    pub constraint_field: ConstraintFieldConfig,
    pub theme: ThemeTokens,
    pub initial_availability: PublicBookingAvailability,
}

impl BookingPagePublication {
    fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.schema_version != BOOKING_PUBLIC_PAGE_SCHEMA_VERSION {
            return Err("booking.public_page schema_version is unsupported");
        }
        if self.owner_display.trim().is_empty() || self.event_types.is_empty() {
            return Err("public booking requires owner display and event cards");
        }
        for (index, event) in self.event_types.iter().enumerate() {
            if event.key.0.trim().is_empty()
                || event.key.0.len() > 64
                || event.title.trim().is_empty()
                || event.duration_min == 0
                || self.event_types[..index]
                    .iter()
                    .any(|prior| prior.key == event.key)
            {
                return Err(
                    "public booking event cards must have unique keys, titles and durations",
                );
            }
        }
        if !self
            .event_types
            .iter()
            .any(|event| event.key == self.initial_availability.event_type)
        {
            return Err("public booking initial availability must name a published event card");
        }
        self.initial_availability.validate()
        // ThemeTokens is deliberately not inspected, defaulted, or interpreted.
    }
}

pub fn encode_public_booking_page_value(value: &BookingPagePublication) -> Result<rmpv::Value> {
    value.validate().map_err(Error::InvalidClaimBody)?;
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvalidClaimBody("public booking value does not encode"))?;
    rmpv::decode::read_value(&mut Cursor::new(bytes))
        .map_err(|_| Error::InvalidClaimBody("public booking value does not encode"))
}

pub fn decode_public_booking_page_value(value: &rmpv::Value) -> Result<BookingPagePublication> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvalidClaimBody("public booking value is not MessagePack"))?;
    let decoded: BookingPagePublication = rmp_serde::from_slice(&bytes)
        .map_err(|_| Error::InvalidClaimBody("public booking value does not match its schema"))?;
    decoded.validate().map_err(Error::InvalidClaimBody)?;
    Ok(decoded)
}

/// Structural claim gate, used by the existing booking/config family dispatcher
/// at every claim write door, including batch and rematerialization.
/// Authority is checked separately against the same write/read transaction.
pub(crate) fn validate_public_booking_page_claim(body: &ClaimBody) -> Result<()> {
    if body.predicate != BOOKING_PUBLIC_PAGE_PREDICATE
        || !matches!(body.subject, ClaimSubject::Entity(_))
        || body.scope.is_some()
        || body.world.is_some()
        || body.session_tag.is_some()
        || body.source != Some(ClaimSource::UserStated)
        || publication_owner(body).is_none()
    {
        return Err(Error::InvalidClaimBody(
            "public booking publication requires an unscoped owner claim",
        ));
    }
    if body.lifecycle == crate::claim::ClaimLifecycleStatus::Active
        && !matches!((body.valid_from, body.valid_to), (Some(start), Some(end)) if start < end)
    {
        return Err(Error::InvalidClaimBody(
            "public booking publication requires a bounded validity window",
        ));
    }
    decode_public_booking_page_value(&body.value)?;
    Ok(())
}

/// Actor identity comes from the engine's write envelope, never presentation.
fn publication_owner(body: &ClaimBody) -> Option<EntityId> {
    let rmpv::Value::Map(evidence) = body.evidence.as_ref()? else {
        return None;
    };
    let field = |key: &str| {
        let mut matches = evidence
            .iter()
            .filter(|(name, _)| name.as_str() == Some(key));
        let (_, value) = matches.next()?;
        matches.next().is_none().then_some(value)
    };
    if field(WRITE_ENVELOPE_EVIDENCE_ACTOR_CLASS_KEY)?.as_u64()
        != Some(EdgeActorClass::Human as u64)
    {
        return None;
    }
    let rmpv::Value::Binary(bytes) = field(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)? else {
        return None;
    };
    EntityId::from_bytes(bytes.as_slice().try_into().ok()?).ok()
}

/// Resolve one genuinely live publication. An absent, stale, proposed, revoked,
/// expired, malformed, owner-unbound, or ambiguous publication is not public.
/// The read boundary validates again: replayed bytes are not a writer promise.
pub fn load_public_booking_page(
    vault: &Vault,
    page_ref: EntityId,
    now: u64,
) -> Result<Option<BookingPagePublication>> {
    let rtxn = vault.store.env.read_txn()?;
    if !crate::vault::live_entity_row_in_txn(&vault.store, &rtxn, &page_ref)?.is_live() {
        return Ok(None);
    }
    let mut publication = None;
    let mut active_count = 0;
    for id in vault.claims_for_subject_in_txn(&rtxn, &page_ref)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if body.predicate != BOOKING_PUBLIC_PAGE_PREDICATE
            || body.subject != ClaimSubject::Entity(page_ref)
            || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        {
            continue;
        }
        // Never select an older allow around a concurrent deny or pending head.
        active_count += 1;
        if active_count > 1 {
            return Ok(None);
        }
        if !claim_surfaceable(&body)
            || validate_public_booking_page_claim(&body).is_err()
            || body.valid_from.is_none_or(|start| now < start)
            || body.valid_to.is_none_or(|end| now >= end)
        {
            return Ok(None);
        }
        let Some(owner) = publication_owner(&body) else {
            return Ok(None);
        };
        if crate::memory::verify_public_booking_owner_in_txn(vault, &rtxn, owner).is_err() {
            return Ok(None);
        }
        let value = decode_public_booking_page_value(&body.value)?;
        if !value.published {
            return Ok(None);
        }
        for card in &value.event_types {
            let config = match crate::booking::config::load_event_type_config_in_txn(
                vault, &rtxn, page_ref, &card.key,
            ) {
                Ok(config) => config,
                Err(BookingError::InvalidConfig(_)) => return Ok(None),
                Err(_) => {
                    return Err(Error::InvalidConfig(
                        "public booking configuration read failed".to_owned(),
                    ));
                }
            };
            if u32::from(config.duration_min) != card.duration_min {
                return Ok(None);
            }
        }
        publication = Some(value);
    }
    Ok(publication)
}

#[cfg(test)]
mod tests;
