//! Active future bookings charged to a page's contact cap.

use super::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE,
    BookingBookerContactValue, BookingSourcePageValue, BookingStatus, BookingStatusValue,
};
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::{EntityId, Vault};

/// Counts one contact's active future bookings on a page in one snapshot.
/// Outstanding owner confirmations cannot supply the booking facts. An unknown
/// occurrence end still counts; a known end counts only when it is after `now`.
pub fn active_future_booking_count_for_contact(
    vault: &Vault,
    page_ref: EntityId,
    contact_ref: EntityId,
    now: u64,
) -> crate::Result<u8> {
    let txn = vault.store.env.read_txn()?;
    let mut count: u8 = 0;
    for id in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_EVENT, None)?
    {
        let event_ref = id?;
        let Some(record) = vault.store.port_entity_record(&txn, &event_ref)? else {
            continue;
        };
        if record.entity_type == ENTITY_TYPE_EVENT
            && booking_is_active_future_for_in_txn(
                vault,
                &txn,
                event_ref,
                page_ref,
                contact_ref,
                now,
            )?
        {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn booking_is_active_future_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: EntityId,
    page_ref: EntityId,
    contact_ref: EntityId,
    now: u64,
) -> crate::Result<bool> {
    let (mut same_page, mut same_contact, mut confirmed) = (false, false, false);
    for claim_id in vault.claims_for_subject_in_txn(txn, &event_ref)? {
        let Some(body) = vault
            .get_claim_for_effect_in_txn(txn, &claim_id)?
            .filter(claim_surfaceable)
        else {
            continue;
        };
        if body.subject != ClaimSubject::Entity(event_ref) {
            continue;
        }
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                same_page = decode_claim_value::<BookingSourcePageValue>(&body.value)
                    .is_some_and(|value| value.page_ref == page_ref);
            }
            BOOKING_BOOKER_CONTACT_PREDICATE => {
                same_contact = decode_claim_value::<BookingBookerContactValue>(&body.value)
                    .is_some_and(|value| value.contact_ref == contact_ref);
            }
            BOOKING_STATUS_PREDICATE => {
                confirmed = decode_claim_value::<BookingStatusValue>(&body.value)
                    .is_some_and(|value| value.status == BookingStatus::Confirmed);
            }
            _ => {}
        }
    }
    if !(same_page && same_contact && confirmed) {
        return Ok(false);
    }
    let occurrence = crate::calendar::query::event_row_for_effect_in_txn(vault, txn, event_ref)?;
    Ok(occurrence.is_none_or(|row| row.occurred.is_none_or(|at| at.end > now)))
}

fn decode_claim_value<T: serde::de::DeserializeOwned>(value: &rmpv::Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}
