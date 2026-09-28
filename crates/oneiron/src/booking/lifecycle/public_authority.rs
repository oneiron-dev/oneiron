//! Transactional public authority check for all four lifecycle mutations.
use super::claim::read_booking_facts;
use super::storage::{
    HOLD, booking_writer, confirm_receipt_key, engine_failure, read_receipt, refused,
};
use super::token::{hold_digest, resolve_token_event, token_digest};
use super::types::{BookingVerbRequest, LifecycleTokenScope};
use crate::Vault;
use crate::booking::BookingError;
use crate::booking::publication::PublicBookingAuthority;

pub(super) fn booking_writer_with_publication<T>(
    vault: &Vault,
    authority: Option<&PublicBookingAuthority>,
    request: &BookingVerbRequest,
    now: u64,
    apply: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T, BookingError>,
) -> Result<T, BookingError> {
    booking_writer(vault, |txn| {
        check_publication_in_writer(vault, txn, authority, request, now)?;
        let result = apply(txn)?;
        // Include time spent solving and staging the mutation. A refusal here
        // aborts every staged lifecycle row, not just the response.
        check_publication_in_writer(vault, txn, authority, request, now)?;
        Ok(result)
    })
}

fn check_publication_in_writer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: Option<&PublicBookingAuthority>,
    request: &BookingVerbRequest,
    now_utc: u64,
) -> Result<(), BookingError> {
    let Some(authority) = authority else {
        return Ok(());
    };
    let (page, event) = match request {
        BookingVerbRequest::Hold(spec) => (spec.page_ref, spec.event_type.clone()),
        BookingVerbRequest::Confirm(spec) => {
            let receipt_key = confirm_receipt_key(&token_digest(&spec.hold_token));
            if let Some(receipt) = read_receipt(vault, txn, &receipt_key)? {
                let facts = read_booking_facts(vault, txn, &receipt.event_ref)?;
                (facts.page_ref, facts.event_type)
            } else {
                let hold = HOLD
                    .get(&vault.store, txn, &hold_digest(&spec.session_key))
                    .map_err(|error| engine_failure("meta read", error))?
                    .ok_or_else(|| refused("no hold exists for this session"))?;
                (hold.page_ref, hold.event_type)
            }
        }
        BookingVerbRequest::Reschedule(spec) => {
            let event =
                resolve_token_event(vault, txn, &spec.token, LifecycleTokenScope::Reschedule)?;
            let facts = read_booking_facts(vault, txn, &event)?;
            (facts.page_ref, facts.event_type)
        }
        BookingVerbRequest::Cancel(spec) => {
            let event = resolve_token_event(vault, txn, &spec.token, LifecycleTokenScope::Cancel)?;
            let facts = read_booking_facts(vault, txn, &event)?;
            (facts.page_ref, facts.event_type)
        }
    };
    // Admission's sampled clock is not the commit clock. A delayed attempt
    // must not retain an expired publication even if its caller reuses `now`.
    authority.check_in_txn(
        vault,
        txn,
        page,
        &event,
        vault.store.clock.now_recorded_at().max(now_utc),
    )
}
