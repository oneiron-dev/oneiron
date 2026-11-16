//! Transactional public authority check for every lifecycle mutation.
use super::claim::{read_booking_facts, read_booking_facts_to_cancel};
use super::storage::{
    HOLD, booking_writer, confirm_receipt_key, engine_failure, read_receipt, refused,
};
use super::token::{hold_digest, resolve_token_event, token_digest};
use super::types::{BookingVerbRequest, LifecycleTokenScope};
use super::waitlist::waitlist_publication_scope;
use crate::booking::publication::PublicBookingAuthority;
use crate::booking::{BookingError, EventTypeKey};
use crate::{EntityId, Vault};

pub(super) fn booking_writer_with_publication<T>(
    vault: &Vault,
    authority: Option<&PublicBookingAuthority>,
    request: &BookingVerbRequest,
    now: u64,
    apply: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<T, BookingError>,
) -> Result<T, BookingError> {
    booking_writer(vault, |txn| {
        let scope = match authority {
            Some(authority) => {
                let scope = publication_scope_in_writer(vault, txn, request)?;
                check_publication_in_writer(vault, txn, authority, &scope, now)?;
                Some((authority, scope))
            }
            None => None,
        };
        let result = apply(txn)?;
        // Include time spent solving and staging the mutation, on the scope
        // read before it: the mutation may end the row that scope was read
        // from (a waitlist leave, a claim whose slot was taken). A refusal
        // here aborts every staged lifecycle row, not just the response.
        if let Some((authority, scope)) = &scope {
            check_publication_in_writer(vault, txn, authority, scope, now)?;
        }
        Ok(result)
    })
}

/// The page and event type a lifecycle request acts on, read in its writer
/// before the request mutates anything.
fn publication_scope_in_writer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &BookingVerbRequest,
) -> Result<(EntityId, EventTypeKey), BookingError> {
    Ok(match request {
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
            let facts = read_booking_facts_to_cancel(vault, txn, &event)?;
            (facts.page_ref, facts.event_type)
        }
        BookingVerbRequest::Waitlist(spec) => waitlist_publication_scope(vault, txn, spec)?,
    })
}

fn check_publication_in_writer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: &PublicBookingAuthority,
    (page, event): &(EntityId, EventTypeKey),
    now_utc: u64,
) -> Result<(), BookingError> {
    // Admission's sampled clock is not the commit clock. A delayed attempt
    // must not retain an expired publication even if its caller reuses `now`.
    authority.check_in_txn(
        vault,
        txn,
        *page,
        event,
        vault.store.clock.now_recorded_at().max(now_utc),
    )
}
