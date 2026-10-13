//! The outbound calendar passport written at sequence 0 and superseded by
//! reschedule and cancel.

use super::BookingContent;
use super::claim::put_claim;
use super::storage::{calendar_wrap, engine_failure, refused};
use super::types::{BOOKING_PASSPORT_SYSTEM, BookingStatus, CalendarRevision, SoftHoldRow};
use crate::booking::BookingError;
use crate::calendar::claims::{CalendarPassportPresence, PREDICATE_CALENDAR_PASSPORT};
use crate::calendar::passport::encode_passport_value;
use crate::calendar::{CalendarPassportDirection, CalendarPassportValue};
use crate::{EntityId, Vault};

/// Constructs the CAL-00-owned outbound passport value.
///
/// Persistence and index maintenance are CAL-02's; this only builds the value,
/// so no parallel passport type exists in booking.
fn outbound_passport_value(
    system: String,
    uid: String,
    sequence: u32,
    content_hash: [u8; 32],
    recorded_at: u64,
) -> CalendarPassportValue {
    CalendarPassportValue {
        system,
        uid,
        last_sequence: sequence,
        content_hash,
        direction: CalendarPassportDirection::Outbound,
        last_seen_at: recorded_at,
        presence: CalendarPassportPresence::Live,
    }
}

const CONTENT_HASH_DOMAIN: &[u8] = b"oneiron.booking.content.v1\0";

impl BookingContent {
    /// Content hash over the fields a revision can move, so passport drift is
    /// detectable without restating any calendar payload.
    fn hash(&self) -> [u8; 32] {
        if let Some(hash) = self.emergency_content_hash {
            return hash;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONTENT_HASH_DOMAIN);
        hasher.update(self.page_ref.as_bytes());
        hasher.update(self.event_type.0.as_bytes());
        hasher.update(&self.slot.start.to_be_bytes());
        hasher.update(&self.slot.end.to_be_bytes());
        hasher.update(self.status.as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Mints the outbound UID. Globally unique, and it carries no booker identity.
pub(super) fn mint_booking_uid(event_ref: &EntityId) -> String {
    format!("{}@{BOOKING_PASSPORT_SYSTEM}", event_ref.to_hex())
}

/// Writes the sequence-0 outbound passport claim for a new booking.
pub(super) fn write_outbound_passport(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    uid: &str,
    hold: &SoftHoldRow,
    now_utc: u64,
) -> Result<(), BookingError> {
    let content = BookingContent {
        page_ref: hold.page_ref,
        event_type: hold.event_type.clone(),
        slot: hold.slot,
        status: BookingStatus::Confirmed,
        emergency_content_hash: None,
    };
    let value = outbound_passport_value(
        BOOKING_PASSPORT_SYSTEM.to_owned(),
        uid.to_owned(),
        0,
        content.hash(),
        now_utc,
    );
    put_claim(
        vault,
        wtxn,
        event_ref,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&value),
        now_utc,
    )
    .map(|_| ())
}

/// The booking's outbound passport: its one admitted head carrying the
/// booking system, which every amendment derives its UID and next SEQUENCE
/// from.
///
/// Admitted means surfaceable and about the EVENT itself, as the booking facts
/// read. A pending, stale or future-dated proposal is never revision authority:
/// it can neither block an amendment nor steer its UID or SEQUENCE, and no
/// amendment supersedes it. Two admitted heads are refused through `refuse`,
/// never picked by scan order.
pub(super) fn outbound_passport_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    refuse: fn(&'static str) -> BookingError,
) -> Result<(EntityId, CalendarPassportValue), BookingError> {
    let mut own =
        crate::calendar::passport::admitted_passports_for_event_in_txn(vault, txn, event_ref)
            .map_err(calendar_wrap)?
            .into_iter()
            .filter(|(_, value)| value.system == BOOKING_PASSPORT_SYSTEM);
    let head = own
        .next()
        .ok_or_else(|| refuse("booking carries no outbound calendar passport"))?;
    if own.next().is_some() {
        return Err(refuse(
            "booking carries competing outbound calendar passports",
        ));
    }
    Ok(head)
}

/// Supersedes this booking's outbound passport at `last_sequence + 1`.
///
/// CAL-02's `supersede_calendar_passport` opens its OWN write transaction, so
/// calling it from inside the home-node writer would deadlock LMDB. This
/// composes CAL-02's own live-passport resolution with the engine's
/// transaction-composable supersession instead — the same transition without
/// the nested transaction.
pub(super) fn supersede_outbound_passport(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    content: &BookingContent,
    now_utc: u64,
) -> Result<CalendarRevision, BookingError> {
    crate::booking::emergency_reschedule::ensure_no_pending_effect_in(vault, wtxn, *event_ref)?;
    let (old_id, current) = outbound_passport_in(vault, wtxn, event_ref, refused)?;
    let sequence = current
        .last_sequence
        .checked_add(1)
        .ok_or_else(|| refused("booking passport sequence is exhausted"))?;
    let value = outbound_passport_value(
        BOOKING_PASSPORT_SYSTEM.to_owned(),
        current.uid.clone(),
        sequence,
        content.hash(),
        now_utc,
    );
    let new_id = put_claim(
        vault,
        wtxn,
        event_ref,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&value),
        now_utc,
    )?;
    vault
        .supersede_claim_in_txn(wtxn, &new_id, &old_id, now_utc)
        .map_err(|error| engine_failure("passport supersession", error))?;
    Ok(CalendarRevision {
        event_ref: *event_ref,
        uid: current.uid,
        sequence,
    })
}
