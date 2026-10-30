//! The restorable copy of a quarantined confirm (FIX 7851).
//! Entry: `BookingQuarantinedSubmission`.
//! Defines its own items.

use serde::{Deserialize, Serialize};

use super::storage::{SUBMISSION_KEY_TAG, decode_row, encode_row, engine_failure, to_codec_error};
use crate::booking::agent_api::BookingIntakeAnswer;
use crate::booking::lifecycle::{
    OpaqueLifecycleToken, SessionKey, booking_writer, live_hold_in_txn,
};
use crate::booking::{BookingError, ConstraintObject, EventTypeKey};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Vault};

/// One quarantined confirm's restorable submission. Key: `"submission\0"` +
/// id16 (the quarantine claim id).
const SUBMISSION: SideTable<([u8; 11], [u8; 16]), BookingQuarantinedSubmission, Raw> =
    SideTable::new(&side_table::BOOKING_ANTI_ABUSE);

/// What a quarantined visitor submitted, kept so the owner can restore the
/// booking through the ordinary booking writer: the held slot and the inputs
/// it was solved under, the contact, and the intake. Vault-local and keyed by
/// the quarantine claim; the inbox card itself carries hashes only.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingQuarantinedSubmission {
    #[serde(with = "entity_ref_hex")]
    pub page_ref: EntityId,
    pub event_type: EventTypeKey,
    /// The held slot, half-open `[start, end)` in UTC seconds.
    pub slot_start_utc: u64,
    pub slot_end_utc: u64,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    pub booker_email: String,
    pub intake: Vec<BookingIntakeAnswer>,
    pub quarantined_at: u64,
    /// The booking EVENT the owner's restore made; `None` until restored.
    #[serde(with = "opt_entity_ref_hex")]
    pub restored_event_ref: Option<EntityId>,
}

impl crate::side_table::RawValue for BookingQuarantinedSubmission {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, crate::side_table::CodecError> {
        encode_row(self).map_err(to_codec_error)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, crate::side_table::CodecError> {
        decode_row(bytes).map_err(to_codec_error)
    }
}

/// The raw confirm the trusted boundary holds when it quarantines one: what
/// the restorable copy is made from.
#[derive(Clone, Copy, Debug)]
pub struct BookingQuarantineRestoreInput<'a> {
    pub session_key: SessionKey,
    pub hold_token: &'a OpaqueLifecycleToken,
    pub booker_email: &'a str,
    pub intake: &'a [BookingIntakeAnswer],
}

/// Keeps the restorable copy of one quarantined confirm, in the quarantine
/// write's own transaction. A confirm whose hold is no longer live keeps
/// none: there is no slot to restore.
pub(super) fn keep_restorable_submission_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: [u8; 16],
    restore: &BookingQuarantineRestoreInput<'_>,
    quarantined_at: u64,
) -> Result<(), BookingError> {
    let Some(hold) = live_hold_in_txn(
        vault,
        wtxn,
        &restore.session_key,
        restore.hold_token,
        quarantined_at,
    )?
    else {
        return Ok(());
    };
    let submission = BookingQuarantinedSubmission {
        page_ref: hold.page_ref,
        event_type: hold.event_type,
        slot_start_utc: hold.slot.start,
        slot_end_utc: hold.slot.end,
        visitor_tz: hold.visitor_tz,
        constraint: hold.constraint,
        booker_email: restore.booker_email.to_owned(),
        intake: restore.intake.to_vec(),
        quarantined_at,
        restored_event_ref: None,
    };
    SUBMISSION
        .put(
            &vault.store,
            wtxn,
            &(*SUBMISSION_KEY_TAG, claim_id),
            &submission,
        )
        .map_err(|error| engine_failure("quarantined submission write", error))
}

/// The restorable submission one quarantine claim kept, for the owner's
/// review and restore.
///
/// # Errors
///
/// Storage and decode failures.
pub fn booking_quarantined_submission(
    vault: &Vault,
    claim_ref: &EntityId,
) -> Result<Option<BookingQuarantinedSubmission>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    SUBMISSION
        .get(
            &vault.store,
            &rtxn,
            &(*SUBMISSION_KEY_TAG, *claim_ref.as_bytes()),
        )
        .map_err(|error| engine_failure("quarantined submission read", error))
}

/// Records the booking EVENT an owner restore made from one quarantined
/// submission, so the submission reads as restored and a second restore
/// books nothing.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the claim kept no submission or
/// it was already restored; storage failures.
pub fn record_quarantined_submission_restored(
    vault: &Vault,
    claim_ref: &EntityId,
    event_ref: EntityId,
) -> Result<(), BookingError> {
    booking_writer(vault, |wtxn| {
        let key = (*SUBMISSION_KEY_TAG, *claim_ref.as_bytes());
        let Some(mut submission) = SUBMISSION
            .get(&vault.store, &*wtxn, &key)
            .map_err(|error| engine_failure("quarantined submission read", error))?
        else {
            return Err(BookingError::InvalidConstraint(
                "this quarantine claim kept no restorable submission".to_owned(),
            ));
        };
        if submission.restored_event_ref.is_some() {
            return Err(BookingError::InvalidConstraint(
                "this quarantined submission is already restored".to_owned(),
            ));
        }
        submission.restored_event_ref = Some(event_ref);
        SUBMISSION
            .put(&vault.store, wtxn, &key, &submission)
            .map_err(|error| engine_failure("quarantined submission write", error))
    })
}

mod entity_ref_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::EntityId;

    pub(super) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        EntityId::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

mod opt_entity_ref_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::EntityId;

    pub(super) fn serialize<S: Serializer>(
        id: &Option<EntityId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match id {
            Some(id) => serializer.serialize_some(&id.to_hex()),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EntityId>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|hex| EntityId::from_hex(&hex).map_err(serde::de::Error::custom))
            .transpose()
    }
}
