//! The single-writer lease and the vault_meta/receipt key-value primitives,
//! the versioned row codec, the claim-value codec, and the error constructors.

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::LifecycleReceiptRow;
use super::token::{HOLD_KEY_DOMAIN, SessionKey, digest_with};
use super::types::{
    BOOKING_HOLD_META_PREFIX, BOOKING_RECEIPT_META_PREFIX, LIFECYCLE_ROW_VERSION,
    LifecycleTokenScope,
};
use crate::booking::BookingError;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// Acquires the home-node single writer.
///
/// This IS the lifecycle's mutual exclusion: LMDB admits one writer per
/// environment, so everything the closure reads and writes is serialized
/// against every other booking transition. Dropping the transaction on an early
/// return aborts it, so a refusal leaves no partial state.
/// The home-node booking writer: one LMDB write transaction, held across
/// whatever read the decision rests on and through the commit.
///
/// This is the generic soft-confirm hook ONE-1821 delegates to. A companion
/// soft confirmation writes no EVENT, no passport, and dispatches no invite —
/// but it needs the ONE property confirm's correctness rests on, that the final
/// availability read and the write share a single writer lease. Handing out the
/// lease is that property; a companion-local writer would be a second set of
/// rules over the same rows.
pub(in crate::booking) fn booking_writer<T, F>(vault: &Vault, apply: F) -> Result<T, BookingError>
where
    F: FnOnce(&mut heed::RwTxn<'_>) -> Result<T, BookingError>,
{
    let mut wtxn = vault
        .store
        .env
        .write_txn()
        .map_err(|error| engine_failure("writer acquisition", error))?;
    let value = {
        let _active_write_txn = crate::store::active_write_txn_guard();
        apply(&mut wtxn)?
    };
    wtxn.commit()
        .map_err(|error| engine_failure("writer commit", error))?;
    Ok(value)
}

pub(super) fn read_txn(vault: &Vault) -> Result<heed::RoTxn<'_>, BookingError> {
    vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))
}

pub(super) fn claims_for_subject(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<EntityId>, BookingError> {
    vault
        .claims_for_subject_in_txn(rtxn, subject)
        .map_err(|error| engine_failure("claim subject scan", error))
}

pub(super) fn meta_key(prefix: &[u8], digest: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + digest.len());
    key.extend_from_slice(prefix);
    key.extend_from_slice(digest);
    key
}

pub(super) fn hold_key(session_key: &SessionKey) -> Vec<u8> {
    meta_key(
        BOOKING_HOLD_META_PREFIX,
        &digest_with(HOLD_KEY_DOMAIN, &session_key.0),
    )
}

/// Receipt identity for a confirm: the hold token's digest, so the retry key is
/// something only the holder can present and never an advisory input.
pub(super) fn confirm_receipt_key(hold_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_KEY_DOMAIN);
    hasher.update(b"confirm\0");
    hasher.update(hold_hash);
    *hasher.finalize().as_bytes()
}

/// Receipt identity for a revision: the BOOKING and the transition, never the
/// credential that reached it.
///
/// Keying on a token digest made one booking's receipt space as wide as the set
/// of credentials that could reach it, so two cancel tokens for one booking
/// recorded two independent cancels and incremented the sequence twice. A
/// transition happens to the EVENT, so the EVENT is its identity.
///
/// Cancel is keyed by the booking alone — it is terminal, so cancelling twice is
/// one receipt. A reschedule adds its TARGET slot, because one booking
/// legitimately moves more than once; the caller pairs that with a live
/// occurrence check, since a move BACK to an earlier target is a new transition
/// rather than a retry of the old one.
pub(super) fn revision_receipt_key(
    event_ref: &EntityId,
    target_slot: Option<TimeRange>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_KEY_DOMAIN);
    match target_slot {
        Some(slot) => {
            hasher.update(LifecycleTokenScope::Reschedule.tag());
            hasher.update(&slot.start.to_be_bytes());
            hasher.update(&slot.end.to_be_bytes());
        }
        None => {
            hasher.update(LifecycleTokenScope::Cancel.tag());
        }
    }
    hasher.update(event_ref.as_bytes());
    *hasher.finalize().as_bytes()
}

const RECEIPT_KEY_DOMAIN: &[u8] = b"oneiron.booking.receipt.v1\0";

pub(super) fn encode_row<T: Serialize>(value: &T) -> Result<Vec<u8>, BookingError> {
    let mut out = vec![LIFECYCLE_ROW_VERSION];
    out.extend(
        rmp_serde::to_vec_named(value)
            .map_err(|error| refused(format!("lifecycle row does not encode: {error}")))?,
    );
    Ok(out)
}

pub(super) fn decode_row<T: DeserializeOwned>(raw: &[u8]) -> Result<T, BookingError> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(refused("lifecycle row is empty"));
    };
    if version != LIFECYCLE_ROW_VERSION {
        return Err(refused("lifecycle row version is unsupported"));
    }
    rmp_serde::from_slice(body)
        .map_err(|error| refused(format!("lifecycle row does not decode: {error}")))
}

pub(super) fn read_meta<T: DeserializeOwned>(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    prefix: &[u8],
    digest: &[u8; 32],
) -> Result<Option<T>, BookingError> {
    let Some(raw) = read_meta_bytes(vault, rtxn, &meta_key(prefix, digest))? else {
        return Ok(None);
    };
    decode_row(&raw).map(Some)
}

pub(in crate::booking) fn read_meta_bytes(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    key: &[u8],
) -> Result<Option<Vec<u8>>, BookingError> {
    Ok(vault
        .store
        .vault_meta
        .get(rtxn, key)
        .map_err(|error| engine_failure("meta read", error))?
        .map(std::borrow::Cow::into_owned))
}

pub(crate) fn put_meta(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<(), BookingError> {
    vault
        .store
        .vault_meta
        .put(wtxn, key, value)
        .map_err(|error| engine_failure("meta write", error))
}

pub(super) fn delete_meta(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &[u8],
) -> Result<(), BookingError> {
    vault
        .store
        .vault_meta
        .delete(wtxn, key)
        .map(|_| ())
        .map_err(|error| engine_failure("meta delete", error))
}

pub(super) fn read_receipt(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt_key: &[u8; 32],
) -> Result<Option<LifecycleReceiptRow>, BookingError> {
    read_meta(vault, rtxn, BOOKING_RECEIPT_META_PREFIX, receipt_key)
}

pub(super) fn write_receipt(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt_key: &[u8; 32],
    row: &LifecycleReceiptRow,
) -> Result<(), BookingError> {
    let encoded = encode_row(row)?;
    put_meta(
        vault,
        wtxn,
        &meta_key(BOOKING_RECEIPT_META_PREFIX, receipt_key),
        &encoded,
    )
}

// -------------------------------------------------------------------------
// Claim value codec
//
// The same `rmp_serde` ↔ `rmpv` bridge `config.rs` uses, rather than a
// hand-rolled nested walk per value.
// -------------------------------------------------------------------------

pub(super) fn encode_claim_value<T: Serialize>(value: &T) -> Result<rmpv::Value, BookingError> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|error| refused(format!("booking claim value does not encode: {error}")))?;
    rmpv::decode::read_value(&mut std::io::Cursor::new(bytes.as_slice()))
        .map_err(|error| refused(format!("booking claim value does not encode: {error}")))
}

pub(super) fn claim_value<T: DeserializeOwned>(value: &rmpv::Value) -> Option<T> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).ok()?;
    rmp_serde::from_slice(&bytes).ok()
}

pub(super) fn decode_claim_value<T: DeserializeOwned>(
    value: &rmpv::Value,
    what: &str,
) -> Result<T, BookingError> {
    claim_value(value).ok_or_else(|| refused(format!("stored booking {what} claim did not decode")))
}

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

/// A refused request. [`BookingError`] is ONE-1816's, and this lane adds no
/// variant to it: a lifecycle refusal is request data that failed validation.
pub(super) fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

/// Wraps an engine failure without restating the engine's error taxonomy.
pub(super) fn engine_failure<E: Into<crate::Error>>(what: &str, error: E) -> BookingError {
    let error = error.into();
    BookingError::SlotOracle(format!("booking lifecycle {what} failed: {error}"))
}

/// Wraps a calendar failure OPAQUELY: no `CalendarError` variant is matched, and
/// none is restated in booking's own taxonomy. This is the same stance
/// `solver.rs` takes on `freebusy`.
pub(super) fn calendar_wrap(error: crate::calendar::CalendarError) -> BookingError {
    BookingError::SlotOracle(format!("booking lifecycle calendar step failed: {error}"))
}
