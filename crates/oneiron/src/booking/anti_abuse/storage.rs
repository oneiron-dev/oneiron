//! Private booking anti-abuse rows, keys and digests.
//! Entry: `BOOKING_ANTI_ABUSE_META_PREFIX`.
//! Defines its own items.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::booking::BookingError;
use crate::side_table::{self, Raw, SideTable};

use super::rules::BookingAntiAbuseRuleRow;

// -------------------------------------------------------------------------
// Storage layout
// -------------------------------------------------------------------------

/// Booking-only `vault_meta` prefix. The node-local rows this module stores —
/// rule proposals, rate counters, the slot-list response cache, and
/// quarantined confirms' restorable submissions — live under it. Activated
/// rule rows are POLICY_MANIFEST rows (FIX 9628), and quarantine records ride
/// the gate's existing pending-consent rows so the inbox's pending-review
/// pattern can enumerate them.
pub const BOOKING_ANTI_ABUSE_META_PREFIX: &[u8] = b"booking:anti_abuse:v1:";

/// Key tags under the prefix, one byte-string per row family, kept distinct
/// so a prefix scan can pick out exactly one family.
pub(super) const RATE_KEY_TAG: &[u8; 5] = b"rate\x00";
pub(super) const CACHE_KEY_TAG: &[u8; 6] = b"cache\x00";
pub(super) const PROPOSAL_KEY_TAG: &[u8; 9] = b"proposal\x00";
pub(super) const SUBMISSION_KEY_TAG: &[u8; 11] = b"submission\x00";

/// One retained rule change awaiting its holder (FIX 9627). Key:
/// `"proposal\0"` + hash32 (the proposed row's version hash, the digest the
/// owner's approve-once press names).
pub(super) const RULE_PROPOSAL: SideTable<([u8; 9], [u8; 32]), BookingAntiAbuseRuleRow, Raw> =
    SideTable::new(&side_table::BOOKING_ANTI_ABUSE);

impl crate::side_table::RawValue for BookingAntiAbuseRuleRow {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, crate::side_table::CodecError> {
        encode_row(self).map_err(to_codec_error)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, crate::side_table::CodecError> {
        decode_row(bytes).map_err(to_codec_error)
    }
}

/// Every hand-rolled booking anti-abuse row shares this codec (a `BookingError`
/// decode/encode failure carries no crate-`Error` payload to preserve, and no
/// test pins its message), so a decode failure through the typed door becomes
/// this one generic row-corruption marker.
pub(super) fn to_codec_error(_: BookingError) -> crate::side_table::CodecError {
    crate::error::Error::CorruptedIndex("booking anti-abuse row").into()
}

/// Wire-format version byte prepended to every encoded row (the same
/// version-then-rmp idiom the lifecycle rows use).
const ANTI_ABUSE_WIRE_VERSION: u8 = 0;

/// Domain tags for `digest_with`: persisted keys and hashes can never be
/// replayed across purposes because the domain differs.
pub(super) const RULE_KEY_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.rule_key.v0";
pub(super) const RATE_KEY_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.rate_key.v0";
pub(super) const CACHE_KEY_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.cache_key.v0";
pub(super) const QUARANTINE_RATE_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.quarantine_rate.v0";
pub(super) const SUBMISSION_FINGERPRINT_DOMAIN: &[u8] =
    b"oneiron.booking.anti_abuse.server_submission.v0";
pub(super) const ROW_VERSION_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.row_version_hash.v0";
pub(super) const QUARANTINE_CLAIM_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.quarantine_claim.v0";
pub(super) const IP_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.ip.v0";
pub(super) const EMAIL_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.email.v0";
pub(super) const SESSION_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.session.v0";

/// One fixed window for every "per minute" counter, mirroring
/// `task_verb.rs`'s node-local window counter.
pub(super) const RATE_WINDOW_SECS: u64 = 60;

/// Row-id shape: bounded, and tame enough to print in owner notices. One
/// full page hex plus one full event-key digest must always fit.
pub(super) const ROW_ID_MAX_LEN: usize = 160;
/// Bound on a stored slot-list cache body so a handler bug cannot grow the
/// vault without limit.
pub(super) const CACHE_BODY_MAX_LEN: usize = 512 * 1024;

/// The single reason code a booking quarantine record carries. It must pass
/// both gate store vets: the decision ledger requires a `gate.` prefix and
/// the pending-consent ledger requires `gate.pending.`.
pub(super) const QUARANTINE_REASON_CODE: &str = "gate.pending.booking.anti_abuse.borderline";

/// The reason code an owner restore closes a quarantine record's pending
/// review row with (FIX 7851).
pub(super) const QUARANTINE_RESTORE_REASON_CODE: &str =
    "gate.allow.owner_booking_quarantine_restore";

/// Predicate of the minimal CLAIM body a quarantined submission leaves
/// behind: the durable content the owner reviews from the pending gate row.
/// The default policy manifest's `booking.` prefix rule rates it
/// normal-criticality, exactly like the lifecycle claims.
pub(super) const QUARANTINE_CLAIM_PREDICATE: &str = "booking.submission_quarantine";

/// Synthetic run-id prefix stamped on quarantine pending rows. The inbox
/// group projection keys cards on a Dreamer run id; a quarantined submission
/// never has one, so the record carries this content-keyed id and
/// `resolve_run_identity` keeps the stamped id verbatim as the group key
/// when no Dreamer attempt rows anchor it.
pub(super) const QUARANTINE_RUN_ID_PREFIX: &str = "booking.anti_abuse.quarantine.";

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

/// A refused request: `BookingError` is ONE-1816's, and this lane adds no
/// variant to it. Same stance as the lifecycle verbs.
pub(super) fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

/// Wraps an engine failure without restating the engine's error taxonomy.
pub(super) fn engine_failure<E: Into<crate::Error>>(what: &str, error: E) -> BookingError {
    let error = error.into();
    BookingError::SlotOracle(format!("booking anti-abuse {what} failed: {error}"))
}

// -------------------------------------------------------------------------
// Wire codec and keys
// -------------------------------------------------------------------------

pub(super) fn encode_row<T: Serialize>(value: &T) -> Result<Vec<u8>, BookingError> {
    let mut out = vec![ANTI_ABUSE_WIRE_VERSION];
    out.extend(
        rmp_serde::to_vec_named(value)
            .map_err(|error| refused(format!("booking anti-abuse row does not encode: {error}")))?,
    );
    Ok(out)
}

pub(super) fn decode_row<T: DeserializeOwned>(raw: &[u8]) -> Result<T, BookingError> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(refused("booking anti-abuse row is empty"));
    };
    if version != ANTI_ABUSE_WIRE_VERSION {
        return Err(refused("booking anti-abuse row version is unsupported"));
    }
    rmp_serde::from_slice(body)
        .map_err(|error| refused(format!("booking anti-abuse row does not decode: {error}")))
}

pub(super) use crate::booking::lifecycle::hex_lower;
