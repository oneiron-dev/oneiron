//! ONE-1813 [BK-02] booking lifecycle verbs.
//!
//! The four typed verbs — `booking.hold`, `booking.confirm`,
//! `booking.reschedule`, `booking.cancel` — plus the state they need: session
//! keyed soft-hold rows, opaque bearer tokens, durable lifecycle receipts, and
//! the home-node macro attempt that executes them.
//!
//! # Shape
//!
//! A public verb entry point only validates, encodes, and enqueues
//! [`BOOKING_LIFECYCLE_ATTEMPT_KIND`] on the generic attempt queue
//! ([`enqueue_booking_verb`]). Execution happens in exactly one place:
//! [`run_booking_lifecycle_once`], the home-node consumer that claims that
//! attempt kind ([`AttemptQueue::claim_kind`](crate::attempt_queue::AttemptQueue::claim_kind), mirroring `task_verb.rs`'s
//! realization consumer) and runs the transition. There is no public door onto
//! any `execute_*` function, so a caller cannot confirm a booking outside the
//! writer.
//!
//! # Mutual exclusion (r9)
//!
//! Confirm's correctness rests on ONE thing: the final availability read and
//! the write commit sit inside the SAME LMDB write transaction, which is the
//! engine's single-writer lease (`booking_writer`). The transaction is
//! acquired BEFORE the availability read and retained through the commit, so a
//! competing confirm either committed already — and is therefore visible as
//! busy in the fresh solve — or has not yet acquired the writer and will
//! observe our EVENT when it does. Advisory idempotency keys never participate:
//! they are attempt-queue dedupe hygiene, not a lock.
//!
//! Cross-node exclusion is the persisted MACRO home-node designation
//! ([`crate::dreamer_runner::DreamerHomeNodeDesignation`]): a node that is not
//! the home node refuses to claim the attempt at all.
//!
//! # Holds are not entities
//!
//! A hold is one `vault_meta` row under [`BOOKING_HOLD_META_PREFIX`], keyed by
//! the derived session key, so a session has at most one active hold. Expiry is
//! lazy: a row is live only while `expires_at > now`, and an expired row is
//! opportunistically deleted by whatever read next walks past it. No timer,
//! wake, expiry daemon, or recurrence primitive exists here, and correctness
//! never depends on the cleanup running at all.
//!
//! # UID truth is CAL's
//!
//! A booking is an existing EVENT plus claims — never a new entity kind, and
//! never a `booking.uid` claim. The outbound calendar identity is CAL-00's
//! [`CalendarPassportValue`](crate::calendar::CalendarPassportValue) written on the EVENT at sequence 0, indexed
//! through CAL-02's [`index_passport_uid`](crate::calendar::index_passport_uid), and superseded at `last_sequence +
//! 1` by reschedule and cancel. [`BookingError`](crate::booking::BookingError) wraps calendar failures
//! opaquely; no `CalendarError` variant is matched or restated here.

mod claim;
mod confirmation_state;
mod door;
mod emergency;
mod hold_source;
mod occurrence;
mod passport;
mod public_authority;
mod storage;
mod token;
mod transition;
mod types;

#[cfg(test)]
mod tests;

pub use self::claim::{
    BookingConfirmationContext, booking_claim_class_descriptors, booking_confirmation_context,
    claim_class_descriptors, is_booking_family_claim_predicate,
    is_booking_lifecycle_claim_predicate, validate_booking_family_claim,
};
pub use self::door::{
    BookingLifecycleConsumerInput, BookingLifecycleTurn, BookingOracleRequest,
    enqueue_booking_verb, enqueue_booking_verb_with_publication, issue_checkout_lease,
    run_booking_lifecycle_once,
};
pub use self::hold_source::VaultActiveHoldSource;
pub use self::token::{
    HoldLeaseSpec, OpaqueCheckoutLeaseToken, OpaqueLifecycleToken, SessionKey, token_page_ref,
};
pub use self::types::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE, BOOKING_HOLD_META_PREFIX,
    BOOKING_LIFECYCLE_ATTEMPT_KIND, BOOKING_LIFECYCLE_PREDICATES, BOOKING_PASSPORT_SYSTEM,
    BOOKING_RECEIPT_META_PREFIX, BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE,
    BOOKING_TOKEN_META_PREFIX, BOOKING_VERBS, BookingBookerContactValue, BookingEventTypeRefValue,
    BookingLifecycleAttempt, BookingSourcePageValue, BookingStatus, BookingStatusValue,
    BookingVerb, BookingVerbReceipt, BookingVerbRequest, CalendarRevision, CancelSpec,
    ConfirmReceipt, ConfirmSpec, DEFAULT_HOLD_TTL_SECS, HoldReceipt, HoldSpec, LifecycleTokenScope,
    MAX_CHECKOUT_HOLD_TTL_SECS, RescheduleSpec, RevisionReceipt, SoftHoldRow,
};

pub(crate) use self::confirmation_state::{
    bind_booking_invite_identity_in, booking_invite_identity,
};
pub(crate) use self::emergency::{
    admit_emergency_pick, commit_emergency_item, emergency_current_revision_in,
    pick_emergency_item, read_emergency_pick,
};
pub(crate) use self::storage::{booking_writer, put_meta, read_meta_bytes};
pub(crate) use self::token::{digest_with, hex_lower, mint_raw_token};
// The three ordinary transitions are reached from outside this module only by
// sibling test suites; the non-test doors stay behind the consumer turn.
#[cfg(test)]
pub(crate) use self::transition::{execute_cancel, execute_hold, execute_reschedule};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::EntityId;
use crate::booking::EventTypeKey;
use crate::temporal::TimeRange;

// The flat lifecycle.rs module used to provide these names to its inline
// `mod tests` through `use super::*`: its own private crate imports and the
// lifecycle-internal items the tests name bare. After the directory split the
// seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::{claim::*, storage::*, token::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};

// -------------------------------------------------------------------------
// Rows every child reads by field, and the serde adapters their fields name
//
// A private field is visible only to the defining module and its
// descendants, so the rows that more than one child constructs or reads
// field-by-field live here in the parent rather than in `types`. The serde
// adapters sit with them for the same reason: `#[serde(with = ...)]` on
// these rows resolves against this module. `TimeRange` and `EntityId` carry
// no serde impls, and neither is widened for booking: the wire shapes live
// here, exactly as `constraint.rs` and `config.rs` keep theirs.
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimeRangeWire {
    start: u64,
    end: u64,
}

mod time_range_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, TimeRange, TimeRangeWire};

    pub(super) fn serialize<S: Serializer>(
        value: &TimeRange,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        TimeRangeWire {
            start: value.start,
            end: value.end,
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<TimeRange, D::Error> {
        let wire = TimeRangeWire::deserialize(deserializer)?;
        Ok(TimeRange {
            start: wire.start,
            end: wire.end,
        })
    }
}

/// Digests cross the wire as lowercase hex — fixed width, and a compact byte
/// string rather than the 32-element integer array `[u8; 32]` would otherwise
/// serialize into.
mod digest_serde {
    use super::{Deserialize, Deserializer, Serializer, hex_lower};

    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex_lower(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let hex = String::deserialize(deserializer)?;
        super::digest_from_hex(&hex)
            .ok_or_else(|| serde::de::Error::custom("booking digest is not 32 lowercase hex bytes"))
    }
}

mod opt_digest_serde {
    use super::{Deserialize, Deserializer, Serialize, Serializer, hex_lower};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|bytes| hex_lower(&bytes)).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            None => Ok(None),
            Some(hex) => super::digest_from_hex(&hex).map(Some).ok_or_else(|| {
                serde::de::Error::custom("booking digest is not 32 lowercase hex bytes")
            }),
        }
    }
}

/// Parses exactly 32 lowercase hex bytes.
fn digest_from_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

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

/// The digest row a lifecycle token resolves through. The token carries no
/// state; this row is where the EVENT and the permitted action live.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleTokenRow {
    #[serde(with = "entity_ref_serde")]
    event_ref: EntityId,
    scope: LifecycleTokenScope,
}

/// A server-issued checkout lease, bound to one session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutLeaseRow {
    #[serde(with = "digest_serde")]
    session_hash: [u8; 32],
    expires_at: u64,
}

/// The durable lifecycle receipt one transition recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleReceiptRow {
    #[serde(with = "entity_ref_serde")]
    event_ref: EntityId,
    uid: String,
    sequence: u32,
    /// Present on confirm receipts: the session that owned the consumed hold,
    /// so a retry from another session cannot read this receipt back.
    #[serde(with = "opt_digest_serde")]
    session_hash: Option<[u8; 32]>,
    confirmation: Option<BookingConfirmationContext>,
    invite_identity: Option<(String, String)>,
}

impl LifecycleReceiptRow {
    fn into_revision(self) -> CalendarRevision {
        CalendarRevision {
            event_ref: self.event_ref,
            uid: self.uid,
            sequence: self.sequence,
        }
    }
}

/// The booking content one passport revision attests.
struct BookingContent {
    page_ref: EntityId,
    event_type: EventTypeKey,
    slot: TimeRange,
    status: BookingStatus,
    emergency_content_hash: Option<[u8; 32]>,
}

/// The booking facts a revision needs from its EVENT.
struct BookingFacts {
    page_ref: EntityId,
    event_type: EventTypeKey,
    slot: TimeRange,
    /// The LIVE status head, so a transition rules on what the booking is now
    /// rather than on what its token was issued for.
    status: BookingStatus,
    context: Option<BookingConfirmationContext>,
}
