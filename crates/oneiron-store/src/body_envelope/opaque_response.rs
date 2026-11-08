//! Row-held responses that do not decode (FIX 6227).
//!
//! A row its family recognizes before any decode (a STEP, step-state,
//! replay, wait or captured-request row by its key; an HTTP idempotency
//! entry or a media job by its `sync_state` key; a claim by its header and
//! the `dreamer.step` predicate its body names; an agent dispatch's attempt
//! row by a routing probe that asks no strict validator; a voice bank row by
//! its key) whose bytes do not decode, or whose stub does not encode, still
//! holds a response: it is carried sealed under its instance as any other is
//! ([`ResponseScan::Opaque`]), never in the clear, never cleared, dropped or
//! refused (FIX 6227, 9390). A restore under a live instance lands its exact
//! bytes. Under a retired one its row keeps the explicit erased marker
//! [`OPAQUE_ERASED`], which no row's encoding begins with, followed by the
//! time it retired ([`stamp_opaque_erased`], FIX 10710), a claim the
//! erase's shell, as a decoded one does, and a family whose erase deletes
//! its row (a captured request, a voice bank row) loses it.
//!
//! Each reader of those rows checks for the marker before it decodes
//! ([`ResponseRead`]) and answers it as the typed unavailable
//! `ResponseErased` (#3462): never a fabricated row, never an absent one that
//! is asked, sent or run again.
//!
//! Its owners are what its key proves ([`ResponseOwners`]); what its row
//! stamps beside that is not known, and is reported, never invented.

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;

/// The erased marker a retired opaque response's `vault_meta` row keeps:
/// `0xc1`, a byte MessagePack never uses, so no row's encoding starts with
/// it, then its name.
pub const OPAQUE_ERASED: &[u8] = b"\xc1oneiron/response-erased-opaque/v1";

/// The bytes of the time a stamped marker keeps after [`OPAQUE_ERASED`]:
/// wall seconds since the Unix epoch, big-endian.
const RETIRED_AT_LEN: usize = 8;

/// Whether `value` is the erased marker a retired opaque response's row
/// keeps (FIX 9390), bare or stamped with the time it retired (FIX 10710),
/// and nothing else: its readers answer it erased before any decode.
pub fn is_opaque_erased(value: &[u8]) -> bool {
    value
        .strip_prefix(OPAQUE_ERASED)
        .is_some_and(|rest| rest.is_empty() || rest.len() == RETIRED_AT_LEN)
}

/// When the erased marker `value` holds was stamped retired, in wall seconds
/// since the Unix epoch (FIX 10710). `None` for any other row and for a bare
/// marker, which kept no time. Nothing the response held is read.
pub fn opaque_retired_at(value: &[u8]) -> Option<u64> {
    let retired_at = value.strip_prefix(OPAQUE_ERASED)?;
    Some(u64::from_be_bytes(retired_at.try_into().ok()?))
}

/// What a retire leaves in a row whose erased disposition is `kept`: the
/// bare erased marker is stamped with the time it retired, now by the wall
/// clock (FIX 10710), so a row's reader that expires its rows can judge it.
/// Anything else stays as it is, and so does the marker when the clock reads
/// before the epoch: no time is guessed, and that marker never expires.
pub fn stamp_opaque_erased(kept: &[u8]) -> Cow<'_, [u8]> {
    if !kept
        .strip_prefix(OPAQUE_ERASED)
        .is_some_and(<[u8]>::is_empty)
    {
        return Cow::Borrowed(kept);
    }
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return Cow::Borrowed(kept);
    };
    let mut stamped = OPAQUE_ERASED.to_vec();
    stamped.extend_from_slice(&now.as_secs().to_be_bytes());
    Cow::Owned(stamped)
}

/// Who owns a response, as far as its row proves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResponseOwners {
    /// Every owner its family names.
    Known(Vec<EntityId>),
    /// The owners its key proves; the ones its row stamps are not known.
    Partial(Vec<EntityId>),
    /// None proved.
    Unknown,
}

impl ResponseOwners {
    /// Whether every owner is proved.
    pub fn proved(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// The owners proved, which bind its obligations.
    pub fn into_ids(self) -> Vec<EntityId> {
        match self {
            Self::Known(ids) | Self::Partial(ids) => ids,
            Self::Unknown => Vec::new(),
        }
    }
}
