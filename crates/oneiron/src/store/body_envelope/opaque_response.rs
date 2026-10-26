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

use super::response::{ResponseCarriage, ResponseDb, ResponseFamily};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The erased marker a retired opaque response's `vault_meta` row keeps:
/// `0xc1`, a byte MessagePack never uses, so no row's encoding starts with
/// it, then its name.
pub(crate) const OPAQUE_ERASED: &[u8] = b"\xc1oneiron/response-erased-opaque/v1";

/// The bytes of the time a stamped marker keeps after [`OPAQUE_ERASED`]:
/// wall seconds since the Unix epoch, big-endian.
const RETIRED_AT_LEN: usize = 8;

/// What a family finds in one row before anything is carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResponseScan {
    /// No response: a bodyless step, a state with no payload, an erased
    /// form, a row its family does not hold a response in.
    NotResponse,
    /// A response, its stub encoded from the decoded row.
    Decoded(ResponseCarriage),
    /// A response whose row does not decode or whose stub does not encode:
    /// carried whole past what its family recognized it by.
    Opaque(ResponseCarriage),
}

impl ResponseScan {
    /// An opaque row (`vault_meta`, `sync_state` or `job_records`): carried
    /// whole; its stub, and what a retired instance keeps, the erased
    /// marker.
    pub(crate) fn opaque_row() -> Self {
        Self::Opaque(ResponseCarriage {
            keep: 0,
            stub: OPAQUE_ERASED.to_vec(),
            retired: OPAQUE_ERASED.len(),
        })
    }

    /// An opaque claim, `value` its row: its body carried past its header;
    /// a retired instance keeps the header alone, the erase's shell.
    pub(crate) fn opaque_claim(value: &[u8]) -> Self {
        Self::Opaque(ResponseCarriage {
            keep: ENTITY_METADATA_HEADER_LEN,
            stub: value[..ENTITY_METADATA_HEADER_LEN].to_vec(),
            retired: ENTITY_METADATA_HEADER_LEN,
        })
    }

    /// A family's decoded carriage, `None` for a row holding no response.
    pub(crate) fn decoded(carriage: Option<ResponseCarriage>) -> Self {
        carriage.map_or(Self::NotResponse, Self::Decoded)
    }

    /// What a checkpoint carries, and whether it is opaque; `None` for no
    /// response.
    pub(crate) fn carriage(self) -> Option<(ResponseCarriage, bool)> {
        match self {
            Self::NotResponse => None,
            Self::Decoded(carriage) => Some((carriage, false)),
            Self::Opaque(carriage) => Some((carriage, true)),
        }
    }
}

/// Whether `value` is the erased marker a retired opaque response's row
/// keeps (FIX 9390), bare or stamped with the time it retired (FIX 10710),
/// and nothing else: its readers answer it erased before any decode.
pub(crate) fn is_opaque_erased(value: &[u8]) -> bool {
    value
        .strip_prefix(OPAQUE_ERASED)
        .is_some_and(|rest| rest.is_empty() || rest.len() == RETIRED_AT_LEN)
}

/// When the erased marker `value` holds was stamped retired, in wall seconds
/// since the Unix epoch (FIX 10710). `None` for any other row and for a bare
/// marker, which kept no time. Nothing the response held is read.
pub(crate) fn opaque_retired_at(value: &[u8]) -> Option<u64> {
    let retired_at = value.strip_prefix(OPAQUE_ERASED)?;
    Some(u64::from_be_bytes(retired_at.try_into().ok()?))
}

/// What a retire leaves in a row whose erased disposition is `kept`: the
/// bare erased marker is stamped with the time it retired, now by the wall
/// clock (FIX 10710), so a row's reader that expires its rows can judge it.
/// Anything else stays as it is, and so does the marker when the clock reads
/// before the epoch: no time is guessed, and that marker never expires.
pub(crate) fn stamp_opaque_erased(kept: &[u8]) -> Cow<'_, [u8]> {
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
pub(crate) enum ResponseOwners {
    /// Every owner its family names.
    Known(Vec<EntityId>),
    /// The owners its key proves; the ones its row stamps are not known.
    Partial(Vec<EntityId>),
    /// None proved.
    Unknown,
}

impl ResponseOwners {
    /// Whether every owner is proved.
    pub(crate) fn proved(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// The owners proved, which bind its obligations.
    pub(crate) fn into_ids(self) -> Vec<EntityId> {
        match self {
            Self::Known(ids) | Self::Partial(ids) => ids,
            Self::Unknown => Vec::new(),
        }
    }
}

/// What a row-held response's row keeps, read before any decode, once an
/// erase retired a response that never decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ErasedResponseDisposition {
    /// The explicit erased marker, in the row `key` of `database`.
    Opaque {
        family: ResponseFamily,
        database: ResponseDb,
        key: Vec<u8>,
    },
}

impl ErasedResponseDisposition {
    /// The typed unavailable its reader answers (`ErrorKind::ResponseErased`,
    /// #3462): nothing is asked, sent or run again. It names the family and
    /// where the row rests, never a byte the response held.
    pub(crate) fn unavailable(&self) -> Error {
        let Self::Opaque {
            family,
            database,
            key,
        } = self;
        tracing::warn!(
            ?family,
            database = database.name(),
            key_bytes = key.len(),
            "a read met the erased marker of a response that never decoded"
        );
        crate::code_run::response_erased_error(match family {
            ResponseFamily::ProgramStep => "a program step's kept body",
            ResponseFamily::StepState => "an LLM step's state",
            ResponseFamily::Replay => "a code run's replay record",
            ResponseFamily::Http => "an HTTP idempotency entry",
            ResponseFamily::MediaJob => "a media job",
            ResponseFamily::WaitDelivery => "a wait's delivered reply",
            ResponseFamily::WaitSettled => "a wait's settled reply",
            ResponseFamily::AttemptPayload => "an agent dispatch's attempt",
            _ => "a row-held response",
        })
    }
}

/// A reader's row of a response family, before it decodes it (FIX 6227).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResponseRead<'a> {
    /// The row's bytes, to decode as before.
    Present(&'a [u8]),
    /// The erased marker of a retired response that never decoded.
    ErasedOpaque(ErasedResponseDisposition),
}

impl<'a> ResponseRead<'a> {
    /// The row `key` of `family`, holding `value`.
    pub(crate) fn of(family: ResponseFamily, key: &[u8], value: &'a [u8]) -> Self {
        if is_opaque_erased(value) {
            Self::ErasedOpaque(ErasedResponseDisposition::Opaque {
                family,
                database: family.database(),
                key: key.to_vec(),
            })
        } else {
            Self::Present(value)
        }
    }

    /// The bytes to decode.
    ///
    /// # Errors
    ///
    /// `ResponseErased` for the erased marker.
    pub(crate) fn present(self) -> Result<&'a [u8]> {
        match self {
            Self::Present(value) => Ok(value),
            Self::ErasedOpaque(erased) => Err(erased.unavailable()),
        }
    }
}
