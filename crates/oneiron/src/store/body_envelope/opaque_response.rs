//! Core half of `store::body_envelope::opaque_response`: its store-layer items live in `oneiron_store::body_envelope::opaque_response` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::body_envelope::opaque_response::*;

use super::response::{ResponseCarriage, ResponseDb, ResponseFamily};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

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
        crate::store::result_body_erasure::response_erased_error(match family {
            ResponseFamily::ProgramStep => "a program step's kept body",
            ResponseFamily::StepState => "an LLM step's state",
            ResponseFamily::Replay => "a code run's replay record",
            ResponseFamily::Http => "an HTTP idempotency entry",
            ResponseFamily::InvocationClaim => "an invocation claim",
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
