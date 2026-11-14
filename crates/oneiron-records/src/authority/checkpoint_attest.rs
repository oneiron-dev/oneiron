//! Moved from `crates/oneiron/src/authority/checkpoint_attest.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The crypto epoch a certified checkpoint key signs at: a binding names it,
/// and a hash-based record below it is refused.
/// The binding statement domain stays v1 across the tier field (FIX 2754):
/// pre-tier rows fail strict decode in both directions, so no domain bump
/// carries them either way.
pub const CHECKPOINT_KEY_EPOCH: u64 = 1;

pub const KEY_BINDING_DOMAIN: &[u8] = b"oneiron/authority/checkpoint-key-binding/v1";

pub const BINDING_DIGEST_CONTEXT: &str = "oneiron/authority/checkpoint-key-binding/digest/v1";

pub const PIN_DIGEST_CONTEXT: &str = "oneiron/authority/checkpoint-pin/v1";

/// An SLH-DSA-SHA2-256s public key.
pub const SLHDSA_PUBLIC_KEY_LEN: usize = 64;

pub fn attest_refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

pub fn encode_err() -> Error {
    Error::CorruptedIndex("authority checkpoint attestation")
}
