//! Moved from `crates/oneiron/src/secret_custody/leaf_delivery.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use serde::Deserialize;
use serde::Serialize;

/// The wire version of an ask and of its answer.
pub const LEAF_KEY_WIRE_VERSION: u8 = 1;

pub const REQUEST_DOMAIN: &[u8] = b"oneiron/custody-leaf-key-request/v1\0";

pub const ANSWER_DOMAIN: &[u8] = b"oneiron/custody-leaf-key-answer/v1\0";

pub const SEAL_BINDING_DOMAIN: &[u8] = b"oneiron/custody-leaf-key-seal/v1\0";

pub const KEY_ID_LABEL: &[u8] = b"custody-leaf/v1";

/// The ask or answer does not decode, or names another wire version.
pub const REFUSED_MALFORMED: &str = "leaf_key_malformed";

/// The ask's expiry passed.
pub const REFUSED_EXPIRED: &str = "leaf_key_expired";

/// No such ask is out here: answered already, expired or never made.
pub const REFUSED_REPLAYED: &str = "leaf_key_replayed";

/// Why an ask came back without a key, as L03's failure frame carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeafKeyFailureCause {
    /// The holder's socket is dead or absent: the ask stays pending.
    HolderOffline,
    /// The asker's socket is dead or absent: the ask stays pending.
    ExecutorOffline,
    /// The ask's expiry passed: a fresh one is minted next.
    Expired,
    /// The relay already carried an answer for this id: a fresh one is
    /// minted next.
    Replayed,
    /// The holder refused, with its reason code: never a key or a secret.
    /// The carrier waits [`LEAF_KEY_REFUSED_BACKOFF_MS`] before a new ask.
    HolderRefused(String),
    /// The holder met a fault that is no refusal (its storage or keystore):
    /// the ask stays pending and is sent again, as for an offline holder.
    HolderFault,
}

impl LeafKeyFailureCause {
    /// The cause a holder's refusal of an ask travels as: an expired ask, a
    /// replayed one, or the refusal's own reason code. `None` for a fault
    /// that is no refusal (storage, keystore), which travels as
    /// [`Self::HolderFault`]: the asker keeps the ask pending and sends it
    /// again.
    #[must_use]
    pub fn of_refusal(error: &Error) -> Option<Self> {
        match error {
            Error::Record(RecordError::AuthorityRefused(reason)) => Some(match *reason {
                REFUSED_EXPIRED => Self::Expired,
                REFUSED_REPLAYED => Self::Replayed,
                reason => Self::HolderRefused(reason.to_owned()),
            }),
            _ => None,
        }
    }
}

/// Integers, ids and byte lists in MessagePack: never refused, so an
/// encode that fails is the empty frame, which no decode takes.
pub fn encode_frame<T: Serialize>(frame: &T) -> Vec<u8> {
    rmp_serde::to_vec_named(frame).unwrap_or_default()
}

/// One digest over `fields`, each length-prefixed.
pub fn fields_digest(fields: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(fields.len() as u64).to_be_bytes());
    for field in fields {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    *hasher.finalize().as_bytes()
}
