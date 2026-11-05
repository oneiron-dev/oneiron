//! The custody head's wire (KS-4): its MessagePack shapes, the key id that
//! binds a compartment and its wraps to their place in one head, and the
//! unauthenticated reads of a head's position.
//!
//! A head is framed by bytes, never by a cap on what it holds (FIX 5800):
//! each compartment's rows take at most [`COMPARTMENT_BYTES`] of plaintext,
//! a history row too large for that rides in fragments across compartments
//! in order, the released escrow recipients are paged with the host-readable
//! rows, and the control compartment commits to every compartment with one
//! fixed-size [`DigestRoot`], so no part of a head nears one envelope's
//! bound however much custody grows.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use oneiron_base::error::Result;

use crate::key_custody::head::carried_pads;
use crate::key_custody::head::holder_debts::HolderDebtWire;
use crate::key_custody::head::scope::CompartmentScope;

pub const HEAD_MAGIC: &[u8; 4] = b"OCHD";
/// Version 4 carries the holder debts in the host-readable compartments
/// (FIX 11206). It keeps version 3's framing by bytes (FIX 5800):
/// compartments bounded by their plaintext, history rows in fragments,
/// paged recipients and one fixed control root; and version 2's erased
/// credentials' evidence (FIX 10584 item 3), one pad per world compartment,
/// each compartment's whole wire committed, and the carried world
/// compartments (PAD-3). An older head reads as invalid until the next
/// publication pass seals it again (FIX 10469): no old-head reader.
pub const HEAD_VERSION: u16 = 4;
/// The most plaintext bytes one compartment's rows are counted at: a pacing
/// bound far inside one E0 envelope, never a cap on the head; a scope with
/// more takes more compartments (Rule 5).
pub const COMPARTMENT_BYTES: usize = 4 << 20;
/// The most bytes of one history row's value in one compartment: a larger
/// value rides in fragments of this size, in order.
pub const HISTORY_FRAGMENT_BYTES: usize = 1 << 20;
/// What one row's MessagePack framing, its field names and markers, is
/// counted at above its byte strings.
pub const ROW_OVERHEAD: usize = 96;

/// The derive-key context of a compartment's envelope key id ([`key_id`]).
pub const KEY_ID_CONTEXT: &str = "oneiron/custody-head/compartment-key-id/v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapWire {
    pub to: u8,
    pub root: Option<[u8; 32]>,
    /// A world compartment's admitted machine (FIX 6706).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<[u8; 16]>,
    #[serde(with = "serde_bytes_vec")]
    pub envelope: Vec<u8>,
}

/// What a control compartment commits to (FIX 5800): how many compartments
/// follow it and how many carried ones its head holds, and one root over
/// all their digests in order ([`carried_pads::digest_root`]).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestRoot {
    pub compartments: u32,
    pub carried: u32,
    pub root: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceWire {
    pub credential: [u8; 16],
    pub fact: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryWire {
    #[serde(with = "serde_bytes_vec")]
    pub key: Vec<u8>,
    /// The value, or one fragment of it (FIX 5800).
    #[serde(with = "serde_bytes_vec")]
    pub value: Vec<u8>,
    /// The fragment's place in its row, from 0.
    pub part: u32,
    /// Whether it is the row's last fragment.
    pub last: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryWire {
    pub kind: u8,
    #[serde(with = "serde_bytes_vec")]
    pub item: Vec<u8>,
    pub generation: u64,
    #[serde(with = "serde_bytes_vec")]
    pub secret: Vec<u8>,
}

impl Drop for EntryWire {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactWire {
    pub kind: u8,
    #[serde(with = "serde_bytes_vec")]
    pub item: Vec<u8>,
    pub generation: u64,
}

/// Byte strings as msgpack bin, not arrays of numbers.
pub mod serde_bytes_vec {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }
        }
        input.deserialize_bytes(Visitor)
    }
}
