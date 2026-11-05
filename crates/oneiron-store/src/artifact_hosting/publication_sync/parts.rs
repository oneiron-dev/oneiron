//! Bounded publication parts (FIX 9575).
//!
//! A publication goes to the sync server as one or more parts on the
//! `ARTIFACT_PUBLICATION` document kind, each at most
//! [`PUBLICATION_PART_BYTES`] of the serialized publication behind a fixed
//! header: its change id, the BLAKE3 of the whole serialization, its total
//! length, the part's offset and the part's length. No publication outgrows
//! a frame, and a small one, an unpublish included, is one part.
//!
//! The device writes each publication it owes into its spool when the
//! publication changes, checked again at the start of every round, and pulls
//! one part at a time, a turn for each owed publication in outbox order, so
//! one large publication, or one that does not prepare, holds back no other.
//! The server keeps each part, in order, under the owner's live credential,
//! and applies the publication only once every part is there and the whole
//! hashes to the digest every part names. Only that complete publication is
//! answered, with the 33-byte receipt of digest and outcome; no part is
//! acknowledged on its own. A socket's owner-gate denial may instead refuse
//! a part immediately, echoing its supplied digest without keeping or
//! settling any transfer. A change's first part replaces a transfer that
//! did not finish; a later part never starts or revives one, and a settled
//! transfer sent again is answered with its receipt, never applied again.
//!
//! The spool is runtime state under the `bulk:` prefix: a restore drops it,
//! and the canonical outbox sends the publication again from its first part.
//! It is kept per publication entity: `tx` rows on the device, `rx` rows on
//! the server.

use std::collections::HashMap;
use std::io::{self, Write};
use std::ops::Bound;

use heed::{RoTxn, RwTxn};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The most bytes of a serialized publication one part carries. A part's
/// frame is this, its 68-byte header and the 18-byte document frame, well
/// under the server's default per-update gate. It bounds one part, never a
/// publication or the outbox.
pub const PUBLICATION_PART_BYTES: usize = 256 * 1024;

/// A part's header: change id (16), digest (32), total and offset (u64 be),
/// and the part's length (u32 be).
const PART_HEADER_LEN: usize = 68;

/// One spool row.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SpoolRow {
    /// A transfer's identity, and how many of its bytes the spool holds from
    /// offset 0 on: all of them on the device.
    Transfer(Transfer),
    /// One part's bytes, at the offset its key names.
    Part {
        #[serde(with = "spool_bytes")]
        bytes: Vec<u8>,
    },
    /// The last transfer the server settled, and its outcome's byte.
    Settled {
        change_id: [u8; 16],
        digest: [u8; 32],
        outcome: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub change_id: [u8; 16],
    pub digest: [u8; 32],
    pub total: u64,
    pub held: u64,
}

/// Which end of the lane a spool row is kept at.
#[derive(Clone, Copy)]
pub enum Side {
    /// The device that sends.
    Tx,
    /// The server that receives.
    Rx,
}

/// A spool key: the side, the publication entity's hex, then the row: `m`
/// the transfer, `p:<offset as 16 hex>` one part, `s` the last one settled.
pub fn spool_key(side: Side, entity: &EntityId, row: &str) -> String {
    let side = match side {
        Side::Tx => "tx",
        Side::Rx => "rx",
    };
    format!("{side}:{}:{row}", entity.to_hex())
}

pub fn part_key(side: Side, entity: &EntityId, offset: u64) -> String {
    spool_key(side, entity, &format!("p:{offset:016x}"))
}

/// A fresh change id: 16 bytes of OS entropy.
pub fn new_publication_change_id() -> [u8; 16] {
    let mut change_id = [0_u8; 16];
    OsRng.fill_bytes(&mut change_id);
    change_id
}

/// One part as it rides the wire.
pub struct Envelope<'p> {
    pub change_id: [u8; 16],
    pub digest: [u8; 32],
    pub total: u64,
    pub offset: u64,
    pub bytes: &'p [u8],
}

impl<'p> Envelope<'p> {
    /// Reads a part: its exact length, a nonempty span, and an end no later
    /// than the total. Anything else is `None`.
    pub fn parse(payload: &'p [u8]) -> Option<Self> {
        let (header, bytes) = payload.split_at_checked(PART_HEADER_LEN)?;
        let word = |at: usize| -> Option<u64> {
            Some(u64::from_be_bytes(header.get(at..at + 8)?.try_into().ok()?))
        };
        let len = u32::from_be_bytes(header.get(64..68)?.try_into().ok()?);
        let part = Self {
            change_id: header.get(..16)?.try_into().ok()?,
            digest: header.get(16..48)?.try_into().ok()?,
            total: word(48)?,
            offset: word(56)?,
            bytes,
        };
        let fits = usize::try_from(len).ok()? == bytes.len()
            && !bytes.is_empty()
            && part.offset.checked_add(u64::from(len))? <= part.total;
        fits.then_some(part)
    }

    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.bytes.len() as u64)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = u32::try_from(self.bytes.len())
            .map_err(|_| Error::InvariantViolation("artifact publication part length"))?;
        let mut payload = Vec::with_capacity(PART_HEADER_LEN + self.bytes.len());
        payload.extend_from_slice(&self.change_id);
        payload.extend_from_slice(&self.digest);
        payload.extend_from_slice(&self.total.to_be_bytes());
        payload.extend_from_slice(&self.offset.to_be_bytes());
        payload.extend_from_slice(&len.to_be_bytes());
        payload.extend_from_slice(self.bytes);
        Ok(payload)
    }
}

/// A round under way: the digest it sends and the offset of its next part.
#[derive(Debug, Clone, Copy)]
pub struct Round {
    pub digest: [u8; 32],
    pub next: u64,
}

/// A part's bytes as one msgpack bin, not an array of integers.
pub mod spool_bytes {
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
