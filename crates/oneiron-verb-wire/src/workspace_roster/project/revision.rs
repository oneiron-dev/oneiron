//! Moved from `crates/oneiron/src/workspace_roster/project/revision.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::project::*;
use oneiron_store::side_table::key::FixedSideKey;
use oneiron_store::side_table::key::SideKey;
use serde::Deserialize;
use serde::Serialize;

/// blake3(REVISION_HASH_DOMAIN || canonical body). Serde: a MessagePack bin of
/// exactly 32 bytes, or the array of exactly 32 numbers serde_json writes for
/// it; another length is refused.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectRevisionHash(pub [u8; 32]);

impl std::fmt::Debug for ProjectRevisionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            oneiron_contracts::entity_id::bytes_to_hex_lower(&self.0)
        )
    }
}

impl Serialize for ProjectRevisionHash {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProjectRevisionHash {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Bytes32;
        impl<'de> serde::de::Visitor<'de> for Bytes32 {
            type Value = ProjectRevisionHash;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("32 bytes")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                bytes: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                bytes
                    .try_into()
                    .map(ProjectRevisionHash)
                    .map_err(|_| E::invalid_length(bytes.len(), &self))
            }
            // serde_json writes the bytes as an array of numbers; exactly 32
            // of them read back (FIX 3296).
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut bytes = Vec::with_capacity(32);
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                self.visit_bytes(&bytes)
            }
        }
        deserializer.deserialize_bytes(Bytes32)
    }
}

impl SideKey for ProjectRevisionHash {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }
}

impl FixedSideKey for ProjectRevisionHash {
    const WIDTH: usize = 32;
}
