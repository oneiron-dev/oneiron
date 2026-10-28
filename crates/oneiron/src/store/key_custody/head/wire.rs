//! The custody head's wire (KS-4): its MessagePack shapes, the key id that
//! binds a compartment and its wraps to their place in one head, and the
//! unauthenticated reads of a head's position.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::Result;

use super::super::log::{CustodyPosition, POSITION_LEN};
use super::super::recipients::RecipientRetirement;
use super::{CompartmentScope, carried_pads, head_corrupt};

pub(super) const HEAD_MAGIC: &[u8; 4] = b"OCHD";
/// Version 2 carries erased credentials' evidence in every host-readable
/// compartment (FIX 10584 item 3), one pad per world compartment, each
/// compartment's whole wire committed, and the carried world compartments
/// (PAD-3). A version-1 head reads as invalid until the next publication
/// pass seals it again (FIX 10469): no old-head reader.
pub(super) const HEAD_VERSION: u16 = 2;

/// The derive-key context of a compartment's envelope key id ([`key_id`]).
const KEY_ID_CONTEXT: &str = "oneiron/custody-head/compartment-key-id/v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HeadWire {
    pub(super) version: u16,
    #[serde(with = "serde_bytes_vec")]
    pub(super) position: Vec<u8>,
    pub(super) compartments: Vec<CompartmentWire>,
    /// Earlier heads' world compartments a restore here did not open (PAD-3).
    pub(super) carried_world_pads: Vec<carried_pads::CarriedWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompartmentWire {
    pub(super) scope: u8,
    /// A world compartment's world (FIX 6706); absent on every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) world: Option<[u8; 16]>,
    /// A world compartment's one pad (PAD-3); absent on every other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pad: Option<carried_pads::PadCompartmentIdentity>,
    #[serde(with = "serde_bytes_vec")]
    pub(super) sealed: Vec<u8>,
    pub(super) wraps: Vec<WrapWire>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WrapWire {
    pub(super) to: u8,
    pub(super) root: Option<[u8; 32]>,
    /// A world compartment's admitted machine (FIX 6706).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) machine: Option<[u8; 16]>,
    #[serde(with = "serde_bytes_vec")]
    pub(super) envelope: Vec<u8>,
}

/// One compartment's plaintext. The control compartment holds the control
/// secret and the other compartments' digests; the rest hold entries.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BodyWire {
    pub(super) control: Option<[u8; 32]>,
    pub(super) digests: Vec<[u8; 32]>,
    pub(super) live: Vec<EntryWire>,
    pub(super) retired: Vec<FactWire>,
    /// The control compartment's: every released escrow recipient the
    /// lineage retired, public facts only (LC FIX 5384/5385).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) recipients: Vec<RecipientRetirement>,
    /// A host-readable compartment's: body history rows, ids only (FIX
    /// 6229), sealed under the compartment's key like its entries.
    pub(super) history: Vec<HistoryWire>,
    /// A host-readable compartment's: each erased credential's fact (FIX
    /// 10584 item 3), value-free, whatever key eligibility keeps local.
    pub(super) evidence: Vec<EvidenceWire>,
    /// The control compartment's: each carried compartment's digest (PAD-3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) carried_digests: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceWire {
    pub(super) credential: [u8; 16],
    pub(super) fact: u8,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HistoryWire {
    #[serde(with = "serde_bytes_vec")]
    pub(super) key: Vec<u8>,
    #[serde(with = "serde_bytes_vec")]
    pub(super) value: Vec<u8>,
}

impl Drop for BodyWire {
    fn drop(&mut self) {
        if let Some(control) = &mut self.control {
            control.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntryWire {
    pub(super) kind: u8,
    #[serde(with = "serde_bytes_vec")]
    pub(super) item: Vec<u8>,
    pub(super) generation: u64,
    #[serde(with = "serde_bytes_vec")]
    pub(super) secret: Vec<u8>,
}

impl Drop for EntryWire {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FactWire {
    pub(super) kind: u8,
    #[serde(with = "serde_bytes_vec")]
    pub(super) item: Vec<u8>,
    pub(super) generation: u64,
}

/// Byte strings as msgpack bin, not arrays of numbers.
pub(in crate::store::key_custody) mod serde_bytes_vec {
    use serde::{Deserializer, Serializer};

    pub(in crate::store::key_custody) fn serialize<S: Serializer>(
        bytes: &[u8],
        out: S,
    ) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(bytes)
    }

    pub(in crate::store::key_custody) fn deserialize<'de, D: Deserializer<'de>>(
        input: D,
    ) -> Result<Vec<u8>, D::Error> {
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

/// What binds a compartment and its key's wraps to their place in exactly
/// this head: a 32-byte commitment to the whole of `position | u32be index |
/// scope`, and a world compartment's world, which fits an envelope's key id
/// (FIX 6769, 6706).
pub(super) fn key_id(
    position: &[u8; POSITION_LEN],
    index: u32,
    scope: Option<CompartmentScope>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(KEY_ID_CONTEXT);
    hasher.update(position);
    hasher.update(&index.to_be_bytes());
    hasher.update(&[scope.map_or(0, CompartmentScope::code)]);
    if let Some(world) = scope.and_then(CompartmentScope::world) {
        hasher.update(world.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn parse(head: &[u8]) -> Result<HeadWire> {
    let body = head.strip_prefix(HEAD_MAGIC).ok_or_else(head_corrupt)?;
    let wire: HeadWire = rmp_serde::from_slice(body).map_err(|_| head_corrupt())?;
    if wire.version != HEAD_VERSION || wire.compartments.is_empty() {
        return Err(head_corrupt());
    }
    Ok(wire)
}

/// The position a head claims, read without opening it: what a target lists
/// and a status reports. Nothing here is authenticated until it opens.
pub(in crate::store::key_custody) fn head_position(head: &[u8]) -> Result<CustodyPosition> {
    CustodyPosition::from_bytes(&parse(head)?.position).ok_or_else(head_corrupt)
}

/// The position the first bytes of a head claim, before the rest of it has
/// arrived: a residence stage an upload is still writing (FIX 6415). The
/// wire is a map whose first two entries are [`HeadWire`]'s version and
/// position, read alone here. `None` when they are not there yet, or are
/// not this engine's. Unauthenticated, as [`head_position`] is.
pub(in crate::store::key_custody) fn staged_position(lead: &[u8]) -> Option<CustodyPosition> {
    use rmpv::Value;
    let body = lead.strip_prefix(HEAD_MAGIC)?;
    let shape = rmp_serde::to_vec_named(&HeadWire {
        version: HEAD_VERSION,
        position: Vec::new(),
        compartments: Vec::new(),
        carried_world_pads: Vec::new(),
    })
    .ok()?;
    let (map, entries) = body.split_first()?;
    if shape.first() != Some(map) {
        return None;
    }
    let mut cursor = std::io::Cursor::new(entries);
    let version_key = rmpv::decode::read_value(&mut cursor).ok()?;
    let version = rmpv::decode::read_value(&mut cursor).ok()?;
    let position_key = rmpv::decode::read_value(&mut cursor).ok()?;
    let position = rmpv::decode::read_value(&mut cursor).ok()?;
    match (version_key, version, position_key, position) {
        (
            Value::String(version_key),
            Value::Integer(version),
            Value::String(position_key),
            Value::Binary(position),
        ) if version_key.as_str() == Some("version")
            && version.as_u64() == Some(u64::from(HEAD_VERSION))
            && position_key.as_str() == Some("position") =>
        {
            CustodyPosition::from_bytes(&position)
        }
        _ => None,
    }
}
