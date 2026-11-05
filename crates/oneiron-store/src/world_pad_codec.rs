//! The world-key pad row codec (KS-5, FIX 5686): a pad, a pad row's
//! deterministic id, and a pad row body in its carrier, reference and
//! resting forms. The engine's world-key custody (`world_keys`) reads and
//! writes the rows; this module only encodes and decodes them.

use oneiron_authority::authority::WorldKeyId;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{Error, Result};
use zeroize::Zeroizing;

use crate::key_material::os_fill;

const PAD_ROW_DOMAIN: &[u8] = b"oneiron/world-key-pad-row/v1";

/// One key's pad. It has no `Clone` and no `Serialize`, its `Debug` prints
/// nothing, and its bytes are wiped on drop.
pub struct WorldKeyPad(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for WorldKeyPad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorldKeyPad(..)")
    }
}

impl WorldKeyPad {
    /// A fresh pad from the OS RNG, for a key being minted.
    pub fn mint() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        os_fill(&mut bytes[..])?;
        Ok(Self(bytes))
    }

    /// A pad back from a sealed pad object (`bundle`): engine-internal.
    #[doc(hidden)]
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// The pad's own bytes, for the sealed pad object (`bundle`): engine-internal.
    #[doc(hidden)]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `bytes ⊕ pad`: a key to the half its wraps seal, and that half back.
    pub fn apply(&self, bytes: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        for (slot, (byte, pad)) in out.iter_mut().zip(bytes.iter().zip(self.0.iter())) {
            *slot = byte ^ pad;
        }
        out
    }
}

/// The deterministic row id of `key`'s pad.
pub fn pad_row_id(key: &WorldKeyId) -> Result<EntityId> {
    EntityId::derive(
        PAD_ROW_DOMAIN,
        &[
            key.world.as_bytes(),
            &key.generation.to_be_bytes(),
            &key.mint,
        ],
    )
}

/// The carrier form's label.
const CARRIER_LABEL: &[u8] = b"oneiron/world-key-pad/v1\0";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ pad (32).
const CARRIER_LEN: usize = CARRIER_LABEL.len() + 16 + 8 + 16 + 32;
/// The reference form's label (CALLS: KS-5 pad reference form).
const REFERENCE_LABEL: &[u8] = b"oneiron/world-key-pad-ref/v1\0";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ custody
/// namespace (16): the bare reference.
const REFERENCE_LEN: usize = REFERENCE_LABEL.len() + 16 + 8 + 16 + 16;
/// The reference ‖ the row's own pad (32): the row at rest.
const RESTING_LEN: usize = REFERENCE_LEN + 32;

/// One pad row's body, decoded.
pub enum PadBody {
    /// The pad itself, as it travels.
    Carrier(WorldKeyId, WorldKeyPad),
    /// The key whose pad current custody holds, with the row's own pad
    /// beside it at rest; `None` for a bare reference.
    Reference(WorldKeyId, Option<WorldKeyPad>),
}

impl PadBody {
    pub fn key(&self) -> &WorldKeyId {
        match self {
            Self::Carrier(key, _) | Self::Reference(key, _) => key,
        }
    }

    /// The pad the body itself holds: a carrier's, or the one a reference
    /// rests beside.
    pub fn pad(&self) -> Option<&WorldKeyPad> {
        match self {
            Self::Carrier(_, pad) | Self::Reference(_, Some(pad)) => Some(pad),
            Self::Reference(_, None) => None,
        }
    }

    pub fn into_pad(self) -> Option<WorldKeyPad> {
        match self {
            Self::Carrier(_, pad) | Self::Reference(_, Some(pad)) => Some(pad),
            Self::Reference(_, None) => None,
        }
    }
}

/// The custody item `key`'s pad rests under: its full id, world |
/// generation | mint (CALLS: FIX 5686 pad custody item codec).
pub fn pad_item(key: &WorldKeyId) -> [u8; 40] {
    key.envelope_key_id()
}

/// `key` ‖ `pad` as a carrier body.
pub fn encode_carrier(key: &WorldKeyId, pad: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(CARRIER_LEN);
    body.extend_from_slice(CARRIER_LABEL);
    body.extend_from_slice(&pad_item(key));
    body.extend_from_slice(pad);
    body
}

/// The bare reference: `key`'s reference into `namespace`, no pad beside it.
pub fn encode_reference(key: &WorldKeyId, namespace: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(REFERENCE_LEN);
    body.extend_from_slice(REFERENCE_LABEL);
    body.extend_from_slice(&pad_item(key));
    body.extend_from_slice(namespace);
    body
}

/// The custody namespace a reference `body` names, unsigned; `None` for a
/// carrier or a body that does not decode.
pub fn reference_namespace(body: &[u8]) -> Option<[u8; 16]> {
    if !matches!(body.len(), REFERENCE_LEN | RESTING_LEN) || !body.starts_with(REFERENCE_LABEL) {
        return None;
    }
    let at = REFERENCE_LABEL.len() + 40;
    body.get(at..at + 16)?.try_into().ok()
}

/// The row at rest: `key`'s reference into `namespace`, its `pad` beside it.
pub fn encode_resting(key: &WorldKeyId, namespace: &[u8; 16], pad: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(RESTING_LEN);
    body.extend_from_slice(REFERENCE_LABEL);
    body.extend_from_slice(&pad_item(key));
    body.extend_from_slice(namespace);
    body.extend_from_slice(pad);
    body
}

/// The key a full id names: world (16) ‖ generation (8, big-endian) ‖ mint
/// (16).
pub fn key_of_id(id: &[u8]) -> Option<WorldKeyId> {
    Some(WorldKeyId {
        world: EntityId::from_bytes(id.get(..16)?.try_into().ok()?).ok()?,
        generation: u64::from_be_bytes(id.get(16..24)?.try_into().ok()?),
        mint: id.get(24..40)?.try_into().ok()?,
    })
}

/// A pad row's body in any of its forms; anything else is malformed.
pub fn decode_pad_body(body: &[u8]) -> Result<PadBody> {
    let malformed = || Error::CorruptedIndex("world key pad body");
    let (rest, carrier) = if body.len() == CARRIER_LEN && body.starts_with(CARRIER_LABEL) {
        (&body[CARRIER_LABEL.len()..], true)
    } else if matches!(body.len(), REFERENCE_LEN | RESTING_LEN) && body.starts_with(REFERENCE_LABEL)
    {
        (&body[REFERENCE_LABEL.len()..], false)
    } else {
        return Err(malformed());
    };
    let key = key_of_id(rest).ok_or_else(malformed)?;
    // A carrier's pad follows its key; a reference at rest's, its namespace.
    let pad = rest
        .get(if carrier { 40 } else { 56 }..)
        .filter(|raw| raw.len() == 32)
        .map(|raw| {
            let mut pad = Zeroizing::new([0u8; 32]);
            pad.copy_from_slice(raw);
            WorldKeyPad::from_bytes(pad)
        });
    Ok(match pad {
        Some(pad) if carrier => PadBody::Carrier(key, pad),
        pad => PadBody::Reference(key, pad),
    })
}

/// The world a pad row's `body`, with no header, names; an error for a body
/// that does not decode.
pub fn pad_world_in_body(body: &[u8]) -> Result<EntityId> {
    decode_pad_body(body).map(|body| body.key().world)
}

/// The pad row id of the key a custody `item` (its full id) names; `None`
/// for an item that names no key.
///
/// # Errors
///
/// An id that does not derive.
pub fn pad_row_of_item(item: &[u8]) -> Result<Option<EntityId>> {
    key_of_id(item).map(|key| pad_row_id(&key)).transpose()
}
