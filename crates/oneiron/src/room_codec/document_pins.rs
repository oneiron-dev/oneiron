//! Document pin spelling and multipart joining shared by sync and recovery.

use loro::LoroMap;
use serde::{Deserialize, Serialize};

use super::carrier_parts::{PART_BYTES, Parts, join_parts_from};
use super::loro_bytes::map_get_bytes;
use crate::entity_doc::{CitationPin, DocActor};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};

pub(crate) fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("document pin refused: {reason}"))
}

/// Decodes a pin's bytes, with the message it quotes and the record that
/// cites it. A pin has one spelling, so equal pins ride under one key.
pub(crate) fn decode_pin(bytes: &[u8]) -> Result<(CitationPin, EntityId, EntityId)> {
    let pin: CitationPin = rmp_serde::from_slice(bytes).map_err(|_| refused("not a pin"))?;
    if rmp_serde::to_vec_named(&pin).ok().as_deref() != Some(bytes) {
        return Err(refused("not in its one spelling"));
    }
    let (message, citation) = pin
        .carried_ids()
        .ok_or_else(|| refused("not a whole pin"))?;
    Ok((pin, message, citation))
}

/// What a pin key holds: the pin, when it fits in a part, or the manifest of
/// its parts.
pub(crate) enum Carried {
    Whole(CitationPin, EntityId, EntityId),
    Parted(PartedPin),
}

/// The manifest of a pin larger than a part (FIX 4789): the parts of the
/// pin naming no one, and the actor it names, so no part names anyone and
/// the actor is rewritten here alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PartedPin {
    pub(crate) parts: Parts,
    pub(crate) actor: DocActor,
}

/// Decodes the value under a pin key, in its one spelling.
pub(crate) fn decode_carried(bytes: &[u8]) -> Result<Carried> {
    if bytes.len() <= PART_BYTES
        && let Ok((pin, message, citation)) = decode_pin(bytes)
    {
        return Ok(Carried::Whole(pin, message, citation));
    }
    let parted: PartedPin = rmp_serde::from_slice(bytes).map_err(|_| refused("not a pin"))?;
    if rmp_serde::to_vec_named(&parted).ok().as_deref() != Some(bytes)
        || !parted.parts.well_formed()
    {
        return Err(refused("not a pin's parts"));
    }
    Ok(Carried::Parted(parted))
}

/// The key `pin`, of `message` cited by `citation`, rides under: the two
/// ids, then the digest of its one spelling naming no one, so the pin and
/// its erased twin ride under one key (FIX 4247).
pub(crate) fn carrier_key(
    message: EntityId,
    citation: EntityId,
    pin: &CitationPin,
) -> Result<String> {
    let bytes =
        rmp_serde::to_vec_named(&pin.actor_erased()).map_err(|_| refused("does not encode"))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.document_pins.v1");
    hasher.update(&bytes);
    Ok(format!(
        "{}/{}/{}",
        message.to_hex(),
        citation.to_hex(),
        bytes_to_hex_lower(&hasher.finalize().as_bytes()[..16])
    ))
}

/// The message and citation a pin key names, when it is one's spelling.
pub(crate) fn key_ids(map_key: &str) -> Option<(EntityId, EntityId)> {
    let named = |hex: &str| EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex);
    let mut segments = map_key.split('/');
    let message = named(segments.next()?)?;
    let citation = named(segments.next()?)?;
    let digest = segments.next()?;
    let digest_spelled = digest.len() == 32
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    (segments.next().is_none() && digest_spelled).then_some((message, citation))
}

/// The pin under `map_key`, joined from `map`'s parts when it rides in
/// them; `Ok(None)` while a part has not landed.
pub(crate) fn carried_pin(
    map: &LoroMap,
    map_key: &str,
    bytes: &[u8],
) -> Result<Option<CitationPin>> {
    carried_pin_from(map_key, bytes, |key| map_get_bytes(map, key))
}

/// The same pin codec over stored rows rather than a live Loro map.
pub(crate) fn carried_pin_from<B: AsRef<[u8]>>(
    map_key: &str,
    bytes: &[u8],
    get: impl FnMut(&str) -> Option<B>,
) -> Result<Option<CitationPin>> {
    let (pin, message, citation) = match decode_carried(bytes)? {
        Carried::Whole(pin, message, citation) => (pin, message, citation),
        Carried::Parted(parted) => {
            let Some(whole) = join_parts_from(&parted.parts, get) else {
                return Ok(None);
            };
            let (mut pin, message, citation) = decode_pin(&whole)?;
            if pin.actor != DocActor::Erased {
                return Err(refused("a part names an actor"));
            }
            pin.actor = parted.actor;
            // A pin that fits in a part rides whole: one spelling per pin.
            if !rmp_serde::to_vec_named(&pin).is_ok_and(|bytes| bytes.len() > PART_BYTES) {
                return Err(refused("not a pin's parts"));
            }
            (pin, message, citation)
        }
    };
    if carrier_key(message, citation, &pin)? != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(Some(pin))
}
