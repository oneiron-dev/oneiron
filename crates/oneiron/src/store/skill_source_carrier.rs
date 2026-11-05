//! Core half of `store::skill_source_carrier`: its store-layer items live in `oneiron_store::skill_source_carrier` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::skill_source_carrier::*;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::skill_package::HubPackage;
use crate::store::skill_package::codec::{decode_hub_package, encode_hub_package, invalid};
use crate::write_envelope::skill_record::SkillContentHash;
use sha2::{Digest, Sha256};

pub(crate) fn encode_source_carrier(holder: &EntityId, package: &HubPackage) -> Result<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(holder.as_bytes());
    out.extend_from_slice(&encode_hub_package(&canonical_source_package(package)?)?);
    Ok(out)
}

/// The holder is read from the envelope, not guessed from a content-index winner.
/// Unrelated ASSETs return None; malformed source envelopes fail closed.
pub(crate) fn decode_source_carrier(bytes: &[u8]) -> Result<Option<(EntityId, HubPackage)>> {
    if crate::store::skill_package::codec::is_hub_package_envelope(bytes) {
        return Err(invalid("holderless packages are not source carriers"));
    }
    let Some(rest) = bytes.strip_prefix(MAGIC) else {
        return Ok(None);
    };
    let holder = EntityId::from_bytes(
        rest.get(..16)
            .ok_or_else(|| invalid("truncated source holder"))?
            .try_into()
            .map_err(|_| invalid("source holder width"))?,
    )?;
    let package = decode_hub_package(&rest[16..])?;
    if encode_source_carrier(&holder, &package)? != bytes {
        return Err(invalid("noncanonical source carrier"));
    }
    Ok(Some((holder, package)))
}

/// Only a valid envelope at its derived ID can extend deletion's graph scope.
/// Malformed historical payloads are still scrubbed, but grant no other erasure.
#[cfg(feature = "sync")]
pub(crate) fn source_carrier_matches_id(bytes: &[u8], id: &EntityId) -> bool {
    let Ok(Some((holder, package))) = decode_source_carrier(bytes) else {
        return false;
    };
    package
        .content_hash()
        .and_then(|hash| source_carrier_id(&holder, &hash))
        .is_ok_and(|expected| expected == *id)
}
