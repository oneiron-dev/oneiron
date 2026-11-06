//! Holder-bound exact skill source carrier framing.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::skill_package::HubPackage;
use crate::store::skill_package::codec::{decode_hub_package, encode_hub_package, invalid};
use crate::write_envelope::skill_record::SkillContentHash;
use sha2::{Digest, Sha256};

const MAGIC: &[u8] = b"oneiron.hub-source.v1\0";
const DOMAIN: &[u8] = b"oneiron.hub-source.asset.v1\0";

pub(crate) fn source_carrier_id(holder: &EntityId, hash: &SkillContentHash) -> Result<EntityId> {
    let digest = Sha256::new()
        .chain_update(DOMAIN)
        .chain_update(holder.as_bytes())
        .chain_update(hash.as_bytes())
        .finalize();
    EntityId::from_bytes(
        digest[..16]
            .try_into()
            .map_err(|_| invalid("source ID width"))?,
    )
}

pub(crate) fn encode_source_carrier(holder: &EntityId, package: &HubPackage) -> Result<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(holder.as_bytes());
    out.extend_from_slice(&encode_hub_package(&canonical_source_package(package)?)?);
    Ok(out)
}

/// Historical erase closure needs only the fixed holder reference. It must
/// scrub a matching source even if a peer corrupted the package payload; this
/// accessor grants no admission and is never used to materialize source bytes.
#[cfg(feature = "sync")]
pub(crate) fn source_carrier_holder(bytes: &[u8]) -> Option<EntityId> {
    let rest = bytes.strip_prefix(MAGIC)?;
    EntityId::from_bytes(rest.get(..16)?.try_into().ok()?).ok()
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

pub(crate) fn canonical_source_package(package: &HubPackage) -> Result<HubPackage> {
    let record = crate::write_envelope::skill_record::SkillRecord::new(
        &package.record.skill_id,
        &package.record.desc,
        &package.record.version,
        oneiron_contracts::claim::ClaimApprovalStatus::Proposed,
        crate::write_envelope::skill_record::SkillLifecycle::Candidate,
        oneiron_contracts::claim::ClaimSource::Imported,
        0.5,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![("source".into(), "byte-custody".into())]),
    )
    .with_content_hash(package.content_hash()?)
    .with_role(package.record.role, package.record.call.clone());
    let mut canonical =
        HubPackage::new(record, package.files.clone(), package.capabilities.clone());
    canonical.format = package.format;
    Ok(canonical)
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
