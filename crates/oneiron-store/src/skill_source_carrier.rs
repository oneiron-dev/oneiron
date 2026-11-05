//! Holder-bound exact skill source carrier framing.

use crate::skill_package::codec::invalid;
use crate::skill_package::package::HubPackage;
use crate::write_envelope::skill_record::SkillContentHash;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8] = b"oneiron.hub-source.v1\0";
const DOMAIN: &[u8] = b"oneiron.hub-source.asset.v1\0";

pub fn source_carrier_id(holder: &EntityId, hash: &SkillContentHash) -> Result<EntityId> {
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

/// Historical erase closure needs only the fixed holder reference. It must
/// scrub a matching source even if a peer corrupted the package payload; this
/// accessor grants no admission and is never used to materialize source bytes.
#[cfg(feature = "sync")]
pub fn source_carrier_holder(bytes: &[u8]) -> Option<EntityId> {
    let rest = bytes.strip_prefix(MAGIC)?;
    EntityId::from_bytes(rest.get(..16)?.try_into().ok()?).ok()
}

pub fn canonical_source_package(package: &HubPackage) -> Result<HubPackage> {
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
