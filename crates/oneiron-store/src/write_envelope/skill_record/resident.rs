//! Immutable resident ownership encoded in a skill record.

use super::SkillRecord;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{ArtifactError, Error, Result};
use rmpv::Value;

pub const RESIDENT_PROVENANCE_KEY: &str = "residentActor";

/// A fork's owner, if it has one. Invalid/duplicate marks refuse the read;
/// an ambiguous owner must never be interpreted as an unowned shared skill.
pub fn resident_of(record: &SkillRecord) -> Result<Option<EntityId>> {
    let Value::Map(entries) = &record.provenance else {
        return Ok(None);
    };
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() != Some(RESIDENT_PROVENANCE_KEY) {
            continue;
        }
        if found.is_some() {
            return Err(invalid_owner());
        }
        let hex = value.as_str().ok_or_else(invalid_owner)?;
        found = Some(EntityId::from_hex(hex).map_err(|_| invalid_owner())?);
    }
    Ok(found)
}

pub fn invalid_owner() -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(
        "residentActor must name one valid actor entity id",
    ))
}
