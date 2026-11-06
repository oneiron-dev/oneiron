//! Retained parent document/frontier provenance for a skill fork's birth.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{ArtifactError, Error, Result};
use rmpv::Value;

use super::record::SkillRecord;

const DOCUMENT: &str = "forkOfDocument";
const FRONTIER: &str = "forkOfFrontier";

fn invalid_pin() -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(
        "fork parent document and frontier must be a complete typed pair",
    ))
}

/// Reads only the retained birth pin; absence never resolves today's parent.
pub fn fork_parent_pin(record: &SkillRecord) -> Result<Option<(EntityId, Vec<u8>)>> {
    let Value::Map(entries) = &record.provenance else {
        return Err(invalid_pin());
    };
    let document = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(DOCUMENT));
    let frontier = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(FRONTIER));
    match (document, frontier) {
        (None, None) => Ok(None),
        (Some((_, document)), Some((_, Value::Array(frontier)))) => {
            let document = EntityId::from_hex(document.as_str().ok_or_else(invalid_pin)?)
                .map_err(|_| invalid_pin())?;
            let frontier = frontier
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(invalid_pin)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Some((document, frontier)))
        }
        _ => Err(invalid_pin()),
    }
}

/// Writes the actual parent snapshot into a newly constructed fork record.
pub fn retain_fork_parent_pin(
    record: &mut SkillRecord,
    document: EntityId,
    frontier: Vec<u8>,
) -> Result<()> {
    let Value::Map(entries) = &mut record.provenance else {
        return Err(invalid_pin());
    };
    entries.push((Value::from(DOCUMENT), Value::from(document.to_hex())));
    entries.push((
        Value::from(FRONTIER),
        Value::Array(frontier.into_iter().map(Value::from).collect()),
    ));
    Ok(())
}
