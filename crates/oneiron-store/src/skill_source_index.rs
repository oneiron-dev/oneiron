//! Converted-skill source linkage and reverse-index maintenance.

use crate::write_envelope::skill_record::SkillRecord;
use oneiron_base::error::ArtifactError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use std::collections::HashSet;

/// Provenance key carrying the source message/turn ids a converted skill was
/// derived from, as an array of 32-char entity-id hex strings.
///
/// STRUCTURED on purpose, and this ticket mints the convention: ONE-1447 marks
/// a skill `stale` when its sources are deleted, which needs the linkage to be
/// READABLE rather than narrated in prose. [`source_message_refs`] is the
/// matching reader.
pub const PROVENANCE_SOURCE_MESSAGES_KEY: &str = "source_messages";

/// The source message/turn ids a converted skill cites, or empty when the
/// record came in on another road.
///
/// Strict on the shape it wrote: a present-but-malformed linkage is corruption,
/// not an absent linkage, and ONE-1447's deletion sweep must not read it as
/// "this skill cites nothing".
pub fn source_message_refs(record: &SkillRecord) -> Result<Vec<EntityId>> {
    const CONTEXT: &str = "source_messages must be an array of 32-char entity id hex strings";
    let Value::Map(entries) = &record.provenance else {
        return Ok(Vec::new());
    };
    let Some((_, value)) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(PROVENANCE_SOURCE_MESSAGES_KEY))
    else {
        return Ok(Vec::new());
    };
    let Value::Array(refs) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)));
    };
    refs.iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(CONTEXT)))
        })
        .collect()
}
