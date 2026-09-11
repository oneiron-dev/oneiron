use heed::RwTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::store::Store;

use super::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::ArtifactError;

/// Validates fork lineage and the inherited ceiling for a local `AGENT_DEF` create.
///
/// # Errors
///
/// Rejects a self-reference, a missing or non-`AGENT_DEF` parent, or a widened
/// ceiling. Propagates parent-row storage and decoding errors.
pub(super) fn validate_local_agent_definition_create(
    store: &Store,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
    created: &crate::agent_def::AgentDefinition,
) -> Result<()> {
    if let Some(parent) = created.forked_from {
        if parent == *id {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "forkedFrom cannot name the fork itself",
            )));
        }
        let parent_raw = store
            .entities
            .get(wtxn, parent.as_bytes())?
            .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "forkedFrom parent must exist as a type-17 AGENT_DEF",
            )))?;
        let parent_header = EntityMetadataHeader::parse(&parent_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        if parent_header.entity_type != ENTITY_TYPE_AGENT_DEF {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "forkedFrom parent must exist as a type-17 AGENT_DEF",
            )));
        }
        let parent_definition =
            crate::agent_def::decode_agent_definition(&parent_raw[ENTITY_METADATA_HEADER_LEN..])?;
        if created.ceiling.widens_beyond(parent_definition.ceiling) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "forked agent ceiling cannot widen beyond its parent row ceiling",
            )));
        }
    }
    Ok(())
}
