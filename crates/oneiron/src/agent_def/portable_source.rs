//! Immutable captured agent source. Imported/replicated bytes are lineage data, not authorship.
use super::{AgentDefinition, decode_agent_definition, encode_agent_definition};
use crate::batch::export::{ExportEntity, ExportFileTree};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET};
use crate::serialize::ExportBody;
use crate::{
    entity_id::EntityId,
    error::{Error, Result},
    store::Store,
};
use serde::{Deserialize, Serialize};
const FORMAT: &str = "oneiron.agent-birth-source.v1";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentBirthSource {
    format: String,
    child_id: String,
    source_id: String,
    child_agent_id: String,
    child_logical_id: Option<String>,
    pub(crate) tree: ExportFileTree,
    source_definition: ExportBody,
}
pub(crate) fn birth_source_id(child: &EntityId) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(
        b"oneiron.agent-birth-source.v1",
        &[child.as_bytes()],
    )
}
pub(crate) fn encode_birth_source(
    child: &EntityId,
    created: &AgentDefinition,
    source: &EntityId,
    definition: &AgentDefinition,
    tree: ExportFileTree,
) -> Result<(EntityId, Vec<u8>)> {
    let source = AgentBirthSource {
        format: FORMAT.into(),
        child_id: child.to_hex(),
        source_id: source.to_hex(),
        child_agent_id: created.agent_id.clone(),
        child_logical_id: created.logical_id.clone(),
        tree,
        source_definition: ExportBody::from_bytes(
            &encode_agent_definition(definition)?,
            ENTITY_TYPE_AGENT_DEF,
        ),
    };
    source.validate()?;
    Ok((
        birth_source_id(child)?,
        serde_json::to_vec(&source).map_err(|_| invalid("encode"))?,
    ))
}
impl AgentBirthSource {
    pub(crate) fn child(&self) -> Result<EntityId> {
        EntityId::from_hex(&self.child_id)
    }
    fn validate(&self) -> Result<()> {
        let child = EntityId::from_hex(&self.child_id)?;
        let source = EntityId::from_hex(&self.source_id)?;
        if self.format != FORMAT
            || child.to_hex() != self.child_id
            || source.to_hex() != self.source_id
            || self.child_agent_id.is_empty()
            || self.tree.content_hash.is_none()
        {
            return Err(invalid("identity"));
        }
        self.tree.validate()?;
        self.source_definition.validate(ENTITY_TYPE_AGENT_DEF)?;
        let definition = decode_agent_definition(&self.source_definition.to_bytes()?)?;
        let files = self.tree.import_files()?;
        let file = |name: &str| {
            files
                .iter()
                .find(|file| file.path == name)
                .ok_or_else(|| invalid("missing facet"))
        };
        let refs: Vec<super::portable::AgentSkillReference> =
            serde_json::from_slice(&file("skills.json")?.content)
                .map_err(|_| invalid("skill facet"))?;
        let knowledge: Vec<ExportEntity> =
            serde_json::from_slice(&file("knowledge/selected.json")?.content)
                .map_err(|_| invalid("knowledge facet"))?;
        if super::select_agent_knowledge(&source, &knowledge) != knowledge {
            return Err(invalid("knowledge subject"));
        }
        let expected = super::agent_pack_files(&source, &definition, &refs, &knowledge)?;
        if crate::serialize::export_source_tree(&expected)? != self.tree {
            return Err(invalid("facets disagree with captured definition"));
        }
        Ok(())
    }
}
pub(crate) fn decode_birth_source(bytes: &[u8]) -> Result<Option<AgentBirthSource>> {
    #[derive(Deserialize)]
    struct Marker {
        format: String,
    }
    let Ok(marker) = serde_json::from_slice::<Marker>(bytes) else {
        return Ok(None);
    };
    if marker.format != FORMAT {
        return Ok(None);
    }
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(invalid("size"));
    }
    let source: AgentBirthSource = serde_json::from_slice(bytes).map_err(|_| invalid("shape"))?;
    source.validate()?;
    if serde_json::to_vec(&source).map_err(|_| invalid("encode"))? != bytes {
        return Err(invalid("noncanonical source"));
    }
    Ok(Some(source))
}
pub(crate) fn validate_birth_source_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    bytes: &[u8],
) -> Result<()> {
    super::birth_custody::check_registered_birth_target(store, txn, id, kind, bytes)?;
    let old = store.entities.get(txn, id.as_bytes())?;
    if let Some(old) = &old {
        let header =
            EntityMetadataHeader::parse(old).ok_or(Error::CorruptedIndex("agent source header"))?;
        if header.entity_type == ENTITY_TYPE_ASSET
            && decode_birth_source(&old[ENTITY_METADATA_HEADER_LEN..])?.is_some()
            && (kind != ENTITY_TYPE_ASSET || old[ENTITY_METADATA_HEADER_LEN..] != *bytes)
        {
            return Err(invalid("immutable source"));
        }
    }
    if kind == ENTITY_TYPE_ASSET
        && let Some(source) = decode_birth_source(bytes)?
    {
        super::birth_custody::check_birth_custody(store, txn, &source.child()?)?;
        if birth_source_id(&EntityId::from_hex(&source.child_id)?)? != *id {
            return Err(invalid("asset identity"));
        }
        if let Some(old) = old
            && old[ENTITY_METADATA_HEADER_LEN..] != *bytes
        {
            return Err(invalid("asset collision"));
        }
    }
    Ok(())
}
/// Read frozen bytes by the CHILD identity, never by a guess at today's parent
/// hash. Neither the carrier nor this function can mint author or execution rights.
/// Archive payload visibility follows the live child and every captured
/// selected-knowledge/skill input. Standalone ASSET enumeration cannot bypass
/// the originating rows' off-record, deletion or taint exclusions.
pub(crate) fn birth_source_exportable(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<bool> {
    let Some(source) = decode_birth_source(bytes)? else {
        return Ok(true);
    };
    let child = EntityId::from_hex(&source.child_id)?;
    if read_birth_source(store, txn, &child)?.is_none() {
        return Ok(false);
    }
    let files = source.tree.import_files()?;
    let knowledge = files
        .iter()
        .find(|file| file.path == "knowledge/selected.json")
        .ok_or_else(|| invalid("knowledge facet"))?;
    let knowledge: Vec<ExportEntity> =
        serde_json::from_slice(&knowledge.content).map_err(|_| invalid("knowledge facet"))?;
    let mut dependencies = vec![EntityId::from_hex(&source.source_id)?];
    for row in knowledge {
        dependencies.push(EntityId::from_hex(&row.id)?);
    }
    let skills = files
        .iter()
        .find(|file| file.path == "skills.json")
        .ok_or_else(|| invalid("skill facet"))?;
    #[derive(Deserialize)]
    struct Ref {
        entity_id: String,
    }
    let skills: Vec<Ref> =
        serde_json::from_slice(&skills.content).map_err(|_| invalid("skill facet"))?;
    for skill in skills {
        dependencies.push(EntityId::from_hex(&skill.entity_id)?);
    }
    for dependency in dependencies {
        if store.off_record_sessions.contains_entity(&dependency)?
            || !crate::vault::live_entity_row_in_txn(store, txn, &dependency)?.is_live()
            || !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, &dependency)?
                .is_empty()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn read_birth_source(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    child: &EntityId,
) -> Result<Option<AgentBirthSource>> {
    if store.off_record_sessions.contains_entity(child)?
        || !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, child)?.is_empty()
    {
        return Ok(None);
    }
    let crate::vault::LiveEntityRow::Live { entity_type, body } =
        crate::vault::live_entity_row_in_txn(store, txn, child)?
    else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_AGENT_DEF {
        return Ok(None);
    }
    let current = decode_agent_definition(&body)?;
    let asset = birth_source_id(child)?;
    if store.off_record_sessions.contains_entity(&asset)?
        || !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, &asset)?.is_empty()
    {
        return Ok(None);
    }
    let crate::vault::LiveEntityRow::Live { entity_type, body } =
        crate::vault::live_entity_row_in_txn(store, txn, &asset)?
    else {
        return Ok(None);
    };
    if entity_type != ENTITY_TYPE_ASSET {
        return Ok(None);
    }
    let source = decode_birth_source(&body)?.ok_or_else(|| invalid("occupied carrier address"))?;
    if source.child_id != child.to_hex()
        || source.child_agent_id != current.agent_id
        || source.child_logical_id != current.logical_id
        || source.source_id != current.forked_from.unwrap_or(*child).to_hex()
    {
        return Err(invalid("child identity disagrees"));
    }
    Ok(Some(source))
}
fn invalid(reason: &'static str) -> Error {
    Error::Artifact(crate::error::ArtifactError::InvalidAgentDefBody(reason))
}

#[cfg(test)]
mod tests;
