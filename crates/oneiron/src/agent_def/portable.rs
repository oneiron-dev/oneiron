//! Canonical, inert AGENT_PACK facets derived from real definitions and selected rows.
use super::{AgentDefinition, encode_agent_definition};
use crate::batch::export::ExportEntity;
use crate::claim::{ClaimSubject, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::serialize::ExportBody;
use crate::skill::{SkillRecord, canonical_skill_tree_hash};
use crate::skill_hub::HubFile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentSkillReference {
    pub(super) entity_id: String,
    skill_id: String,
    version: String,
    content_hash: String,
    min_version: Option<String>,
}

/// Ambiguous or unpinned references do not become guessed hashes. Version
/// constraints stay in the facet; the native runtime still resolves execution.
pub(crate) fn resolve_agent_skill_refs(
    def: &AgentDefinition,
    skills: &[(EntityId, SkillRecord)],
) -> Option<Vec<AgentSkillReference>> {
    let mut refs = Vec::new();
    for dependency in &def.skills {
        let mut candidates = skills
            .iter()
            .filter(|(_, record)| record.skill_id == dependency.skill_id);
        let (id, record) = candidates.next()?;
        if candidates.next().is_some() {
            return None;
        }
        refs.push(AgentSkillReference {
            entity_id: id.to_hex(),
            skill_id: record.skill_id.clone(),
            version: record.version.clone(),
            content_hash: record.content_hash?.to_hex(),
            min_version: dependency.min_version.clone(),
        });
    }
    Some(refs)
}

/// A selected-knowledge facet includes only ordinary claims directly ABOUT this
/// definition. Reserved actor/control claims are not portable authority.
pub(crate) fn select_agent_knowledge(id: &EntityId, claims: &[ExportEntity]) -> Vec<ExportEntity> {
    claims
        .iter()
        .filter(|row| {
            row.body
                .to_bytes()
                .ok()
                .and_then(|b| decode_claim_body(&b, false).ok())
                .is_some_and(|claim| claim.subject == ClaimSubject::Entity(*id))
        })
        .cloned()
        .collect()
}

pub(crate) fn agent_pack_files(
    id: &EntityId,
    def: &AgentDefinition,
    refs: &[AgentSkillReference],
    knowledge: &[ExportEntity],
) -> Result<Vec<HubFile>> {
    let mut facets = BTreeMap::new();
    facets.insert("identity", "identity.md");
    facets.insert("policy", "policy.md");
    facets.insert("skills", "skills.json");
    facets.insert("knowledge", "knowledge/selected.json");
    let scalar = |s: &str| serde_json::to_string(s).map_err(|_| invalid());
    let manifest = format!(
        "---\nname: {}\ndescription: {}\nversion: {}\nkind: agent\nfacets: {}\n---\n",
        scalar(&def.agent_id)?,
        scalar(&def.desc)?,
        scalar(&def.version)?,
        serde_json::to_string(&facets).map_err(|_| invalid())?,
    );
    let encoded = encode_agent_definition(def)?;
    let policy = serde_json::json!({
        "schema": "oneiron.agent-policy.v1",
        "entity_id": id.to_hex(),
        "definition": ExportBody::from_bytes(&encoded, crate::registry::ENTITY_TYPE_AGENT_DEF),
    });
    let mut knowledge = knowledge.to_vec();
    knowledge.sort_by(|a, b| a.id.cmp(&b.id));
    let files = vec![
        HubFile::new("PACK.md", manifest.into_bytes()),
        HubFile::new(
            "identity.md",
            def.instructions.as_deref().unwrap_or("").as_bytes(),
        ),
        HubFile::new(
            "policy.md",
            serde_json::to_vec(&policy).map_err(|_| invalid())?,
        ),
        HubFile::new(
            "skills.json",
            serde_json::to_vec(refs).map_err(|_| invalid())?,
        ),
        HubFile::new(
            "knowledge/selected.json",
            serde_json::to_vec(&knowledge).map_err(|_| invalid())?,
        ),
    ];
    canonical_skill_tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    Ok(files)
}

fn invalid() -> Error {
    Error::InvariantViolation("agent facet encoding failed")
}
