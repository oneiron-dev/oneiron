//! Typed, inert AGENT_PACK facets on the common pack source path.
use super::{PackManifest, invalid};
use crate::agent_def::decode_agent_definition;
use crate::batch::export::ExportEntity;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::serialize::ExportBody;
use crate::skill::SkillContentHash;
use crate::skill_hub::HubFile;
use serde::Deserialize;
use std::collections::BTreeSet;

/// The closed facet map used by native AGENT_PACK export and hub agent folders.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPackFacets {
    pub identity: String,
    pub policy: String,
    pub skills: String,
    pub knowledge: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentPolicyFacet {
    schema: String,
    entity_id: String,
    definition: ExportBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSkillRef {
    entity_id: String,
    skill_id: String,
    version: String,
    content_hash: String,
    min_version: Option<String>,
}

impl AgentPackFacets {
    pub(super) fn validate_paths(&self) -> Result<()> {
        if self.identity != "identity.md"
            || self.policy != "policy.md"
            || self.skills != "skills.json"
        {
            return Err(invalid(
                "agent facets must name identity.md, policy.md and skills.json",
            ));
        }
        if self
            .knowledge
            .as_ref()
            .is_some_and(|path| !path.starts_with("knowledge/") || !path.ends_with(".json"))
        {
            return Err(invalid(
                "agent knowledge facet must be a knowledge/*.json file",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_files(&self, manifest: &PackManifest, files: &[HubFile]) -> Result<()> {
        let file = |path: &str| -> Result<&[u8]> {
            files
                .iter()
                .find(|f| f.path == path)
                .map(|f| f.content.as_slice())
                .ok_or_else(|| invalid("declared agent facet is absent"))
        };
        let identity = std::str::from_utf8(file(&self.identity)?)
            .map_err(|_| invalid("agent identity facet is not UTF-8"))?;
        let policy: AgentPolicyFacet = serde_json::from_slice(file(&self.policy)?)
            .map_err(|_| invalid("agent policy facet is not typed JSON"))?;
        if policy.schema != "oneiron.agent-policy.v1"
            || EntityId::from_hex(&policy.entity_id)
                .ok()
                .is_none_or(|id| id.to_hex() != policy.entity_id)
        {
            return Err(invalid("agent policy schema or entity identity is invalid"));
        }
        policy
            .definition
            .validate(ENTITY_TYPE_AGENT_DEF)
            .map_err(|_| invalid("agent policy definition is not a safe native body"))?;
        let definition = decode_agent_definition(&policy.definition.to_bytes()?)
            .map_err(|_| invalid("agent policy definition is invalid"))?;
        if definition.agent_id != manifest.name
            || definition.desc != manifest.description
            || definition.version != manifest.version
            || definition.instructions.as_deref().unwrap_or("") != identity
        {
            return Err(invalid("agent identity and policy disagree with PACK.md"));
        }
        let refs: Vec<AgentSkillRef> = serde_json::from_slice(file(&self.skills)?)
            .map_err(|_| invalid("agent skills facet is not typed JSON"))?;
        if refs.len() != definition.skills.len() {
            return Err(invalid("agent skills facet disagrees with policy"));
        }
        let mut seen = BTreeSet::new();
        for (reference, dependency) in refs.iter().zip(&definition.skills) {
            if EntityId::from_hex(&reference.entity_id)
                .ok()
                .is_none_or(|id| id.to_hex() != reference.entity_id)
                || SkillContentHash::parse_hex(&reference.content_hash).is_err()
                || reference.skill_id != dependency.skill_id
                || reference.min_version != dependency.min_version
                || reference.version.is_empty()
                || reference.version.len() > 128
                || !seen.insert(&reference.skill_id)
            {
                return Err(invalid(
                    "agent skill reference is unpinned or disagrees with policy",
                ));
            }
        }
        if let Some(path) = &self.knowledge {
            let knowledge: Vec<ExportEntity> = serde_json::from_slice(file(path)?)
                .map_err(|_| invalid("agent knowledge facet is not typed JSON"))?;
            let id = EntityId::from_hex(&policy.entity_id)
                .map_err(|_| invalid("agent policy entity identity is invalid"))?;
            if crate::agent_def::select_agent_knowledge(&id, &knowledge) != knowledge {
                return Err(invalid("agent knowledge facet contains foreign rows"));
            }
        }
        Ok(())
    }
}
