//! Typed, inert AGENT_PACK facets on the common pack source path.
use super::{PackManifest, invalid};
use crate::agent_def::decode_agent_definition;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::serialize::ExportBody;
use crate::share_travel::{AGENT_PACK_TRAVEL_SCHEMA, AgentPackTravelProjection};
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

/// The schema tag alone, read before either format's typed decode.
#[derive(Deserialize)]
struct PolicySchema {
    schema: String,
}

/// Whether a policy facet carries the reference-free travel format (FIX
/// 2041): a pack another party shared, not the owner's native backup.
pub(super) fn is_travel_policy(policy: &[u8]) -> bool {
    serde_json::from_slice::<PolicySchema>(policy)
        .is_ok_and(|tag| tag.schema == AGENT_PACK_TRAVEL_SCHEMA)
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

    /// The projection a travelling pack's whole folder holds, `None` for
    /// the native facets. Each skill's SKILL.md must name the skill and
    /// version its `skills.json` row pins, so the skill the common door
    /// installs is the one the agent depends on.
    pub(super) fn travel(&self, files: &[HubFile]) -> Result<Option<AgentPackTravelProjection>> {
        let policy = files
            .iter()
            .find(|f| f.path == self.policy)
            .ok_or_else(|| invalid("declared agent facet is absent"))?;
        if !is_travel_policy(&policy.content) {
            return Ok(None);
        }
        let projection = AgentPackTravelProjection::from_files(files)?;
        for skill in &projection.skills {
            let package = super::super::folder::package_from_files(skill.files.clone())?;
            if package.record.skill_id != skill.skill_id
                || package.record.version != skill.version
                || package.content_hash()?.to_hex() != skill.content_hash
            {
                return Err(invalid(
                    "a travelling skill's SKILL.md disagrees with its skills.json row",
                ));
            }
        }
        Ok(Some(projection))
    }

    pub(super) fn validate_files(&self, manifest: &PackManifest, files: &[HubFile]) -> Result<()> {
        if self.travel(files)?.is_some() {
            return Ok(());
        }
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
                || reference.version.trim().is_empty()
                || reference.version.len() > 128
                || !seen.insert(&reference.skill_id)
            {
                return Err(invalid(
                    "agent skill reference is unpinned or disagrees with policy",
                ));
            }
        }
        if let Some(path) = &self.knowledge {
            let (_, knowledge) = crate::agent_def::decode_agent_knowledge(file(path)?)
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
