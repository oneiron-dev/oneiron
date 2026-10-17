//! Canonical, inert AGENT_PACK facets derived from real definitions and selected rows.
use super::portable_knowledge::{KnowledgeFormat, encode_agent_knowledge};
use super::{AgentDefinition, encode_agent_definition};
use crate::batch::export::ExportEntity;
use crate::claim::{ClaimSubject, decode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::serialize::ExportBody;
use crate::share_travel::{
    AgentPackKnowledge, AgentPackSkill, AgentPackTravelProjection, BornWith, TravelChoice,
};
use crate::skill::{SkillRecord, canonical_skill_tree_hash};
use crate::skill_hub::{HubFile, HubPackage};
use rmpv::Value;
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

impl AgentSkillReference {
    pub(crate) fn validate(&self) -> Result<()> {
        EntityId::from_hex(&self.entity_id)?;
        crate::skill::SkillContentHash::parse_hex(&self.content_hash)?;
        if self.skill_id.is_empty()
            || self.version.is_empty()
            || self.min_version.as_deref() == Some("")
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(crate) fn entity_id(&self) -> &str {
        &self.entity_id
    }
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
    agent_pack_files_in(KnowledgeFormat::CURRENT, id, def, refs, knowledge)
}

/// The facets as `agent_pack_files` writes them, with the selected knowledge
/// in `format`: a captured tree is re-derived in the form it was captured in.
pub(crate) fn agent_pack_files_in(
    format: KnowledgeFormat,
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
    // Source-vault short refs belong to the archive's entity envelopes, not
    // to the portable knowledge facet. A fork captures the same claims before
    // export and has no source-vault ref; hashing either path must agree.
    for row in &mut knowledge {
        row.short_ref = None;
    }
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
            encode_agent_knowledge(format, &knowledge)?,
        ),
    ];
    canonical_skill_tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    Ok(files)
}

/// A selected knowledge claim a travelling AgentPack leaves out, for the
/// export receipt: only plain text travels, and nothing drops silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OmittedClaim {
    pub(crate) claim: EntityId,
    pub(crate) reason: OmittedClaimReason,
}

/// Why a knowledge claim stays home.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OmittedClaimReason {
    /// Its value names an entity or an edge.
    RefValue,
    /// Its value is not text, and names no entity or edge.
    TypedValue,
}

/// The facets a sharer sends another party (OF-491): the reference-free
/// AgentPack projection, not the native facets above. Each skill dependency
/// travels with the body of the package its reference pins; a missing or
/// mismatched package refuses the pack. Knowledge travels only as plain text:
/// a typed or ref-bearing claim is left out, never stringified, and returned
/// as an [`OmittedClaim`] in the order the selection is walked (by claim id).
/// Also returns the born-with text that travelled under `choice`. Both lists
/// are for the export receipt.
#[expect(
    clippy::too_many_arguments,
    reason = "the sharing door's admitted snapshot parts and the sharer's choice meet here"
)]
pub(crate) fn agent_pack_files_travelling(
    id: &EntityId,
    def: &AgentDefinition,
    refs: &[AgentSkillReference],
    packages: &BTreeMap<EntityId, HubPackage>,
    claims: &[ExportEntity],
    world_name: Option<&str>,
    born_with_text: BornWith,
    choice: &TravelChoice,
) -> Result<(Vec<HubFile>, BornWith, Vec<OmittedClaim>)> {
    let refused =
        || Error::InvalidConfig("agent pack travel: unresolved or mismatched skill".into());
    if refs.len() != def.skills.len() {
        return Err(refused());
    }
    let mut skills = Vec::with_capacity(refs.len());
    for (dependency, reference) in def.skills.iter().zip(refs) {
        let package = packages
            .get(&EntityId::from_hex(&reference.entity_id)?)
            .ok_or_else(refused)?;
        if package.record.skill_id != reference.skill_id
            || package.record.version != reference.version
            || package.content_hash()?.to_hex() != reference.content_hash
        {
            return Err(refused());
        }
        skills.push(AgentPackSkill::from_package(dependency, package)?);
    }
    let mut selected = select_agent_knowledge(id, claims);
    selected.sort_by(|a, b| a.id.cmp(&b.id));
    let mut knowledge = Vec::with_capacity(selected.len());
    let mut omitted = Vec::new();
    for row in selected {
        let claim = decode_claim_body(&row.body.to_bytes()?, false)?;
        if let Some(text) = claim.value.as_str() {
            knowledge.push(AgentPackKnowledge {
                text: text.to_owned(),
                predicate: claim.predicate,
            });
        } else {
            omitted.push(OmittedClaim {
                claim: EntityId::from_hex(&row.id)?,
                reason: if names_a_ref(&claim.value) {
                    OmittedClaimReason::RefValue
                } else {
                    OmittedClaimReason::TypedValue
                },
            });
        }
    }
    let born_with = choice.project(born_with_text);
    let files = AgentPackTravelProjection::from_definition(
        def,
        world_name,
        skills,
        knowledge,
        born_with.clone(),
    )?
    .files()?;
    Ok((files, born_with, omitted))
}

/// Whether a claim value holds, at any depth, binary that reads as an entity
/// id or an edge ref.
fn names_a_ref(value: &Value) -> bool {
    match value {
        Value::Binary(bytes) => ClaimSubject::decode(bytes).is_ok(),
        Value::Array(items) => items.iter().any(names_a_ref),
        Value::Map(entries) => entries
            .iter()
            .any(|(key, value)| names_a_ref(key) || names_a_ref(value)),
        _ => false,
    }
}

fn invalid() -> Error {
    Error::InvariantViolation("agent facet encoding failed")
}
