//! Validated exact source trees. Parsing never edits the bytes that determine identity.
use super::{PackAdapter, PackManifest, invalid};
use crate::error::Result;
use crate::skill::{SkillContentHash, canonical_skill_tree_hash};
use crate::skill_hub::{
    HubFile, MAX_HUB_FILE_BYTES, MAX_HUB_PACKAGE_FILES, MAX_HUB_PACKAGE_TOTAL_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackSource {
    pub(super) files: Vec<HubFile>,
    pub(super) manifest: PackManifest,
    pub(super) hash: SkillContentHash,
    pub(super) sections: Vec<PackSection>,
}
impl PackSource {
    pub fn from_files(mut files: Vec<HubFile>) -> Result<Self> {
        if files.len() > MAX_HUB_PACKAGE_FILES {
            return Err(invalid("too many source files"));
        }
        let mut total = 0usize;
        for file in &files {
            total = total
                .checked_add(file.content.len())
                .ok_or_else(|| invalid("source length overflow"))?;
            if file.content.len() > MAX_HUB_FILE_BYTES || total > MAX_HUB_PACKAGE_TOTAL_BYTES {
                return Err(invalid("source exceeds byte bound"));
            }
            if file
                .path
                .split('/')
                .any(|part| part.eq_ignore_ascii_case(".git"))
            {
                return Err(invalid("repository metadata is not pack source"));
            }
            let text = std::str::from_utf8(&file.content).map_err(|_| {
                invalid("pack source must be UTF-8; binary artifacts need an asset adapter")
            })?;
            crate::batch::secret_scan::scan_metadata_field(text)?;
            if crate::batch::secret_scan::scan_file_content(&file.path, &file.content).is_some() {
                return Err(invalid("pack source contains credential material"));
            }
        }
        let hash = canonical_skill_tree_hash(
            files
                .iter()
                .map(|f| (f.path.as_str(), f.content.as_slice())),
        )?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let pack = files
            .iter()
            .find(|f| f.path == "PACK.md")
            .ok_or_else(|| invalid("missing PACK.md"))?;
        let manifest = PackManifest::parse(
            std::str::from_utf8(&pack.content).map_err(|_| invalid("PACK.md is not UTF-8"))?,
        )?;
        if let Some(PackAdapter::Script(path)) = &manifest.adapter
            && !files.iter().any(|f| f.path == *path)
        {
            return Err(invalid("declared adapter script is absent"));
        }
        if manifest.kind == super::PackKind::Agent {
            for required in ["identity.md", "policy.md", "skills.json"] {
                if !files.iter().any(|file| file.path == required) {
                    return Err(invalid(
                        "agent pack requires identity.md, policy.md and skills.json",
                    ));
                }
            }
            let refs: Vec<crate::agent_def::AgentSkillReference> = serde_json::from_slice(
                &files
                    .iter()
                    .find(|file| file.path == "skills.json")
                    .expect("checked")
                    .content,
            )
            .map_err(|_| invalid("agent skills.json must be native structured references"))?;
            if refs.len() > 128 {
                return Err(invalid("too many agent skill references"));
            }
            let mut seen = std::collections::BTreeSet::new();
            for reference in refs {
                reference.validate()?;
                if !seen.insert(reference.entity_id().to_owned()) {
                    return Err(invalid("duplicate agent skill reference"));
                }
            }
        }
        let mut sections = Vec::new();
        for file in &files {
            if file.path.starts_with("knowledge/sections/") && file.path.ends_with(".json") {
                let section: PackSection = serde_json::from_slice(&file.content)
                    .map_err(|_| invalid("invalid pack section manifest"))?;
                section.validate()?;
                if sections.len() >= 128 {
                    return Err(invalid("too many pack sections"));
                }
                if !section
                    .section_id
                    .starts_with(&format!("{}.", manifest.name))
                    || !file
                        .path
                        .ends_with(&format!("/{}.json", section.section_id))
                    || sections
                        .iter()
                        .any(|prior: &PackSection| prior.section_id == section.section_id)
                {
                    return Err(invalid("section identity must be unique and pack-scoped"));
                }
                sections.push(section);
            }
        }
        for file in &files {
            if file.path != "PACK.md"
                && !["skills/", "knowledge/", "scripts/"]
                    .iter()
                    .any(|prefix| file.path.starts_with(prefix))
                && !(manifest.kind == super::PackKind::Agent
                    && ["identity.md", "policy.md", "skills.json"].contains(&file.path.as_str()))
            {
                return Err(invalid("unknown pack source facet"));
            }
        }
        Ok(Self {
            files,
            manifest,
            hash,
            sections,
        })
    }
    pub fn entity_id(&self) -> Result<crate::EntityId> {
        super::codec::source_id(self)
    }
    pub fn files(&self) -> &[HubFile] {
        &self.files
    }
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }
    pub fn sections(&self) -> &[PackSection] {
        &self.sections
    }
    pub fn has_code(&self) -> bool {
        self.manifest.kind == super::PackKind::Connector
            || self
                .files
                .iter()
                .any(|file| file.path.starts_with("scripts/") || file.path.contains("/scripts/"))
    }
    pub fn content_hash(&self) -> SkillContentHash {
        self.hash
    }
}

/// A pack-carried board recipe. Its verbs and authority are permission requests,
/// not a second owner-consented install or executable handlers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSection {
    pub section_id: String,
    pub state_family: crate::context_board::StateFamilyRef,
    pub verbs: Vec<crate::context_board::SectionVerbRef>,
    pub authority_lane: crate::context_board::AuthorityLaneRef,
    pub budget_policy: crate::context_board::BudgetPolicyRef,
}
impl PackSection {
    fn validate(&self) -> Result<()> {
        let allow = crate::context_board::SectionVerbAllowlist::from_exported_verbs();
        if self.section_id.is_empty()
            || self.section_id.len() > 256
            || !self.section_id.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            })
            || self.verbs.is_empty()
            || self.verbs.len() > 128
            || self.verbs.iter().any(|verb| !allow.contains(verb))
            || self
                .verbs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.verbs.len()
            || self.state_family.family.is_empty()
            || self.state_family.family.len() > 256
            || self.state_family.version == 0
            || self.authority_lane.0.is_empty()
            || self.authority_lane.0.len() > 256
            || crate::context_board::section_policy_for_budget_ref(&self.budget_policy).is_err()
        {
            return Err(invalid("invalid section recipe or verb"));
        }
        Ok(())
    }
}
