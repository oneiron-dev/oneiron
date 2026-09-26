//! Validated exact source trees. Parsing never edits the bytes that determine identity.
use super::{PackAdapter, PackKind, PackManifest, invalid};
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
        for file in &files {
            if manifest.kind == PackKind::Agent && file.path.starts_with("scripts/") {
                return Err(invalid("agent pack cannot contain executable scripts"));
            }
            if file.path != "PACK.md"
                && !(manifest.kind == PackKind::Agent
                    && matches!(
                        file.path.as_str(),
                        "identity.md" | "policy.md" | "skills.json"
                    ))
                && !["skills/", "knowledge/", "scripts/"]
                    .iter()
                    .any(|prefix| file.path.starts_with(prefix))
            {
                return Err(invalid("unknown pack source facet"));
            }
        }
        if let Some(facets) = &manifest.agent_facets {
            facets.validate_files(&manifest, &files)?;
        }
        Ok(Self {
            files,
            manifest,
            hash,
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
    pub fn content_hash(&self) -> SkillContentHash {
        self.hash
    }
}
