use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::skill::{SkillContentHash, SkillRecord, canonical_skill_tree_hash};

use super::support::validate_text;

const MAX_CAPABILITY_ENTRIES: usize = 256;
pub(super) const MAX_CAPABILITY_TEXT_BYTES: usize = 512;
pub(crate) const MAX_HUB_FILE_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_HUB_PACKAGE_FILES: usize = 4096;
pub(crate) const MAX_HUB_PACKAGE_TOTAL_BYTES: usize = 32 * 1024 * 1024;

/// One file in a fetched, exportable skill package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubFile {
    pub path: String,
    pub content: Vec<u8>,
}

impl HubFile {
    /// Constructs an owned package file.
    #[must_use]
    pub fn new(path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            content: content.into(),
        }
    }
}

/// Capability surface used by the rug-pull widening diff.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkillCapabilitySurface {
    pub bins: BTreeSet<String>,
    pub env: BTreeSet<String>,
    pub mcp: BTreeSet<String>,
    pub allowed_tools: BTreeSet<String>,
}

impl SkillCapabilitySurface {
    /// Adds a required binary.
    #[must_use]
    pub fn with_bin(mut self, value: impl Into<String>) -> Self {
        self.bins.insert(value.into());
        self
    }

    /// Adds a required environment key.
    #[must_use]
    pub fn with_env(mut self, value: impl Into<String>) -> Self {
        self.env.insert(value.into());
        self
    }

    /// Adds a required MCP capability.
    #[must_use]
    pub fn with_mcp(mut self, value: impl Into<String>) -> Self {
        self.mcp.insert(value.into());
        self
    }

    /// Adds an allowed tool.
    #[must_use]
    pub fn with_allowed_tool(mut self, value: impl Into<String>) -> Self {
        self.allowed_tools.insert(value.into());
        self
    }

    pub(super) fn validate(&self) -> Result<()> {
        for entries in [&self.bins, &self.env, &self.mcp, &self.allowed_tools] {
            if entries.len() > MAX_CAPABILITY_ENTRIES {
                return Err(Error::InvalidSkillBody(
                    "capability surface has too many entries",
                ));
            }
            for entry in entries {
                validate_text(
                    entry,
                    MAX_CAPABILITY_TEXT_BYTES,
                    "capability entries must be non-empty",
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn is_same_or_narrower_than(&self, prior: &Self) -> bool {
        self.bins.is_subset(&prior.bins)
            && self.env.is_subset(&prior.env)
            && self.mcp.is_subset(&prior.mcp)
            && self.allowed_tools.is_subset(&prior.allowed_tools)
    }
}

/// Offline package fetched by an adapter or supplied directly to a vault door.
#[derive(Debug, Clone, PartialEq)]
pub struct HubPackage {
    pub record: SkillRecord,
    pub files: Vec<HubFile>,
    pub capabilities: SkillCapabilitySurface,
}

impl HubPackage {
    /// Constructs a package. Tree validation runs when its canonical hash is read.
    #[must_use]
    pub fn new(
        record: SkillRecord,
        files: Vec<HubFile>,
        capabilities: SkillCapabilitySurface,
    ) -> Self {
        Self {
            record,
            files,
            capabilities,
        }
    }

    /// Recomputes canonical identity from the package tree.
    pub fn content_hash(&self) -> Result<SkillContentHash> {
        self.capabilities.validate()?;
        if self.files.len() > MAX_HUB_PACKAGE_FILES {
            return Err(Error::InvalidSkillBody("hub package has too many files"));
        }
        let mut total_bytes = 0_usize;
        for file in &self.files {
            if file.content.len() > MAX_HUB_FILE_BYTES {
                return Err(Error::InvalidSkillBody(
                    "hub package file exceeds the maximum size",
                ));
            }
            total_bytes =
                total_bytes
                    .checked_add(file.content.len())
                    .ok_or(Error::InvalidSkillBody(
                        "hub package total size exceeds the maximum",
                    ))?;
            if total_bytes > MAX_HUB_PACKAGE_TOTAL_BYTES {
                return Err(Error::InvalidSkillBody(
                    "hub package total size exceeds the maximum",
                ));
            }
        }
        canonical_skill_tree_hash(
            self.files
                .iter()
                .map(|file| (file.path.as_str(), file.content.as_slice())),
        )
    }

    /// Returns a clean, path-sorted folder independent of package origin.
    pub fn export_files(&self) -> Result<Vec<HubFile>> {
        self.content_hash()?;
        let mut files = self.files.clone();
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        Ok(files)
    }
}

/// One http-index discovery row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubIndexEntry {
    pub name: String,
    pub description: String,
    pub version: String,
    pub content_hash: SkillContentHash,
    pub ref_string: String,
}
