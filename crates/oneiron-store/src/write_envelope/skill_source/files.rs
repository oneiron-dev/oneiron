//! Exact skill source files and their declared metadata format.

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

/// How source fields relate to native metadata. Neither variant grants trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillPackageFormat {
    /// Required name, description and version come from scalar SKILL.md frontmatter.
    Folder,
    /// Native metadata is separate from exact authored bytes. Frontmatter may be
    /// partial or absent; any capabilities still come from the source, not a grant.
    Native,
}
