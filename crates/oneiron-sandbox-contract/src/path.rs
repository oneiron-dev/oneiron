//! Canonical guest-workspace addressing, including byte-counted components.
use super::{Result, refused};

pub const WORKSPACE_ROOT: &str = "/mnt/workspace";
pub const MAX_WORKSPACE_PATH_BYTES: usize = 4096;
pub const MAX_PATH_COMPONENT_BYTES: usize = 255;
pub const MAX_PATH_COMPONENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkspacePath(String);
impl WorkspacePath {
    pub fn parse(path: &str) -> Result<Self> {
        let relative = path
            .strip_prefix("/mnt/workspace/")
            .ok_or_else(|| refused("not a workspace file"))?;
        if path.len() > MAX_WORKSPACE_PATH_BYTES
            || relative.split('/').count() > MAX_PATH_COMPONENTS
            || relative.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.len() > MAX_PATH_COMPONENT_BYTES
                    || part.contains(['\\', '\0'])
            })
        {
            return Err(refused("noncanonical or excessive path"));
        }
        Ok(Self(path.to_owned()))
    }
    pub fn from_relative(relative: &str) -> Result<Self> {
        Self::parse(&format!("{WORKSPACE_ROOT}/{relative}"))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    #[must_use]
    pub fn relative(&self) -> &str {
        &self.0[WORKSPACE_ROOT.len() + 1..]
    }
}
