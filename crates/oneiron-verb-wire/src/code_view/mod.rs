//! Moved from `crates/oneiron/src/code_view/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::build_cache::BuildCacheResult;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::checkout_task::CheckoutTaskClass;
use oneiron_store::git_wire::path_text::git_path_bytes;
use oneiron_store::git_wire::path_text::git_path_os_str;
use oneiron_store::git_wire::path_text::git_path_text_of_os;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisibleFilePolicy {
    pub version: u32,
    pub include_prefixes: Vec<String>,
    pub exclude_prefixes: Vec<String>,
}

impl VisibleFilePolicy {
    pub fn selects(&self, path: &str) -> Result<bool> {
        relative(path)?;
        if self.version != 1 {
            return Err(Error::InvalidClaimBody(
                "unknown visible-file policy version",
            ));
        }
        Ok(self.include_prefixes.iter().any(|p| path.starts_with(p))
            && !self.exclude_prefixes.iter().any(|p| path.starts_with(p)))
    }
}

/// A view path, a Git path's text (FIX 21326): a name outside UTF-8 holds its
/// canonical escape, the only NUL it may hold, and lands on disk as its own
/// bytes through [`view_path_on_disk`].
pub fn relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.contains('\\')
        || git_path_bytes(path).is_err()
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p == ".git" || p.contains(':'))
    {
        return Err(Error::InvalidClaimBody("unsafe view path"));
    }
    Ok(())
}
