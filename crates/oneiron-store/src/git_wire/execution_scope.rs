//! Private Git execution view, derived only from an admitted repository profile.

use std::fs;
use std::io::Write;
use std::path::Path;

use tempfile::TempDir;

use crate::git_wire::failure::invalid;
use crate::git_wire::repository_profile::RefBackend;
use oneiron_base::error::Result;

pub fn link_if_present(common: &Path, shadow: &Path, name: &str) -> Result<()> {
    let source = common.join(name);
    if source.exists() {
        link_common_entry(&source, &shadow.join(name))?;
    }
    Ok(())
}

#[cfg(unix)]
fn link_common_entry(source: &Path, target: &Path) -> Result<()> {
    std::os::unix::fs::symlink(source, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn link_common_entry(_source: &Path, _target: &Path) -> Result<()> {
    Err(invalid("isolated Git execution requires a supported host"))
}
