//! Private Git execution view, derived only from an admitted repository profile.

use std::fs;
use std::io::Write;
use std::path::Path;

use tempfile::TempDir;

use super::GitWireProcessEnv;
use super::failure::invalid;
use super::repository_profile::{AdmittedRepoProfile, RefBackend};
use crate::error::Result;

pub(super) struct PreparedGitExecution {
    shadow: TempDir,
    profile: AdmittedRepoProfile,
}

impl PreparedGitExecution {
    pub(super) fn prepare(
        process_env: &GitWireProcessEnv,
        profile: AdmittedRepoProfile,
        creates_worktree: bool,
    ) -> Result<Self> {
        // All format, config and attribute admission happened before this
        // function creates any repository registration or index effect.
        if !profile.layout.git_dir.is_dir() {
            return Err(invalid("admitted Git worktree directory disappeared"));
        }
        let shadow = tempfile::Builder::new()
            .prefix("oneiron-git-attributes-")
            .tempdir_in(&process_env.tmpdir)?;
        fs::create_dir(shadow.path().join("info"))?;
        fs::write(shadow.path().join("info/attributes"), b"")?;
        fs::write(
            shadow.path().join("config"),
            profile.semantics.render(&profile.layout),
        )?;
        if let Some(exclude) = profile.exclude_bytes() {
            fs::write(shadow.path().join("info/exclude"), exclude)?;
        }
        if creates_worktree {
            fs::create_dir_all(profile.layout.common.join("worktrees"))?;
        }
        for entry in ["objects", "logs", "worktrees", "packed-refs"] {
            link_if_present(&profile.layout.common, shadow.path(), entry)?;
        }
        let ref_store = match profile.layout.refs {
            RefBackend::Files => "refs",
            RefBackend::Reftable => "reftable",
        };
        link_if_present(&profile.layout.common, shadow.path(), ref_store)?;
        // Git's reftable format still has a conventional refs directory on
        // some versions. It is not the authority for HEAD; keep it available
        // without ever substituting it for the reftable store.
        if profile.layout.refs == RefBackend::Reftable {
            link_if_present(&profile.layout.common, shadow.path(), "refs")?;
        }
        if !shadow.path().join("objects").is_dir() || !shadow.path().join(ref_store).is_dir() {
            return Err(invalid("admitted Git backing store is unavailable"));
        }
        Ok(Self { shadow, profile })
    }

    pub(super) fn common_dir(&self) -> &Path {
        self.shadow.path()
    }

    pub(super) fn source_changed(&self) -> Result<bool> {
        self.profile.source_changed()
    }

    /// Git can write the private common-dir spelling into the linked
    /// worktree's .git file. Bind the successful (or partial) registration to
    /// the real common dir before private state is removed.
    pub(super) fn rebind_created_worktree(&self, target: &Path, succeeded: bool) -> Result<()> {
        let git_file = target.join(".git");
        let meta = match fs::symlink_metadata(&git_file) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !succeeded => {
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        if !meta.file_type().is_file() {
            return Err(invalid("worktree gitdir is not a regular file"));
        }
        let current = fs::read_to_string(&git_file)?;
        let private_prefix = format!("gitdir: {}/worktrees/", self.shadow.path().display());
        let real_prefix = format!(
            "gitdir: {}/worktrees/",
            self.profile.layout.common.display()
        );
        let (name, needs_rebind) = if let Some(name) = current.strip_prefix(&private_prefix) {
            (name.trim_end_matches('\n'), true)
        } else if let Some(name) = current.strip_prefix(&real_prefix) {
            (name.trim_end_matches('\n'), false)
        } else {
            return Err(invalid("worktree gitdir has an unexpected owner"));
        };
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err(invalid("worktree registration name is malformed"));
        }
        let registered = self.profile.layout.common.join("worktrees").join(name);
        if !registered.is_dir() {
            return Err(invalid("worktree registration is missing"));
        }
        if needs_rebind {
            let mut replacement = tempfile::NamedTempFile::new_in(target)?;
            writeln!(replacement, "gitdir: {}", registered.display())?;
            replacement
                .persist(&git_file)
                .map_err(|error| error.error)?;
        }
        self.persist_worktree_overrides(&registered)?;
        Ok(())
    }

    fn persist_worktree_overrides(&self, registered: &Path) -> Result<()> {
        let Some(config) = self.profile.worktree_overrides.render() else {
            return Ok(());
        };
        if !self.profile.layout.worktree_config_enabled {
            return Err(invalid("durable worktree settings require worktreeConfig"));
        }
        let destination = registered.join("config.worktree");
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_file() => {
                if fs::read(&destination)? == config.as_bytes() {
                    return Ok(());
                }
                return Err(invalid(
                    "created worktree config disagrees with admitted profile",
                ));
            }
            Ok(_) => return Err(invalid("created worktree config is not a regular file")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut replacement = tempfile::NamedTempFile::new_in(registered)?;
        replacement.write_all(config.as_bytes())?;
        replacement
            .persist_noclobber(&destination)
            .map_err(|error| error.error)?;
        Ok(())
    }
}

fn link_if_present(common: &Path, shadow: &Path, name: &str) -> Result<()> {
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
