//! Core half of `git_wire::repository_profile`: its store-layer items live in `oneiron_store::git_wire::repository_profile` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::git_wire::repository_profile::*;

use super::failure::invalid;
use super::process::spawn_git_inner;
use super::{GIT_WIRE_CONFIG_POLICY, GitWireProcessEnv};
use crate::error::Result;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct AdmittedRepoProfile {
    pub(super) layout: RepoLayout,
    pub(super) semantics: WorktreeSemantics,
    pub(super) worktree_overrides: WorktreeOverrides,
    sources: [SourceFile; 4],
}

impl AdmittedRepoProfile {
    pub(super) fn admit(
        process_env: &GitWireProcessEnv,
        repo_root: &Path,
        prefix: &[OsString],
        allow_bare_worktree_add: bool,
    ) -> Result<Self> {
        let common = git_path(process_env, repo_root, prefix, "--git-common-dir")?;
        let git_dir = git_path(process_env, repo_root, prefix, "--git-dir")?;
        let sources = [
            SourceFile::observe(common.join("config"))?,
            SourceFile::observe(git_dir.join("config.worktree"))?,
            SourceFile::observe(common.join("info/attributes"))?,
            SourceFile::observe(common.join("info/exclude"))?,
        ];
        if sources[2]
            .bytes
            .as_ref()
            .is_some_and(|bytes| !bytes.is_empty())
        {
            return Err(invalid("unmodeled repository info attributes"));
        }
        let args = prefixed(
            prefix,
            &["config", "--null", "--list", "--show-scope", "--includes"],
        );
        let observed = spawn_git_inner(process_env, repo_root, &args, None, None)?;
        if !observed.success {
            return Err(invalid("git configuration snapshot could not be read"));
        }
        let (layout, semantics, worktree_overrides) =
            parse_effective_config(&observed.stdout, common, git_dir)?;
        if layout.bare && !allow_bare_worktree_add {
            return Err(invalid("bare repository requires a worktree-add operation"));
        }
        let profile = Self {
            layout,
            semantics,
            worktree_overrides,
            sources,
        };
        if profile.source_changed()? {
            return Err(invalid("repository profile changed during admission"));
        }
        // The object format is a repository fact, never guessed from a path.
        let args = prefixed(prefix, &["rev-parse", "--show-object-format=storage"]);
        let object_format = spawn_git_inner(process_env, repo_root, &args, None, None)?;
        if !object_format.success || object_format.stdout != b"sha1\n" {
            return Err(invalid("unsupported Git object format"));
        }
        if profile.source_changed()? {
            return Err(invalid("repository profile changed during admission"));
        }
        match profile.layout.refs {
            RefBackend::Files if !profile.layout.common.join("refs").is_dir() => {
                return Err(invalid("files ref store is missing"));
            }
            RefBackend::Reftable if !profile.layout.common.join("reftable").is_dir() => {
                return Err(invalid("reftable ref store is missing"));
            }
            _ => {}
        }
        if !profile.layout.common.join("objects").is_dir() {
            return Err(invalid("Git object store is missing"));
        }
        Ok(profile)
    }

    pub(super) fn exclude_bytes(&self) -> Option<&[u8]> {
        self.sources[3].bytes.as_deref()
    }

    pub(super) fn worktree_settings_hash(&self) -> [u8; 32] {
        let content = self.worktree_overrides.render().unwrap_or_default();
        hash_worktree_settings(content.as_bytes())
    }

    pub(super) fn source_changed(&self) -> Result<bool> {
        for source in &self.sources {
            if source.changed()? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn git_path(
    process_env: &GitWireProcessEnv,
    repo_root: &Path,
    prefix: &[OsString],
    flag: &str,
) -> Result<PathBuf> {
    let args = prefixed(prefix, &["rev-parse", "--path-format=absolute", flag]);
    let observed = spawn_git_inner(process_env, repo_root, &args, None, None)?;
    if !observed.success {
        return Err(invalid("Git directory cannot be verified"));
    }
    let text = std::str::from_utf8(&observed.stdout)
        .map_err(|_| invalid("Git directory must be UTF-8"))?;
    let path = Path::new(text.trim_end_matches(['\r', '\n']));
    if path.as_os_str().is_empty() {
        return Err(invalid("Git directory is empty"));
    }
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    };
    path.canonicalize().map_err(Into::into)
}
