//! A cell's world: a fresh repository of the task's base, one commit, the
//! sealed paths removed.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::beam::BeamResult;

use super::super::manifest::{Task, invalid};
use super::Pack;
use super::git::{git, git_stdout, run_git};

impl Pack<'_> {
    /// Builds the world at `root`: a fresh repository of the base's tree,
    /// one commit, the sealed paths removed. `add -f` keeps tracked files
    /// that match an ignore rule. With writers, each gets a worktree of it
    /// on its own branch at `<arm folder>/<writer>/tree`, beside a shared
    /// `integration` branch. Returns the root commit.
    pub(super) fn build_world(
        &self,
        root: &Path,
        task: &Task,
        writers: &[&str],
    ) -> BeamResult<String> {
        std::fs::create_dir(root)?;
        let mut archive = git(&self.repo)
            .args(["archive", "--format=tar", &task.base])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let tar_input = archive
            .stdout
            .take()
            .ok_or_else(|| invalid("git archive gave no output pipe".to_owned()))?;
        let unpacked = Command::new("tar")
            .args(["-x", "-f", "-", "-C"])
            .arg(root)
            .stdin(tar_input)
            .stderr(Stdio::null())
            .status()?;
        let archived = archive.wait()?;
        if !(archived.success() && unpacked.success()) {
            return Err(invalid(format!(
                "the world of task `{}`: git archive of base {} into {} failed",
                task.id,
                task.base,
                root.display()
            )));
        }
        for path in &task.sealed {
            remove_path(&root.join(path))?;
        }
        run_git(root, &["init", "-q"])?;
        run_git(root, &["add", "-A", "-f"])?;
        run_git(
            root,
            &[
                "-c",
                "user.name=code-bench",
                "-c",
                "user.email=code-bench@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--no-verify",
                "-m",
                &world_subject(task),
            ],
        )?;
        let commit = git_stdout(root, &["rev-parse", "HEAD"])?
            .map(|commit| commit.trim().to_owned())
            .ok_or_else(|| invalid(format!("no world commit in {}", root.display())))?;
        if !writers.is_empty() {
            run_git(root, &["branch", "integration"])?;
            let arm_dir = root.parent().unwrap_or(root);
            for writer in writers {
                let tree = arm_dir.join(writer).join("tree");
                let added = git(root)
                    .args(["worktree", "add", "-q", "-b", writer])
                    .arg(&tree)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()?;
                if !added.success() {
                    return Err(invalid(format!(
                        "git worktree add of writer `{writer}` at {} failed",
                        tree.display()
                    )));
                }
            }
        }
        Ok(commit)
    }
}

/// The subject of a world's one root commit.
fn world_subject(task: &Task) -> String {
    format!("code-bench world: {} at {}", task.id, task.base)
}

/// The source repository's work tree and Git folder, absolute; a linked
/// worktree keeps its objects in its main repository's folder.
pub(super) fn source_folders(repo: &Path) -> BeamResult<Vec<PathBuf>> {
    let mut folders = vec![std::fs::canonicalize(repo)?];
    let common = git_stdout(
        repo,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    if let Some(common) = common {
        let common = std::fs::canonicalize(common.trim())?;
        if !folders.iter().any(|folder| common.starts_with(folder)) {
            folders.push(common);
        }
    }
    Ok(folders)
}

/// Removes a sealed path from the world, whatever it is; a path the base
/// lacks is no error.
fn remove_path(path: &Path) -> BeamResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path)?,
        Ok(_) => std::fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
