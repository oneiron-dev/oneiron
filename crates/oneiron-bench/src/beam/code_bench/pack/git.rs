//! Git in a folder, reading no stdin.

use std::{
    path::Path,
    process::{Command, Stdio},
};

use crate::beam::BeamResult;

use super::super::manifest::invalid;

/// Git in `dir`, reading no stdin.
pub(super) fn git(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(dir).stdin(Stdio::null());
    command
}

pub(in super::super) fn git_ok(repo: &Path, args: &[&str]) -> BeamResult<bool> {
    Ok(git(repo)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

/// Git's stdout, or `None` when the command fails.
pub(super) fn git_stdout(dir: &Path, args: &[&str]) -> BeamResult<Option<String>> {
    let output = git(dir).args(args).stderr(Stdio::null()).output()?;
    Ok(output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned()))
}

pub(super) fn run_git(dir: &Path, args: &[&str]) -> BeamResult<()> {
    let output = git(dir).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(invalid(format!(
        "git {} in {} failed: {}",
        args.join(" "),
        dir.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
