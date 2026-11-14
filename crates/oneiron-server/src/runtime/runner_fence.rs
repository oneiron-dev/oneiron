//! The runner fence of this server's vault (canon `#runner-fence`, row
//! L8-27): every runner the daemon starts on the host, a seat's official
//! CLI first, runs without the vault's data tree (the vault directory) and
//! its control tree (the key custody directory beside it), under one rule
//! this host proves once. The rule and the proof are
//! [`oneiron_container::RunnerFence`]'s; this module names the trees, keeps
//! the proof, and hands each runner its command and its session manifest.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use oneiron_container::{RunnerFence, RunnerFenceOutcome, SessionManifest};

use crate::server::SyncServer;

/// The runner fence one server puts its runners under, and what the proof
/// of it on this host found.
#[derive(Debug)]
pub struct HostRunnerFence {
    fence: RunnerFence,
    outcome: RunnerFenceOutcome,
}

impl HostRunnerFence {
    /// The fence that removes the vault at `vault_path` and the key custody
    /// directory beside it, proved on this host.
    ///
    /// # Errors
    /// `vault_path` is not an absolute path below `/`.
    pub fn for_vault(vault_path: &Path) -> io::Result<Self> {
        let custody = oneiron::store::custody_container_path(vault_path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(Self::proved(RunnerFence::for_host([
            vault_path.to_path_buf(),
            custody,
        ])?))
    }

    /// `fence`, proved on this host once.
    #[must_use]
    pub fn proved(fence: RunnerFence) -> Self {
        let outcome = fence.prove();
        Self { fence, outcome }
    }

    /// What the proof found: the outcome each runner session's manifest
    /// carries unless its own spawn could not apply the rule.
    #[must_use]
    pub fn outcome(&self) -> &RunnerFenceOutcome {
        &self.outcome
    }

    /// The command for `program`, started in `workdir` under the fence,
    /// with the outcome its session's manifest carries and a private temp
    /// directory as its `TMPDIR`. The temp directory exists before the rule
    /// is built, so the runner can write there even where the system temp
    /// directory is on the way to a removed tree. A runner with no `workdir`
    /// of its own starts in that temp directory (`/` where none was made).
    ///
    /// The runner still runs, unfenced and unproven, where the rule cannot
    /// be built for this spawn, and where `workdir` or its git directories
    /// lie in a removed tree: a masked copy's checkout is a worktree of a
    /// repository in the vault's data tree (FIX 7608), and git there needs
    /// that repository. Canon `#fence-unproven`: the engine never refuses
    /// the run.
    #[must_use]
    pub fn command(&self, program: impl AsRef<OsStr>, workdir: Option<&Path>) -> RunnerCommand {
        let scratch = tempfile::Builder::new()
            .prefix("oneiron-runner-")
            .tempdir()
            .inspect_err(|error| {
                tracing::warn!(
                    error = %error,
                    "runner fence: no private temp directory for a runner"
                );
            })
            .ok();
        let (mut command, outcome) = if workdir.is_some_and(|dir| self.needs_removed_tree(dir)) {
            tracing::warn!(
                "runner fence: a runner's working tree needs a removed tree (a masked \
                 checkout's repository in the vault); it runs unproven"
            );
            (oneiron_spawn::command(program), self.unproven())
        } else {
            match self.fence.command(program.as_ref()) {
                Ok(command) => (command, self.outcome.clone()),
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "runner fence: the rule could not be built for a runner; it runs unproven"
                    );
                    (oneiron_spawn::command(program), self.unproven())
                }
            }
        };
        command.current_dir(
            workdir
                .or_else(|| scratch.as_ref().map(tempfile::TempDir::path))
                .unwrap_or(Path::new("/")),
        );
        if let Some(scratch) = &scratch {
            command.env("TMPDIR", scratch.path());
        }
        RunnerCommand {
            command,
            outcome,
            scratch,
        }
    }

    /// This host's outcome for a runner that runs without the rule.
    fn unproven(&self) -> RunnerFenceOutcome {
        RunnerFenceOutcome {
            proven: false,
            ..self.outcome.clone()
        }
    }

    /// Whether a runner working in `workdir` needs a removed tree: the tree
    /// itself, its git directory, or the common directory of the repository
    /// a linked worktree belongs to lies in one.
    fn needs_removed_tree(&self, workdir: &Path) -> bool {
        let removed = self.fence.removed();
        std::iter::once(workdir.to_path_buf())
            .chain(git_dirs(workdir))
            .filter_map(|path| fs::canonicalize(path).ok())
            .any(|path| removed.iter().any(|tree| path.starts_with(tree)))
    }
}

/// One runner's command under the fence, what its session's manifest
/// states, and the private temp directory it writes in. Keep this value
/// until the runner has exited: dropping it removes the temp directory.
#[derive(Debug)]
pub struct RunnerCommand {
    /// The command, with its working directory and `TMPDIR` set.
    pub command: Command,
    /// What this runner's session manifest states.
    pub outcome: RunnerFenceOutcome,
    /// The runner's `TMPDIR`; `None` where it could not be made.
    pub scratch: Option<tempfile::TempDir>,
}

/// The git directories a working tree at `workdir` uses: its `.git`, and
/// for a linked worktree (a `.git` file `gitdir: <dir>`) that directory and
/// the common directory its `commondir` file names.
fn git_dirs(workdir: &Path) -> Vec<PathBuf> {
    let dot_git = workdir.join(".git");
    let named = fs::read_to_string(&dot_git).ok().and_then(|text| {
        text.lines()
            .next()
            .and_then(|line| line.strip_prefix("gitdir:"))
            .map(|dir| workdir.join(dir.trim()))
    });
    let Some(git_dir) = named else {
        return vec![dot_git];
    };
    let common = fs::read_to_string(git_dir.join("commondir"))
        .ok()
        .map(|dir| git_dir.join(dir.trim()));
    std::iter::once(git_dir).chain(common).collect()
}

/// The session manifest of one runner session: `backend` names the runner,
/// and the argument list is `program` then `args`.
#[must_use]
pub fn runner_session_manifest(
    outcome: &RunnerFenceOutcome,
    backend: &str,
    program: &str,
    args: &[String],
) -> SessionManifest {
    let argv: Vec<OsString> = std::iter::once(program)
        .chain(args.iter().map(String::as_str))
        .map(OsString::from)
        .collect();
    outcome.session_manifest(backend, program, &argv)
}

impl SyncServer {
    /// This server's runner fence, built and proved at its first use (serve
    /// proves it at start). `None` where the vault's trees cannot be named,
    /// and then every runner runs unfenced with no manifest.
    pub(crate) fn runner_fence(&self) -> Option<Arc<HostRunnerFence>> {
        self.runner_fence
            .get_or_init(|| match HostRunnerFence::for_vault(self.vault.path()) {
                Ok(fence) => {
                    let outcome = fence.outcome();
                    tracing::info!(
                        mechanism = ?outcome.mechanism,
                        proven = outcome.proven,
                        ruleset_hash = %outcome.ruleset_hash,
                        "runner fence"
                    );
                    Some(Arc::new(fence))
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        "runner fence: the vault's trees cannot be named; runners run unfenced"
                    );
                    None
                }
            })
            .clone()
    }
}
