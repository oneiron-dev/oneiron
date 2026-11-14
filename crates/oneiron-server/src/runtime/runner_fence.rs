//! The runner fence of this server's vault (canon `#runner-fence`, row
//! L8-27): every runner the daemon starts on the host, a seat's official
//! CLI first, runs without the vault's data tree (the vault directory) and
//! its control tree (the key custody directory beside it), under one rule
//! this host proves once. The rule and the proof are
//! [`oneiron_container::RunnerFence`]'s; this module names the trees, keeps
//! the proof, and hands each runner its command and its session manifest.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
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

    /// A command for `program` under the fence, and the outcome its
    /// session's manifest carries. Where the rule cannot be built for this
    /// spawn, the runner still runs, unfenced and unproven (canon
    /// `#fence-unproven`: the engine never refuses the run).
    #[must_use]
    pub fn command(&self, program: impl AsRef<OsStr>) -> (Command, RunnerFenceOutcome) {
        match self.fence.command(program.as_ref()) {
            Ok(command) => (command, self.outcome.clone()),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "runner fence: the rule could not be built for a runner; it runs unproven"
                );
                let unproven = RunnerFenceOutcome {
                    proven: false,
                    ..self.outcome.clone()
                };
                (oneiron_spawn::command(program), unproven)
            }
        }
    }
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
