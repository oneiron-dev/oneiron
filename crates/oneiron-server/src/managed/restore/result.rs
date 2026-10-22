//! The restore's result pipe (`--restore-result-fd`): one frame per line,
//! each written whole. A pipe that stops taking frames is let go and
//! logged, never a failed restore: a kept vault is never removed for it, and
//! `restore_status` answers for the attempt once the vault serves.

use std::io::Write as _;
use std::sync::{Mutex, PoisonError};

use oneiron_vault_contract::restore::{
    ManagedRestoreDestination, ManagedRestoreIdentity, ManagedRestorePhase,
    ManagedRestoreResultFrame, RestoreFailureReason,
};

/// The write end of the result pipe, shared by the restore's steps; `None`
/// once it took no more.
#[derive(Debug)]
pub(super) struct ResultSink(Mutex<Option<std::fs::File>>);

impl ResultSink {
    pub(super) fn new(pipe: std::fs::File) -> Self {
        Self(Mutex::new(Some(pipe)))
    }

    /// Writes `frame` as one line. Its contents are never logged.
    pub(super) fn send(&self, frame: &ManagedRestoreResultFrame) {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(pipe) = held.as_mut() else {
            return;
        };
        let written = frame.encode().and_then(|line| Ok(pipe.write_all(&line)?));
        if written.is_err() {
            tracing::warn!(
                reason = "restore_result_pipe_lost",
                "the restore result pipe took no more frames; restore_status answers for the attempt once the vault serves"
            );
            *held = None;
        }
    }

    /// A step the restore starts.
    pub(super) fn progress(&self, identity: &ManagedRestoreIdentity, phase: ManagedRestorePhase) {
        self.send(&ManagedRestoreResultFrame::Progress {
            identity: identity.clone(),
            phase,
        });
    }

    /// The restore's one failure; `identity` is `None` before the input
    /// parsed.
    pub(super) fn failed(
        &self,
        identity: Option<&ManagedRestoreIdentity>,
        reason: RestoreFailureReason,
        phase: ManagedRestorePhase,
        destination_state: ManagedRestoreDestination,
    ) {
        tracing::warn!(
            reason = "managed_restore_failed",
            cause = reason.as_str(),
            ?phase,
            destination = ?destination_state,
            "the cold managed restore failed"
        );
        self.send(&ManagedRestoreResultFrame::Failed {
            identity: identity.cloned(),
            reason,
            phase,
            destination_state,
        });
    }
}
