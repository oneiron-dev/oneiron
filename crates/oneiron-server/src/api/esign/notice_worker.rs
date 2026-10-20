//! The e-sign notice worker (FIX 6219, Engine design B): staged transition
//! notices (pending, completed, rejection, expiry) go out with no caller,
//! each sent as the principal its document's trail recorded while that
//! principal still stands.
//!
//! It runs on the host's housekeeping tick, after the engine's pass; it has
//! no scheduler of its own. Each pass lists the due notices grouped by
//! document and principal ([`oneiron::Vault::esign_notice_groups_due`]) and
//! hands each group to the engine
//! ([`oneiron::Vault::dispatch_esign_notices_unattended`]), which rechecks
//! the principal's recorded send act and standing in each snapshot it writes
//! in and runs the door's own claim, lease and send through the email gate
//! as that principal. The worker holds no credential and adds no authority:
//! a group with no recorded send act, or whose principal no longer stands,
//! stays staged for the principal's own `vault.esign.notices.dispatch`, and
//! a group that fails is tried again on a later pass.
//!
//! Log lines carry counts, a static reason and an error's code, never a
//! notice's text, an address or an error's message.

use oneiron::Vault;
use oneiron::blob_artifact::esign::EsignUnattendedNotices;

/// How much of the due work one housekeeping pass takes (CALLS `FIX 6219
/// notice worker pass`): every due group, in queue order. The host's stop
/// ends a pass between two groups.
#[derive(Clone, Copy)]
enum NoticeWorkerPass {
    EveryDueGroup,
}

const NOTICE_WORKER_PASS: NoticeWorkerPass = NoticeWorkerPass::EveryDueGroup;

impl NoticeWorkerPass {
    /// Whether the pass takes another group after `taken`.
    const fn takes_another(self, _taken: usize) -> bool {
        match self {
            Self::EveryDueGroup => true,
        }
    }
}

/// One pass over the due staged notices, on a blocking thread.
pub(crate) fn dispatch_due_notices(vault: &Vault, stopping: &dyn Fn() -> bool) {
    let groups = match vault.esign_notice_groups_due() {
        Ok(groups) => groups,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "e-sign notice worker could not list the staged notices");
            return;
        }
    };
    let (mut taken, mut notices, mut kept, mut failed) = (0_usize, 0_usize, 0_usize, 0_usize);
    for group in &groups {
        if stopping() || !NOTICE_WORKER_PASS.takes_another(taken) {
            break;
        }
        taken += 1;
        match vault.dispatch_esign_notices_unattended(group) {
            Ok(EsignUnattendedNotices::Dispatched { view, under_grant }) => {
                notices += view.notices.len();
                tracing::debug!(
                    notices = view.notices.len(),
                    recovered = view.recovered,
                    under_grant,
                    "e-sign notices went through the send gate as their recorded principal"
                );
            }
            Ok(EsignUnattendedNotices::KeptStaged(reason)) => {
                kept += 1;
                tracing::debug!(
                    reason,
                    "e-sign notices stay staged for their principal's own call"
                );
            }
            Err(error) => {
                failed += 1;
                tracing::warn!(
                    code = %error.code,
                    "e-sign notice group stays staged for a later pass"
                );
            }
        }
    }
    if notices > 0 || failed > 0 {
        tracing::info!(
            groups = taken,
            notices,
            kept_staged = kept,
            failed,
            "e-sign notice worker pass"
        );
    }
}
