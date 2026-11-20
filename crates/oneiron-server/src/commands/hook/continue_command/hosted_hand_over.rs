//! The hooks' hand-over of a Claude Code session's log to the selected
//! hosted vault ([`hand_over_hosted`]): step 3 of `oneiron continue
//! --cloud` alone, over the same bridge and import.

use std::path::Path;
use std::process::Stdio;
use std::time::Instant;

use oneiron::ingest::history::HookTranscriptImportView;

use super::{Hosted, transcript};
use crate::commands::hook::hosted_selection::HostedVault;

/// The hooks' hand-over to the selected hosted vault: the Claude Code session
/// log at `log` and its subagents' logs, landed through
/// `vault.imports.hook_transcript` as step 3 lands them, over one `oneiron
/// mcp` as the selection's own credential, in its own mode, under the
/// consent `policy_ref` names. The bridge's stderr goes nowhere, as the
/// local import's does: a hand-over's output is not the host's.
///
/// Only the log of the event's own session `session` goes, and only in
/// calls the selection's carrier takes ([`transcript::calls_within`]): a log
/// too long for it is refused before any bridge starts, so no hand-over
/// sends a call that could never land.
pub(in crate::commands::hook) fn hand_over_hosted(
    oneiron: &Path,
    vault: &HostedVault,
    session: &str,
    log: &Path,
    policy_ref: String,
    deadline: Instant,
) -> anyhow::Result<()> {
    let logs = transcript::read_hook_log(log, session)?;
    let calls = transcript::calls_within(&logs, transcript::carried_bytes(vault.auth_mode))?;
    let mut remote = Hosted::open(oneiron, vault, policy_ref, Stdio::null(), deadline)?;
    let mut landed = Ok(());
    for call in &calls {
        landed = remote
            .call::<HookTranscriptImportView>(
                "vault.imports.hook_transcript",
                call,
                "land this session's log in the selected vault",
            )
            .map(drop);
        if landed.is_err() {
            break;
        }
    }
    remote.bridge.close();
    landed
}
