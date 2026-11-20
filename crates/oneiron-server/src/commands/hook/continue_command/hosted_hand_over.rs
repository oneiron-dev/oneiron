//! The hooks' hand-over of a session's log to the selected hosted vault
//! ([`hand_over_hosted`]): step 3 of `oneiron continue --cloud` alone, over
//! the same bridge and import.
//!
//! A Claude Code session sends its log and its subagents' logs
//! ([`transcript::read_hook_log`]). Every other host's session sends one
//! file, read by the import that reads that host's logs locally and named
//! as that import names it (FIX HOOK-HOSTED-HAND-OVER-OTHER-HOSTS):
//!
//! - Codex: its rollout, `rollout-<time>-<session>.jsonl`, below
//!   `$CODEX_HOME/sessions`, else `~/.codex/sessions`;
//! - Cursor: `<session>.jsonl`, below `~/.cursor/projects`;
//! - GitHub Copilot: the CLI's `<session>/events.jsonl` below
//!   `~/.copilot/session-state`, or VS Code's `transcripts/<session>.jsonl`
//!   below VS Code's (or VS Code Insiders') `User/workspaceStorage` in the
//!   person's config folder.
//!
//! The log must be named for the event's own session, so an event never
//! sends another session's log where its own session's starts bound, and
//! must sit below its host's folder, every folder on the way and the log
//! opened through no link ([`transcript::read_one_below`]), so nothing
//! outside the host's own logs is sent.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;

use oneiron::ingest::history::{HookTranscriptImportView, HookTranscriptSource};

use super::transcript::SessionLogs;
use super::{Hosted, transcript};
use crate::cli::HookHost;
use crate::commands::hook::hosted_selection::HostedVault;

/// The hooks' hand-over to the selected hosted vault: `host`'s session log
/// at `log` (Claude Code's with its subagents' logs), landed through
/// `vault.imports.hook_transcript` as step 3 lands them, over one `oneiron
/// mcp` as the selection's own credential, in its own mode, under the
/// consent `policy_ref` names. The bridge's stderr goes nowhere, as the
/// local import's does: a hand-over's output is not the host's.
///
/// Only the log of the event's own session `session` goes ([`host_log`]),
/// and only in calls the selection's carrier takes
/// ([`transcript::calls_within`]): a log too long for it is refused before
/// any bridge starts, so no hand-over sends a call that could never land.
pub(in crate::commands::hook) fn hand_over_hosted(
    oneiron: &Path,
    vault: &HostedVault,
    host: HookHost,
    session: &str,
    log: &Path,
    policy_ref: String,
    deadline: Instant,
) -> anyhow::Result<()> {
    let logs = host_log(host, log, session)?;
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

/// The log at `path` that `host`'s event of the session `session` names,
/// read and encoded: refused unless it is named for that session and sits
/// below one of the folders `host` keeps its session logs in.
fn host_log(host: HookHost, path: &Path, session: &str) -> anyhow::Result<SessionLogs> {
    let (source, stem, roots) = match host {
        HookHost::ClaudeCode | HookHost::Hermes => {
            return transcript::read_hook_log(path, session);
        }
        HookHost::Codex => (
            HookTranscriptSource::Codex,
            rollout_stem(path, session),
            vec![codex_sessions()?],
        ),
        HookHost::Cursor => (
            HookTranscriptSource::HookTranscript,
            own_stem(path, session),
            vec![home()?.join(".cursor").join("projects")],
        ),
        HookHost::Copilot => copilot_log(path, session)?,
    };
    let stem = stem.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not the log of {} session {session}, whose event named it",
            path.display(),
            host.product_name()
        )
    })?;
    let Some(root) = roots.iter().find(|root| path.starts_with(root)) else {
        let shown: Vec<String> = roots
            .iter()
            .map(|root| root.display().to_string())
            .collect();
        anyhow::bail!(
            "{} is not under {}, where {} keeps its session logs",
            path.display(),
            shown.join(" or "),
            host.product_name()
        );
    };
    transcript::read_one_below(root, path, stem, source)
}

/// A host's log as [`host_log`] reads it: its source, its stem as the
/// import names it (`None` when it is not the event's session's log), and
/// the folders it may sit below.
type HostLog = (HookTranscriptSource, Option<String>, Vec<PathBuf>);

/// A Copilot log: the CLI's `events.jsonl`, in a folder named for its
/// session below `~/.copilot/session-state`; else VS Code's
/// `<session>.jsonl` in a `transcripts` folder below VS Code's workspace
/// storage.
fn copilot_log(path: &Path, session: &str) -> anyhow::Result<HostLog> {
    let folder = path.parent().and_then(Path::file_name);
    if path.file_name() == Some(OsStr::new("events.jsonl")) {
        return Ok((
            HookTranscriptSource::HookTranscript,
            (folder == Some(OsStr::new(session))).then(|| session.to_owned()),
            vec![home()?.join(".copilot").join("session-state")],
        ));
    }
    let stem = own_stem(path, session).filter(|_| folder == Some(OsStr::new("transcripts")));
    Ok((
        HookTranscriptSource::HookTranscript,
        stem,
        vs_code_workspace_storage()?,
    ))
}

/// The rollout's stem, `rollout-<time>-<session>`, when `path` is a Codex
/// rollout of `session`.
fn rollout_stem(path: &Path, session: &str) -> Option<String> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".jsonl")?;
    (stem.starts_with("rollout-") && stem.ends_with(&format!("-{session}")))
        .then(|| stem.to_owned())
}

/// `session`, when `path` is named `<session>.jsonl`.
fn own_stem(path: &Path, session: &str) -> Option<String> {
    (path.file_name() == Some(OsStr::new(&format!("{session}.jsonl")))).then(|| session.to_owned())
}

/// Codex's folder of rollouts: `sessions` in `$CODEX_HOME`, else in
/// `~/.codex`.
fn codex_sessions() -> anyhow::Result<PathBuf> {
    let codex = match std::env::var_os("CODEX_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home()?.join(".codex"),
    };
    Ok(codex.join("sessions"))
}

/// VS Code's and VS Code Insiders' folders of workspace storage, in the
/// person's config folder (`~/Library/Application Support` on macOS,
/// `$XDG_CONFIG_HOME` or `~/.config` elsewhere).
fn vs_code_workspace_storage() -> anyhow::Result<Vec<PathBuf>> {
    let config =
        dirs::config_dir().ok_or_else(|| anyhow::anyhow!("no config folder; HOME is not set"))?;
    Ok(["Code", "Code - Insiders"]
        .into_iter()
        .map(|app| config.join(app).join("User").join("workspaceStorage"))
        .collect())
}

/// The person's home folder.
fn home() -> anyhow::Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow::anyhow!("HOME is not set"))
}
