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
//!   `$CODEX_HOME/sessions` (`CODEX_HOME` resolved as Codex resolves it),
//!   else `~/.codex/sessions`;
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
//!
//! An OAuth selection lands logs on its hand-over sign-in alone, `full` at
//! the vault's `/mcp` ([`StepUp::HandOver`]): its recall sign-in is `read`,
//! and the import writes. With none standing, or when a send does not land
//! the log whole, the log waits in the vault's hand-over queue
//! ([`hand_over_queue`]), and the first to wait says so on stderr. Every
//! hand-over that lands a log whole lands the waiting logs of the same host
//! after it, each read through the same checks and sent only while its
//! session is bound to that vault alone (row
//! HOOK-HOSTED-HAND-OVER-OAUTH-READ-TIER; lead ruling B, Sat 21 Nov 07:0x).

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;

use oneiron::ingest::history::{
    HookTranscriptImportRequest, HookTranscriptImportView, HookTranscriptPartView,
    HookTranscriptSource,
};

use super::transcript::SessionLogs;
use super::{CallUnconfirmed, Hosted, ToolRefused, transcript};
use crate::cli::HookHost;
use crate::commands::hook::hand_over_queue;
use crate::commands::hook::hosted_selection::{HostedAuthMode, HostedVault};
use crate::commands::hook::hosted_sign_in::StepUp;
use crate::commands::hook::recall::RpcRefusal;
use crate::commands::hook::session_binding::{self, SessionBinding};

/// The hooks' hand-over to the selected hosted vault: `host`'s session log
/// at `log` (Claude Code's with its subagents' logs), landed through
/// `vault.imports.hook_transcript` as step 3 lands them, over one `oneiron
/// mcp` as the selection's own credential, in its own mode, under the
/// consent `policy_ref` names. The bridge's stderr goes nowhere, as the
/// local import's does: a hand-over's output is not the host's.
///
/// Only the log of the event's own session `session` goes ([`host_log`]),
/// and only in calls the selection's carrier takes
/// ([`transcript::calls_within`]); over the owner's socket, a request longer
/// than one call goes in parts ([`land`]). A log too long even for that is
/// refused before any bridge starts, so no hand-over sends a call that could
/// never land.
///
/// An OAuth selection goes on its hand-over sign-in; with none standing,
/// the log is queued for the vault and nothing is sent. A log that does not
/// land whole (its send failed, or turns wait behind another import) is
/// queued too, for a later session end. Once a log lands whole, the logs of
/// the same host waiting for the vault go over the same bridge, oldest
/// first ([`land_waiting`]).
pub(in crate::commands::hook) fn hand_over_hosted(
    oneiron: &Path,
    vault: &HostedVault,
    host: HookHost,
    session: &str,
    log: &Path,
    policy_ref: String,
    deadline: Instant,
) -> anyhow::Result<()> {
    let carried = Carried::of(vault.auth_mode);
    let calls = carried.calls(&host_log(host, log, session)?)?;
    let oauth = vault.auth_mode == HostedAuthMode::OAuth;
    let on = if oauth {
        let Some(file) = StepUp::HandOver.held(vault) else {
            if hand_over_queue::enqueue(vault, host, session, log)? {
                note(&hand_over_queue::waiting_note(&vault.origin));
            }
            return Ok(());
        };
        HostedVault {
            credential_file: file,
            ..vault.clone()
        }
    } else {
        vault.clone()
    };
    // An entry an earlier hand-over of this session left: this one's
    // landing makes it needless, unless a later one queues it again.
    let seen = hand_over_queue::generation_of(&on, host, session);
    let waiting = hand_over_queue::queued(&on);
    let landed =
        Hosted::open(oneiron, &on, policy_ref, Stdio::null(), deadline).and_then(|mut remote| {
            let landed = land_log(&mut remote, &calls, carried);
            if matches!(landed, Ok(Landing::Whole)) {
                if let Some(seen) = &seen {
                    hand_over_queue::leave(&on, host, session, seen);
                }
                let others = waiting
                    .iter()
                    .filter(|queued| queued.host == host && queued.session != session);
                land_waiting(&mut remote, others, carried);
            }
            remote.bridge.close();
            landed
        });
    let why = match &landed {
        Ok(Landing::Whole) => None,
        Ok(Landing::Pending) => Some("some of its turns wait behind another import".to_owned()),
        Err(error) => Some(format!("{error:#}")),
    };
    if oauth
        && let Some(why) = why
        && hand_over_queue::enqueue(vault, host, session, log).unwrap_or(false)
    {
        note(&hand_over_queue::unlanded_note(&on.origin, &why));
    }
    landed.map(drop)
}

/// Says `text` on the hook's stderr, best effort.
fn note(text: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{text}");
}

/// How a log's calls landed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Landing {
    /// Every turn: nothing of it waits.
    Whole,
    /// With turns still pending behind another import: sending it again
    /// lands them.
    Pending,
}

/// What one call of a selection carries ([`transcript::carried_bytes`]), and
/// how long a request may grow in parts ([`transcript::staged_bytes`]).
#[derive(Clone, Copy)]
struct Carried {
    call: usize,
    staged: Option<usize>,
}

impl Carried {
    fn of(mode: HostedAuthMode) -> Self {
        Self {
            call: transcript::carried_bytes(mode),
            staged: transcript::staged_bytes(mode),
        }
    }

    /// The calls `logs` go in ([`transcript::calls_within`]).
    fn calls(self, logs: &SessionLogs) -> anyhow::Result<Vec<HookTranscriptImportRequest>> {
        transcript::calls_within(logs, self.call, self.staged)
    }
}

/// Lands one session's log through `remote` in `calls`, in order
/// ([`land`]); the first refused call stops the rest. Answers whether any
/// conversation of it still has turns pending.
fn land_log(
    remote: &mut Hosted<'_>,
    calls: &[HookTranscriptImportRequest],
    carried: Carried,
) -> anyhow::Result<Landing> {
    let mut landing = Landing::Whole;
    for call in calls {
        let view = land(remote, call, carried.call)?;
        if view
            .conversations
            .iter()
            .any(|conversation| conversation.pending > 0)
        {
            landing = Landing::Pending;
        }
    }
    Ok(landing)
}

/// Lands each log of `waiting` through `remote`, oldest first. Each is read
/// first, through [`host_log`], and only then is its session's binding
/// checked, so turns a later start appends for another vault are never in
/// what goes. A log that lands whole, whose log is gone or refused here,
/// whose session no hosted vault may take (mixed, local or not recorded),
/// or that the vault refuses (the session's own log just landed on the same
/// sign-in, so a refusal is this log's own) leaves the queue. One bound to
/// another vault alone, or with turns still pending, waits on; the first
/// whose send failed any other way (no answer, the deadline, the bridge)
/// stops the rest, which wait on.
fn land_waiting<'q>(
    remote: &mut Hosted<'_>,
    waiting: impl Iterator<Item = &'q hand_over_queue::Queued>,
    carried: Carried,
) {
    for queued in waiting {
        let vault = remote.vault;
        let leave = || {
            hand_over_queue::leave(vault, queued.host, &queued.session, queued.generation());
        };
        let unsent = |why: &str| {
            note(&format!(
                "{} session {}'s log waited for {} and leaves the queue unsent: {why}",
                queued.host.product_name(),
                queued.session,
                vault.origin
            ));
        };
        let calls = match host_log(queued.host, &queued.log, &queued.session)
            .and_then(|logs| carried.calls(&logs))
        {
            Ok(calls) => calls,
            Err(error) => {
                unsent(&format!("{error:#}"));
                leave();
                continue;
            }
        };
        match session_binding::bound(queued.host, &queued.session) {
            Some(SessionBinding::Hosted(bound)) if bound.names(vault) => {}
            Some(SessionBinding::Hosted(_)) => continue,
            Some(SessionBinding::Mixed | SessionBinding::Local) | None => {
                unsent("its session is not bound to this vault alone");
                leave();
                continue;
            }
        }
        match land_log(remote, &calls, carried) {
            Ok(Landing::Whole) => leave(),
            Ok(Landing::Pending) => {}
            Err(error) if refused_by_vault(&error) => {
                unsent(&format!("{error:#}"));
                leave();
            }
            Err(_) => break,
        }
    }
}

/// Whether the vault answered `error`'s call with a refusal of it: a
/// JSON-RPC error that is not one of the unanswered kinds, or a tool
/// result that is an error. A call that got no answer, timed out or never
/// reached the bridge is not one.
fn refused_by_vault(error: &anyhow::Error) -> bool {
    error.downcast_ref::<CallUnconfirmed>().is_none()
        && (error.downcast_ref::<RpcRefusal>().is_some()
            || error.downcast_ref::<ToolRefused>().is_some())
}

/// Why a hand-over's calls are made, as their consent names it.
const PURPOSE: &str = "land this session's log in the selected vault";

/// Lands `request` over `remote`: in one `vault.imports.hook_transcript`
/// call when its spec fits `carried` bytes, else in
/// `vault.imports.hook_transcript_part` calls ([`transcript::parts`]), the
/// last of which lands it. Answers what the import landed.
fn land(
    remote: &mut Hosted<'_>,
    request: &HookTranscriptImportRequest,
    carried: usize,
) -> anyhow::Result<HookTranscriptImportView> {
    if serde_json::to_vec(request)?.len() <= carried {
        return remote.call("vault.imports.hook_transcript", request, PURPOSE);
    }
    let mut imported = None;
    for part in transcript::parts(request, carried)? {
        let view: HookTranscriptPartView =
            remote.call("vault.imports.hook_transcript_part", &part, PURPOSE)?;
        imported = view.imported;
    }
    imported.ok_or_else(|| {
        anyhow::anyhow!("the hosted vault took the session's log in parts but did not land it")
    })
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
/// rollout of `session`: `<time>` in Codex's shape ([`ROLLOUT_TIME`]) and
/// the rest of the name the session id whole, so the rollout of a session
/// whose id only ends in this one's is never taken for it (REVIEW-9914).
fn rollout_stem(path: &Path, session: &str) -> Option<String> {
    let stem = path.file_name()?.to_str()?.strip_suffix(".jsonl")?;
    let rest = stem.strip_prefix("rollout-")?;
    let timed = rest
        .get(..ROLLOUT_TIME.len())?
        .bytes()
        .zip(ROLLOUT_TIME.bytes())
        .all(|(byte, shape)| {
            if shape == b'0' {
                byte.is_ascii_digit()
            } else {
                byte == shape
            }
        });
    let id = rest.get(ROLLOUT_TIME.len()..)?.strip_prefix('-')?;
    (timed && id == session).then(|| stem.to_owned())
}

/// The time in a rollout's name, as Codex writes it,
/// `[year]-[month]-[day]T[hour]-[minute]-[second]`: each `0` a digit.
const ROLLOUT_TIME: &str = "0000-00-00T00-00-00";

/// `session`, when `path` is named `<session>.jsonl`.
fn own_stem(path: &Path, session: &str) -> Option<String> {
    (path.file_name() == Some(OsStr::new(&format!("{session}.jsonl")))).then(|| session.to_owned())
}

/// Codex's folder of rollouts: `sessions` in `$CODEX_HOME` as Codex
/// resolves it, absolute with every link resolved, so a relative or linked
/// `CODEX_HOME` names the folder its rollouts' paths are in (REVIEW-9914);
/// else in `~/.codex`, which Codex takes as it is.
fn codex_sessions() -> anyhow::Result<PathBuf> {
    let codex = match std::env::var_os("CODEX_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => std::fs::canonicalize(&dir).map_err(|error| {
            anyhow::anyhow!("CODEX_HOME {}: {error}", Path::new(&dir).display())
        })?,
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
