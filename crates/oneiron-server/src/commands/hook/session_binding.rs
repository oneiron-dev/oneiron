//! What a session's starts bound, recorded by each `session-start` for the
//! session's hand-over (REVIEW-9834). A hand-over sends a session's log to a
//! hosted vault only when every start of that session bound that one vault
//! and it is still the one selected; it never finds a destination of its
//! own.
//!
//! Each session has a folder, `<run folder>/<host's folder>/<session id>/`,
//! where the host's folder is `hook-sessions` for Claude Code, as before,
//! and `hook-sessions-<host>` for each other host ([`folder`]), so two hosts'
//! sessions of one id never share a record. It holds one file per distinct
//! binding the session's starts made:
//! - `local`: a pin, a local vault or no vault, whose log the local queue
//!   takes, as before;
//! - `hosted-<16 hex digits>`: a hosted vault, the file naming its origin
//!   and vault id, never its credential;
//! - `unknown`: a start that goes on from earlier turns whose vault is not
//!   known, or not one: a resumed or compacted session's start that found no
//!   record of the session, or a fork's ([`EarlierTurns::CopiedFrom`]) of a
//!   session that recorded nothing, more than one binding, a `local` one, or
//!   another binding than the fork's start made; and a start that adds
//!   another binding beside a `local` record, before its own file
//!   ([`beside_local_record`]).
//!
//! A fork's log begins with a copy of the turns of the session it was forked
//! from, so the first start that records the fork writes one file for its
//! whole log: that session's one hosted vault when the start bound the
//! same, else `unknown`. One file, so a write that fails never leaves the
//! copied turns' binding recorded alone. A `local` record names no vault,
//! and the parent's local vault may not be the fork's, so a fork of a
//! session that bound one is `unknown` too (REVIEW-9973 round 2).
//!
//! A log holds every turn of its session, so a session whose folder holds
//! more than one file has a log that mixes vaults: no hand-over sends it
//! anywhere, and selecting a vault again never undoes that. The person moves
//! it (`oneiron continue --cloud --transcript <log>`). A session with no
//! folder (its start ran before this record, or could write none) queues
//! locally, as every hand-over did before.
//!
//! The board mark and shown recall keys live beside the bindings but are
//! not binding records: they expire with the folder they sit in
//! (REVIEW-10587 P1 4).
//!
//! Binding records are only added. Each is written under a staging name no
//! other writer uses and renamed into place, so starts of one session running at
//! once never replace or remove each other's file, and a writer that fails
//! removes only its own staging file. A file anyone else could write is
//! never read. No record other than `local` is ever removed, so a session
//! that bound a hosted vault, or more than one vault, hands over by its
//! whole record however long it waited (REVIEW-9914). The folders of
//! sessions whose every file is a `local` record, a staging file or hook
//! state, all older than [`KEEP_FOR`], are removed when another session
//! records: such a session queues locally with its record or without it.
//! That removal may list a folder just before a start of its session adds a
//! file, and remove the `local` record after, so a start adding another
//! binding beside a `local` record first records `unknown`, which is never
//! removed: the log stays mixed when the `local` record goes (FIX
//! HOOK-SESSION-LOCAL-RECORD-EXPIRY-RACE).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron_contracts::fingerprint::ContentHash;
use serde::{Deserialize, Serialize};

use super::hosted_selection::HostedVault;
use crate::cli::HookHost;
use crate::commands::{credential_file, local_servers};
/// The file of a session that bound a pin, a local vault or no vault.
const LOCAL: &str = "local";
/// The file of a session whose earlier turns' vault is not known.
const UNKNOWN: &str = "unknown";
pub(super) const BOARD_KEYFRAME: &str = "board-keyframe";
pub(super) const CARRIER_LINES: &str = "carrier-lines";
/// The start of a hosted vault's file name.
const HOSTED_PREFIX: &str = "hosted-";
/// The longest hosted vault file read; one is a few hundred bytes.
const MAX_RECORD_BYTES: u64 = 4 * 1024;
/// The longest session id a folder is named by.
const MAX_SESSION_ID_BYTES: usize = 128;
/// How long a session's `local` records are kept after the newest was
/// written.
const KEEP_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// A hosted vault a session bound: its origin and vault id.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct HostedBinding {
    origin: String,
    vault_id: String,
}

impl HostedBinding {
    fn of(vault: &HostedVault) -> Self {
        Self {
            origin: vault.origin.clone(),
            vault_id: vault.vault_id.clone(),
        }
    }

    /// Whether `vault` is the hosted vault the session bound.
    pub(super) fn names(&self, vault: &HostedVault) -> bool {
        self.origin == vault.origin && self.vault_id == vault.vault_id
    }

    /// The file it is recorded in: `hosted-` and the first 16 hex digits of
    /// the content hash of its origin, a NUL and its vault id.
    fn file_name(&self) -> String {
        let named = [
            self.origin.as_bytes(),
            &[0_u8][..],
            self.vault_id.as_bytes(),
        ]
        .concat();
        let digest = ContentHash::of(&named).to_hex();
        format!("{HOSTED_PREFIX}{}", &digest[..16])
    }
}

/// The turns a session's start goes on from, which its log holds before the
/// start's own.
pub(super) enum EarlierTurns {
    /// None: a new session.
    None,
    /// The session's own (a resume or a compaction), or turns the start
    /// cannot tell the session of: the vault an earlier start of the session
    /// recorded, if any did.
    Own,
    /// A copy of the turns of the session named (a Codex fork): the vault
    /// that session's starts recorded.
    CopiedFrom(String),
}

/// What the starts of a session bound, as its hand-over reads it.
pub(super) enum SessionBinding {
    /// A pin, a local vault or no vault, at every start: the local queue's.
    Local,
    /// One hosted vault, at every start.
    Hosted(HostedBinding),
    /// More than one, or turns whose vault is not known: no vault takes the
    /// log.
    Mixed,
}

impl SessionBinding {
    /// What one start bound: the hosted vault `hosted`, or, with `None`, a
    /// pin, a local vault or no vault.
    fn of(hosted: Option<&HostedVault>) -> Self {
        hosted.map_or(Self::Local, |vault| Self::Hosted(HostedBinding::of(vault)))
    }
}

/// The folder in the run folder `host`'s sessions' folders are in. Hermes
/// asks only `bind`, and a hand-over under its name reads a Claude Code
/// log, so its sessions are Claude Code's.
const fn folder(host: HookHost) -> &'static str {
    match host {
        HookHost::ClaudeCode | HookHost::Hermes => "hook-sessions",
        HookHost::Codex => "hook-sessions-codex",
        HookHost::Cursor => "hook-sessions-cursor",
        HookHost::Copilot => "hook-sessions-copilot",
    }
}

/// Records that a start of `host`'s session `session` bound the hosted
/// vault `hosted`, or, with `None`, a pin, a local vault or no vault.
/// `earlier` names the turns the start goes on from, when no earlier start
/// of the session recorded anything: a fork's first start records one
/// binding for its whole log ([`fork_binding`]); another start that goes on
/// from turns records first that their vault is not known, as does a start
/// that adds another binding beside a `local` record
/// ([`beside_local_record`]), and either records nothing more when it
/// cannot record that.
pub(super) fn record(
    host: HookHost,
    session: &str,
    hosted: Option<&HostedVault>,
    earlier: &EarlierTurns,
) {
    let Some(folder) = session_folder(host, session) else {
        return;
    };
    let records = records(&folder);
    let first = !matches!(earlier, EarlierTurns::None) && records.is_empty();
    let start = SessionBinding::of(hosted);
    let _ = match earlier {
        EarlierTurns::CopiedFrom(parent) if first => {
            add_binding(&folder, &fork_binding(host, parent, start))
        }
        _ if first || beside_local_record(&records, &start) => {
            add(&folder, UNKNOWN, b"").and_then(|()| add_binding(&folder, &start))
        }
        _ => add_binding(&folder, &start),
    };
    remove_old(&folder);
}

/// Whether a start that bound `start` adds a file beside a `local` record
/// in a folder whose records are `records`, none of them `unknown`. Such a
/// start records `unknown` first: an old `local` record is removed
/// ([`remove_old`]), maybe after this start read the folder, and the
/// start's own file must never name alone a log whose earlier turns that
/// record named.
fn beside_local_record(records: &[OsString], start: &SessionBinding) -> bool {
    let holds = |name: &str| records.iter().any(|record| record == name);
    !matches!(start, SessionBinding::Local) && holds(LOCAL) && !holds(UNKNOWN)
}

/// The one binding the first start of a fork of `host`'s session `parent`
/// records for the fork's whole log, the start having bound `start`: the
/// hosted vault `parent`'s starts recorded when it is `start`'s, else a
/// mixed log, which no vault takes. Two `local` records may name two local
/// vaults, so they never agree.
fn fork_binding(host: HookHost, parent: &str, start: SessionBinding) -> SessionBinding {
    if let (Some(SessionBinding::Hosted(copied)), SessionBinding::Hosted(own)) =
        (bound(host, parent), start)
        && copied == own
    {
        return SessionBinding::Hosted(own);
    }
    SessionBinding::Mixed
}

/// What the starts of `host`'s session `session` bound; `None` when none
/// recorded anything. A file that anyone else could write, or that this
/// version does not read, reads as a mixed log, which no vault takes.
pub(super) fn bound(host: HookHost, session: &str) -> Option<SessionBinding> {
    let folder = session_folder(host, session)?;
    let mut files = fs::read_dir(&folder)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| binding_record(name));
    let first = files.next()?;
    if files.next().is_some() {
        return Some(SessionBinding::Mixed);
    }
    let Some(file) = local_servers::open_own(&folder.join(&first)) else {
        return Some(SessionBinding::Mixed);
    };
    let binding = match first.to_str() {
        Some(LOCAL) => SessionBinding::Local,
        Some(name) if name.starts_with(HOSTED_PREFIX) => {
            let mut body = Vec::new();
            let read = file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut body);
            match serde_json::from_slice::<HostedBinding>(&body) {
                Ok(hosted)
                    if read.is_ok()
                        && body.len() as u64 <= MAX_RECORD_BYTES
                        && hosted.file_name() == name =>
                {
                    SessionBinding::Hosted(hosted)
                }
                _ => SessionBinding::Mixed,
            }
        }
        _ => SessionBinding::Mixed,
    };
    Some(binding)
}

/// The folder of `host`'s session `session`, when its id is a plain name:
/// ASCII letters, digits, dashes and underscores, as hosts name sessions, so
/// it names no folder outside the run folder's.
pub(super) fn session_folder(host: HookHost, session: &str) -> Option<PathBuf> {
    let plain = !session.is_empty()
        && session.len() <= MAX_SESSION_ID_BYTES
        && session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !plain {
        return None;
    }
    Some(local_servers::run_dir()?.join(folder(host)).join(session))
}

/// The names of the records the starts of the session whose folder is
/// `folder` made: every file but staging files and the board and recall
/// hook state; none when there is no folder.
fn records(folder: &Path) -> Vec<OsString> {
    let Ok(entries) = fs::read_dir(folder) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| binding_record(name))
        .collect()
}

fn binding_record(name: &OsStr) -> bool {
    !staging(name) && name != OsStr::new(BOARD_KEYFRAME) && name != OsStr::new(CARRIER_LINES)
}

/// Whether `name` is a writer's staging file, not yet a record.
fn staging(name: &OsStr) -> bool {
    name.as_encoded_bytes().starts_with(b".")
}

/// Adds the file `name` holding `body` to the session folder `folder`, 0600
/// in 0700 folders in the run folder: written under a staging name of this
/// writer's alone, then renamed into place, where a file of that name is
/// replaced by the same bytes. A writer that fails removes its staging file
/// alone.
pub(super) fn add(folder: &Path, name: &str, body: &[u8]) -> anyhow::Result<()> {
    ensure_session_folder(folder)?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staged = folder.join(format!(".{name}.{}.{nanos}.tmp", std::process::id()));
    let written = credential_file::create(&staged)
        .and_then(|mut file| Ok(file.write_all(body)?))
        .and_then(|()| Ok(fs::rename(&staged, folder.join(name))?));
    if let Err(error) = written {
        let _ = fs::remove_file(&staged);
        anyhow::bail!("write {}: {error}", folder.join(name).display());
    }
    Ok(())
}

pub(super) fn ensure_session_folder(folder: &Path) -> anyhow::Result<()> {
    local_servers::ensure_run_dir()?;
    let sessions = folder
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} is in no folder", folder.display()))?;
    for dir in [sessions, folder] {
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => anyhow::bail!("create {}: {error}", dir.display()),
        }
    }
    Ok(())
}

/// Adds the file that records `binding` to the session folder `folder`: a
/// mixed log is recorded as `unknown`, which no vault takes either.
fn add_binding(folder: &Path, binding: &SessionBinding) -> anyhow::Result<()> {
    match binding {
        SessionBinding::Local => add(folder, LOCAL, b""),
        SessionBinding::Hosted(hosted) => add_hosted(folder, hosted),
        SessionBinding::Mixed => add(folder, UNKNOWN, b""),
    }
}

/// Adds the file of the hosted vault `binding` names to the session folder
/// `folder`.
fn add_hosted(folder: &Path, binding: &HostedBinding) -> anyhow::Result<()> {
    let body = serde_json::to_vec(binding)?;
    add(folder, &binding.file_name(), &body)
}

/// Removes the folders of sessions other than the one at `own` whose files
/// are all `local` records, staging files or hook state ([`BOARD_KEYFRAME`],
/// [`CARRIER_LINES`]), written more than [`KEEP_FOR`] ago. A folder holding any other record stays: removing it, or any part
/// of it, could leave a session that may still hand over with no record, or
/// with one of the vaults it bound alone (REVIEW-9914). A start that adds a
/// file after this listed the folder recorded `unknown` first
/// ([`beside_local_record`]), so removing the listed `local` records leaves
/// a mixed log.
fn remove_old(own: &Path) {
    let Some(sessions) = own.parent() else {
        return;
    };
    let Some(cutoff) = SystemTime::now().checked_sub(KEEP_FOR) else {
        return;
    };
    let Ok(entries) = fs::read_dir(sessions) else {
        return;
    };
    let old = |path: &Path| {
        fs::symlink_metadata(path)
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|modified| modified < cutoff)
    };
    let held = |path: &Path| {
        path.file_name()
            .is_some_and(|name| binding_record(name) && name != OsStr::new(LOCAL))
    };
    for entry in entries.filter_map(Result::ok) {
        let folder = entry.path();
        if folder == own || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Ok(files) = fs::read_dir(&folder) else {
            continue;
        };
        let files: Vec<PathBuf> = files
            .filter_map(Result::ok)
            .map(|file| file.path())
            .collect();
        if files.iter().all(|file| old(file) && !held(file)) {
            for file in &files {
                let _ = fs::remove_file(file);
            }
            let _ = fs::remove_dir(&folder);
        }
    }
}
