//! The hand-over sign-in request the hooks file themselves (row
//! HOOK-HOSTED-HAND-OVER-OAUTH-READ-TIER; the change in lead ruling B, Sat
//! 21 Nov 07:0x).
//!
//! At the first session end on an OAuth selection with no hand-over
//! sign-in, the hand-over queues the log ([`super::hand_over_queue`]) and
//! starts `oneiron hosted login --hand-over --unattended` itself
//! ([`start_if_due`]), detached from the hook, which waits for nothing. The
//! request lands in the owner's inbox as an ask worded "land this
//! machine's coding sessions in your hosted vault as each ends"; once he
//! allows it, the sign-in is kept, and the logs waiting land at the next
//! session end.
//!
//! One small file per vault beside the selection
//! ([`hosted_selection::hand_over_ask_file`]) records the ask, so session
//! ends do not ask again and again: none while a request waits, none after
//! a deny, and after a request that lapsed unanswered (the vault keeps one
//! for 10 minutes) at most one a day. `oneiron hosted login --hand-over`
//! stays the explicit form, and `hosted logout` forgets the record.
//!
//! Every read-and-write of the record runs under its lock, a file beside
//! it, so two session ends at once file one ask. Each ask is an attempt
//! with its own id; the command it starts records how it ended only while
//! the record still names that attempt, so a logout that forgot it is never
//! undone.

use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Stdio;

use serde::{Deserialize, Serialize};

use super::hosted_selection::{self, HostedVault};
use super::hosted_sign_in::SignInEnded;
use crate::commands::{credential_file, local_servers, oauth_sign_in};

/// How long after an ask, or its lapse, a session end may ask again.
const ASK_AGAIN_AFTER_MS: u64 = 24 * 60 * 60 * 1000;
/// An ask's record is a few dozen bytes; a larger file is not one.
const MAX_RECORD_BYTES: u64 = 4 * 1024;

/// Where the last ask stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AskState {
    /// Filed, its answer not yet in.
    Asked,
    /// The owner denied it: no session end asks again.
    Denied,
    /// It lapsed unanswered, or its command stopped short.
    Lapsed,
}

/// The ask record's file body.
#[derive(Serialize, Deserialize)]
struct AskRecord {
    state: AskState,
    /// When it reached that state, in ms since the Unix epoch.
    at_ms: u64,
    /// The ask's attempt: drawn when it was filed.
    #[serde(default)]
    attempt: String,
}

/// Whether a session end may ask at `now_ms` after `record`: never after a
/// deny; else when no ask was recorded, or the last one was filed or
/// lapsed [`ASK_AGAIN_AFTER_MS`] ago or more.
fn due(record: Option<&AskRecord>, now_ms: u64) -> bool {
    match record {
        None => true,
        Some(record) => {
            record.state != AskState::Denied
                && now_ms.saturating_sub(record.at_ms) >= ASK_AGAIN_AFTER_MS
        }
    }
}

/// Files the hand-over sign-in request for the OAuth selection `vault`
/// when an ask is due: records it first, then starts `oneiron hosted login
/// --hand-over --unattended` by `oneiron` in a process group of its own,
/// with no stdin, stdout or stderr, so it outlives the hook and holds none
/// of the host's pipes. Answers whether it started one.
pub(super) fn start_if_due(oneiron: &Path, vault: &HostedVault) -> bool {
    let Some(file) = hosted_selection::hand_over_ask_file(&vault.origin) else {
        return false;
    };
    let now = oauth_sign_in::now_ms();
    let attempt = format!("{now}-{}", std::process::id());
    {
        let Ok(_locked) = lock(&file) else {
            return false;
        };
        if !due(read(&file).as_ref(), now) || write(&file, AskState::Asked, now, &attempt).is_err()
        {
            return false;
        }
    }
    let mut command = oneiron_spawn::command(oneiron);
    command
        .args(["hosted", "login", "--origin", vault.origin.as_str()])
        .args([
            "--vault-id",
            vault.vault_id.as_str(),
            "--hand-over",
            "--unattended",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    match command.spawn() {
        Ok(mut child) => {
            // Reaped if it ends while the hook still runs; else it outlives
            // the hook.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            true
        }
        Err(_) => {
            let _ = std::fs::remove_file(&file);
            false
        }
    }
}

/// The attempt of the ask that waits for `origin`, if one does: what the
/// command it started reads before it files the request.
pub(super) fn waiting_attempt(origin: &str) -> Option<String> {
    let file = hosted_selection::hand_over_ask_file(origin)?;
    read(&file)
        .filter(|record| record.state == AskState::Asked)
        .map(|record| record.attempt)
}

/// Records how a hand-over sign-in for `origin` ended, under the record's
/// lock: one that stands now (`ended` is `None`) forgets the ask; a deny or
/// a lapse of the ask `attempt` is kept with its time, and only while the
/// record still names that attempt (a logout since forgot it).
pub(super) fn record_end(origin: &str, ended: Option<SignInEnded>, attempt: Option<&str>) {
    let Some(file) = hosted_selection::hand_over_ask_file(origin) else {
        return;
    };
    let Ok(_locked) = lock(&file) else {
        return;
    };
    let state = match ended {
        None => {
            let _ = forget_file(&file);
            return;
        }
        Some(SignInEnded::Denied) => AskState::Denied,
        Some(SignInEnded::Lapsed) => AskState::Lapsed,
    };
    if let Some(attempt) = attempt
        && read(&file).is_some_and(|record| record.attempt == attempt)
    {
        let _ = write(&file, state, oauth_sign_in::now_ms(), attempt);
    }
}

/// Forgets the ask recorded for `origin`, if there is one, under its lock.
pub(super) fn forget(origin: &str) -> anyhow::Result<()> {
    let Some(file) = hosted_selection::hand_over_ask_file(origin) else {
        return Ok(());
    };
    let _locked = lock(&file)?;
    forget_file(&file)
}

/// The record `file`'s lock, held until the answer drops: an exclusive
/// `flock` on `<file>.lock`.
fn lock(file: &Path) -> anyhow::Result<std::fs::File> {
    hosted_selection::create_user_dir_for(file)?;
    let mut name = file.as_os_str().to_owned();
    name.push(".lock");
    let path = std::path::PathBuf::from(name);
    let opened = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| anyhow::anyhow!("open {}: {error}", path.display()))?;
    rustix::fs::flock(&opened, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|error| anyhow::anyhow!("lock {}: {error}", path.display()))?;
    Ok(opened)
}

fn forget_file(file: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(file) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(anyhow::anyhow!("remove {}: {error}", file.display()))
        }
        _ => Ok(()),
    }
}

/// The record `file` holds, when it is a file only this user can write and
/// reads as one.
fn read(file: &Path) -> Option<AskRecord> {
    let opened = local_servers::open_own(file)?;
    let mut body = Vec::new();
    opened
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    if body.len() as u64 > MAX_RECORD_BYTES {
        return None;
    }
    serde_json::from_slice(&body).ok()
}

/// Writes `state` of the ask `attempt` at `at_ms` to `file`, owner-only and
/// in one rename, in the per-user folder.
fn write(file: &Path, state: AskState, at_ms: u64, attempt: &str) -> anyhow::Result<()> {
    hosted_selection::create_user_dir_for(file)?;
    let record = AskRecord {
        state,
        at_ms,
        attempt: attempt.to_owned(),
    };
    credential_file::replace(file, &serde_json::to_vec(&record)?)
}
