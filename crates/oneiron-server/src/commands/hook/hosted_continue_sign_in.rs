//! The continue sign-in of an OAuth selection: the step-up `oneiron continue
//! --cloud` runs on (lead rulings CONTINUE-PUSH-GIT-TIER = C, Sat 21 Nov
//! 05:4x, and CONTINUE-STEP-UP-MCP-WRITE = A, 06:1x).
//!
//! `oneiron hosted login` signs in for recall alone, `read` at the vault's
//! `/mcp`, so a sign-in that only recalls never asks for write, and the
//! recall hook never holds more. Moving a session writes: its log lands
//! (`vault.imports.hook_transcript`), its code is pushed through the git
//! door (every receive-pack needs `core:write`), and its run starts
//! (`vault.runners.continue`). So `continue --cloud` runs on a sign-in of
//! its own, `full` at `/mcp` and `/git` in one sign-in, which no other
//! command reads; when none stands it starts the step-up itself
//! ([`continuing`]), and `oneiron hosted login --push` is the explicit form
//! ([`step_up`]). Its calls still need the owner's Grants naming each verb,
//! and a push his per-repo `git_push` Grant, as a paired slip's do.
//!
//! The step-up is the recall sign-in's own flow, as the client the recall
//! sign-in registered, so the owner's ask names the agent he already
//! admitted and says it asks to continue this session in his hosted vault.
//! It is kept in a file of its own beside the recall sign-in
//! ([`hosted_selection::oauth_continue_sign_in_file`]); a logout of the
//! vault signs it out too ([`sign_out`]).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::hosted_selection::{self, HostedAuthMode, HostedVault};
use super::hosted_sign_in::{self, CONTINUE_SCOPE, SignInAsk};
use crate::commands::oauth_sign_in::{OAuthSession, OAuthSignIn};

/// The longest `continue --cloud` waits for the owner to allow its step-up,
/// as `hosted login` waits by default.
const STEP_UP_TIMEOUT: Duration = Duration::from_secs(600);

/// A session on the sign-in in `file`, for requests to `door` under
/// `origin`, refreshed on the command's runtime when due.
fn session(file: &Path, origin: &str, door: &str) -> anyhow::Result<OAuthSession> {
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| anyhow::anyhow!("continue signs in on the command's runtime"))?;
    OAuthSession::open(
        file,
        &reqwest::Url::parse(&format!("{origin}{door}"))?,
        runtime,
    )
}

/// The continue sign-in that stands for `vault`: the file of its step-up,
/// when it reads, holds the `full` tier and yields a bearer (refreshed when
/// due). `None` when there is none, or it no longer refreshes.
fn standing(vault: &HostedVault) -> Option<PathBuf> {
    let file = hosted_selection::oauth_continue_sign_in_file(&vault.origin)?;
    let held = OAuthSignIn::read(&file).ok()?;
    (held.scope == CONTINUE_SCOPE
        && session(&file, &vault.origin, "/mcp").is_ok_and(|open| open.bearer().is_ok()))
    .then_some(file)
}

/// Runs the step-up for the OAuth selection `vault`, waiting up to
/// `timeout` for the owner's answer, and keeps the sign-in it makes in the
/// vault's continue sign-in file in place of any earlier one, which is
/// revoked. Refused for a selection signed in another way, and when the
/// owner allowed a tier below `full`: that sign-in is signed out again and
/// nothing is kept.
pub(super) fn step_up(vault: &HostedVault, timeout: Duration) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        vault.auth_mode == HostedAuthMode::OAuth,
        "the continue step-up is an OAuth sign-in's, and {} is signed in another way",
        vault.origin
    );
    let recall = OAuthSignIn::read(&vault.credential_file)?;
    let file = hosted_selection::oauth_continue_sign_in_file(&vault.origin)
        .ok_or_else(|| anyhow::anyhow!("there is no per-user oneiron folder (HOME is not set)"))?;
    hosted_selection::create_user_dir_for(&file)?;
    let staged = hosted_sign_in::staged_file(&file);
    hosted_sign_in::sign_in(
        &vault.origin,
        &staged,
        timeout,
        SignInAsk::Continue {
            client_id: &recall.client_id,
        },
    )?;
    let made = OAuthSignIn::read(&staged)?;
    if made.scope != CONTINUE_SCOPE {
        let _ = hosted_sign_in::sign_out(&staged);
        anyhow::bail!(
            "the owner allowed the continue sign-in at the `{}` tier, and moving a session \
             needs `{CONTINUE_SCOPE}`; it was signed out again",
            made.scope
        );
    }
    hosted_sign_in::take_place(&staged, &file)?;
    Ok(file)
}

/// `vault` as `continue --cloud` reaches it: an OAuth selection on its
/// continue sign-in, the one that stands or, when none does, the one the
/// step-up makes now, which the owner allows before `deadline` (and within
/// [`STEP_UP_TIMEOUT`]); a slip or owner selection as it is. Runs on the
/// blocking pool of the command's runtime.
pub(super) fn continuing(vault: &HostedVault, deadline: Instant) -> anyhow::Result<HostedVault> {
    if vault.auth_mode != HostedAuthMode::OAuth {
        return Ok(vault.clone());
    }
    let file = match standing(vault) {
        Some(file) => file,
        None => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "No continue sign-in stands for {}: `oneiron hosted login` signs in to recall, \
                 and moving this session writes to the vault. Asking the owner now.",
                vault.origin
            );
            let timeout = STEP_UP_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
            step_up(vault, timeout)?
        }
    };
    Ok(HostedVault {
        credential_file: file,
        ..vault.clone()
    })
}

/// The session the push of the OAuth selection `vault` (on its continue
/// sign-in, [`continuing`]) goes with to the vault's git door.
pub(super) fn push_session(vault: &HostedVault) -> anyhow::Result<OAuthSession> {
    session(&vault.credential_file, &vault.origin, "/git")
}

/// What a push refused while it went on the continue sign-in of `origin`
/// to the custody repo `repo` says the person can do.
pub(super) fn refused_push_steps(origin: &str, repo: &str) -> String {
    format!(
        "the push went on this machine's continue sign-in to {origin}. A 401 means it no longer \
         stands: `oneiron hosted login --origin {origin} --push` signs in again. A 403 \
         git_push_capability_required means the owner has not granted the `oneiron hosted \
         login` agent git_push on `{repo}`"
    )
}

/// Signs out the continue sign-in kept for `origin`, if there is one:
/// revoked at the vault, best effort, and its file removed.
pub(super) fn sign_out(origin: &str) -> anyhow::Result<()> {
    match hosted_selection::oauth_continue_sign_in_file(origin) {
        Some(file) if std::fs::symlink_metadata(&file).is_ok() => hosted_sign_in::sign_out(&file),
        _ => Ok(()),
    }
}
