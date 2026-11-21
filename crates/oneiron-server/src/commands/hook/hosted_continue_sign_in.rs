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
//! ([`StepUp::Continue`]). Its calls still need the owner's Grants naming each verb,
//! and a push his per-repo `git_push` Grant, as a paired slip's do.
//!
//! The step-up is the recall sign-in's own flow, as the client the recall
//! sign-in registered, so the owner's ask names the agent he already
//! admitted and says it asks to continue this session in his hosted vault.
//! It is kept in a file of its own beside the recall sign-in
//! ([`super::hosted_selection::oauth_continue_sign_in_file`]); a logout of the
//! vault signs it out too ([`StepUp::sign_out`]), and so does a new `hosted
//! login`, which registers another client ([`StepUp::sign_out_replaced_client`]).

use std::io::Write as _;
use std::time::{Duration, Instant};

use super::hosted_selection::{HostedAuthMode, HostedVault};
use super::hosted_sign_in::{self, CodeDelivery, StepUp};
use crate::commands::oauth_sign_in::OAuthSession;

/// The longest `continue --cloud` waits for the owner to allow its step-up,
/// as `hosted login` waits by default.
const STEP_UP_TIMEOUT: Duration = Duration::from_secs(600);

/// `vault` as `continue --cloud` reaches it: an OAuth selection on its
/// continue sign-in, the one that stands or, when none does, the one the
/// step-up makes now, which the owner allows before `deadline` (and within
/// [`STEP_UP_TIMEOUT`]); a slip or owner selection as it is. Runs on the
/// blocking pool of the command's runtime.
pub(super) fn continuing(vault: &HostedVault, deadline: Instant) -> anyhow::Result<HostedVault> {
    if vault.auth_mode != HostedAuthMode::OAuth {
        return Ok(vault.clone());
    }
    let file = match StepUp::Continue.standing(vault) {
        Some(file) => file,
        None => {
            let _ = writeln!(
                std::io::stderr().lock(),
                "No continue sign-in stands for {}: `oneiron hosted login` signs in to recall, \
                 and moving this session writes to the vault. Asking the owner now.",
                vault.origin
            );
            let timeout = STEP_UP_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
            StepUp::Continue.run(vault, timeout, CodeDelivery::Browser)?
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
    hosted_sign_in::session(&vault.credential_file, &vault.origin, "/git")
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
