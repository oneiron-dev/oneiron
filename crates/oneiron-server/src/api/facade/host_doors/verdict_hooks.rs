//! `ai.verdict` through the host's decision ladder, and the owner's `vault.hooks.replay`.
//! `ai_verdict`, `vault_hooks_replay` and `vault_hooks_replay_as_owner` are its call surface.
//! The engine's `HookVerdict` (`oneiron::runtime_hooks`) and the sdk DTOs are forwarded here.

use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use oneiron::runtime_hooks::HookVerdict;
use oneiron::task_verb::sdk::{AiVerdict, AiVerdictRequest, HooksReplayPage, HooksReplayRequest};

use super::support::{
    Listed, MaybeListed, asking, credential_listing, internal, owner_proof, read_beside, refused,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `ai.verdict`: the caller's own typed question through the host's
/// decision ladder, asked for the caller: the slip's principal, or the
/// vault's own owner for an owner-grade credential that names none. Its
/// evidence is read under the caller's own scoped read
/// ([`crate::decision_verdict::run_verdict`]); a screenshot the calling
/// code run's browser holds comes from that browser. Beside it, the rows its
/// evidence reads listed and the asset an image it pulls is read from: the
/// image's lane is a scoped read of its own, which lists nothing itself.
pub(crate) async fn ai_verdict(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AiVerdictRequest,
) -> Listed<AiVerdict> {
    const VERB: &str = "ai.verdict";
    let caller = match asking(auth, server) {
        Ok(caller) => caller,
        Err(refusal) => return refused(refusal),
    };
    let held = crate::decision_verdict::HeldImage::in_task(input.image.as_deref());
    // A held screenshot is the run's browser's pixels, no row's.
    let beside = match (&input.image, &held) {
        (Some(handle), None) => read_beside([handle.as_str()]),
        _ => Vec::new(),
    };
    let (answer, mut listed) =
        credential_listing(server, auth, caller, VERB, move |server, auth, reader| {
            let mut evidence = Vec::new();
            // An image is pulled through the caller's own lane before any model
            // reads it, unless it is the run's own held screenshot.
            let lane = match (&input.image, &held) {
                (Some(_), None) => Some(
                    crate::api::scoped_read_for_core_auth(&server.vault, auth).map_err(|_| {
                        MemoryError::new(
                            MEMORY_CODE_FORBIDDEN,
                            "ai.verdict reads an image under the caller's scoped read",
                            &["Present a credential that can read the image."],
                        )
                    })?,
                ),
                _ => None,
            };
            let verdict = crate::decision_verdict::run_verdict(
                server,
                caller.0,
                caller.1,
                &reader,
                lane.as_ref(),
                held,
                &input,
                // A facade caller's verdict bills the vault owner.
                None,
                &mut evidence,
            );
            Ok((verdict, evidence))
        })
        .await;
    // The rows the evidence refs and image resolved to, short refs
    // included, refused verdict or not (FIX 5461).
    let answer = answer.and_then(|(verdict, evidence)| {
        listed.extend(evidence);
        verdict
    });
    listed.extend(beside);
    (answer, listed)
}

/// `vault.hooks.replay`: the owner replays a hook over past facts or its
/// saved verb runs, under the proof `/v1/owner` takes from the request, on
/// the hook sandbox serve runs its hooks on. A dry run: nothing lands. A fact
/// no run pinned previews a generative hook's verdicts on serve's own ladder.
/// Beside it, the binding, its body's source, each entry's fact and every
/// row a replayed read served ([`oneiron::Vault::hooks_replay_listing`]);
/// `None` once an entry heard a verdict whose evidence rows are not known.
pub(crate) async fn vault_hooks_replay(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HooksReplayRequest,
) -> MaybeListed<HooksReplayPage> {
    match vault_hooks_replay_answer(server, auth, input).await {
        Ok((replayed, rows)) => (Ok(replayed), rows),
        Err(refusal) => (Err(refusal), Some(Vec::new())),
    }
}

/// [`vault_hooks_replay`]'s answer, beside its listing.
pub(super) async fn vault_hooks_replay_answer(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HooksReplayRequest,
) -> MemoryResult<(HooksReplayPage, Option<Vec<EntityId>>)> {
    let owner = owner_proof(auth, server, "vault.hooks.replay")?;
    vault_hooks_replay_as_owner(server, owner, input).await
}

/// [`vault_hooks_replay`] under an owner proof the caller's own door made:
/// an owner's own program's, for the vault's live recorded owner (FIX 5911).
/// The engine checks the proof again, as for the request's.
pub(crate) async fn vault_hooks_replay_as_owner(
    server: &Arc<SyncServer>,
    owner: oneiron::consent::AuthenticatedOwner,
    input: HooksReplayRequest,
) -> MemoryResult<(HooksReplayPage, Option<Vec<EntityId>>)> {
    let verdict = replay_verdict(server);
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        // The sandbox serve's runner runs on, taken here when no runner took
        // it: `--no-hooks` stops the runner, not an explicit replay.
        let runtime = crate::commands::hook_sandbox(&server).map_err(no_hook_sandbox)?;
        oneiron::task_verb::sdk::replay_hooks_as_owner_listing(
            server.vault(),
            &owner,
            runtime.as_ref(),
            verdict,
            &input,
        )
    })
    .await
    .map_err(|_| internal("vault.hooks.replay"))?
}

/// An explicit replay's refusal when no hook sandbox loads: this build has
/// none, or it did not build (`reason`).
pub(in crate::api::facade) fn no_hook_sandbox(reason: String) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!("no hook sandbox runs on this server: {reason}"),
        &["Serve on a build with the code sandbox (code-sandbox-wasmtime)."],
    )
}

/// The verdict host a replay's preview asks: the one the fact-hook runner
/// asks.
#[cfg(feature = "code-sandbox-wasmtime")]
pub(super) fn replay_verdict(server: &Arc<SyncServer>) -> Option<Arc<dyn HookVerdict>> {
    Some(Arc::new(crate::hook_verdict::ServerHookVerdict::new(
        server,
    )))
}

/// No hook sandbox runs on this build, so no replay reaches a verdict.
#[cfg(not(feature = "code-sandbox-wasmtime"))]
pub(super) fn replay_verdict(_server: &Arc<SyncServer>) -> Option<Arc<dyn HookVerdict>> {
    None
}
