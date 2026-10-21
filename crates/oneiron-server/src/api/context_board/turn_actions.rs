//! The context board a queued Continue or Retry reads (FIX 6920), as a live
//! chat turn reads its own ([`super::chat_board`]): hydrated once, for the
//! user turn the reply answers, under the authority its requester asked
//! with. That is the invocation slip the action keeps, verified again now
//! and projected as the request's own credential was; nothing else stands
//! in for it. Reading it never fails the action: a slip that no longer
//! verifies, a credential that is not the requester's or reads nothing, a
//! refused assembly, an empty frame or a hold leaves the action as it always
//! ran, logged without content. A native action, asked in-process with no
//! slip, reads none.
use std::sync::Arc;

use oneiron::claim::CallerLocality;
use oneiron::conversation::TurnActionAttempt;
use oneiron::{EntityId, ModelLocality};

use crate::auth::{CoreAuth, CoreScope};
use crate::server::{SyncServer, blocking};

/// The call's route is fixed only at admission, after the hold: judge the widest, as chat does.
const BOARD_MODEL_LOCALITY: ModelLocality = ModelLocality::ThirdParty;

/// The board `action`'s reply reads for `query`, the user turn it answers,
/// with `agent`, the answering agent's definition, shaping its recall. It
/// is read as an off-device read is, and its rows meet the hold of a prompt
/// that leaves the device. `None` when the action reads none.
pub(crate) async fn action_board(
    server: &Arc<SyncServer>,
    action: &TurnActionAttempt,
    agent: EntityId,
    query: &str,
) -> Option<String> {
    let auth = blocking(|| requester_auth(server, action))?.at(CallerLocality::OffDevice);
    let prompt_for =
        crate::device_local::prompt_destination(auth.destination(), BOARD_MODEL_LOCALITY);
    let board = match super::chat_board(server, auth, Some(action.conversation), agent, query).await
    {
        Ok(board) if !board.block.trim().is_empty() => board,
        Ok(_) => return None,
        Err(status) => {
            tracing::info!(
                %status,
                "a turn action's context board was refused; the action runs without it"
            );
            return None;
        }
    };
    match crate::device_local::retained_hold(
        server.vault(),
        &prompt_for,
        &board.rows,
        board.block.as_bytes(),
    ) {
        Ok(None) => Some(board.block),
        Ok(Some(hold)) => {
            tracing::info!(
                reason = hold.reason(),
                "a turn action's context board is kept on this device; the action runs without it"
            );
            None
        }
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a turn action's context board hold was not read; the action runs without it"
            );
            None
        }
    }
}

/// The credential `action`'s request was admitted on, as it stands now: the
/// kept slip verified again in a snapshot of its own, then projected with
/// the fingerprint of the exact token the request presented, at no invitee
/// door. It must still name the requester at its class and grant a read.
/// `None`, logged, for a native action or one whose slip no longer does.
fn requester_auth(server: &SyncServer, action: &TurnActionAttempt) -> Option<CoreAuth> {
    let (Some(binding), false) = (&action.invocation_slip, action.native) else {
        tracing::debug!("a native turn action reads no context board; it runs as it always did");
        return None;
    };
    let (actor, class) = action.requester().ok()?;
    let vault = server.vault();
    let verified = match vault.verify_invocation_slip(binding) {
        Ok(verified) => verified,
        Err(error) => {
            tracing::info!(
                kind = ?error.kind(),
                "a turn action's slip did not verify for its context board; the action runs without it"
            );
            return None;
        }
    };
    // The token's own codec is canonical, so it is the exact token the
    // request presented, fingerprinted as its admission fingerprinted it.
    let Ok(token) = binding.credential_token() else {
        tracing::info!(
            "a turn action's slip has no token; the action runs without a context board"
        );
        return None;
    };
    let instrument = *blake3::hash(token.as_bytes()).as_bytes();
    let Ok(auth) =
        CoreAuth::from_kept_slip(verified, binding.clone(), instrument, None, vault.as_ref())
    else {
        tracing::info!(
            "a turn action's slip was not projected for its context board; the action runs without it"
        );
        return None;
    };
    if auth.principal_ref() != Some(actor.to_hex().as_str())
        || auth.actor_class() != Some(class.gate_actor_class())
        || auth.require(CoreScope::Read).is_err()
    {
        tracing::info!(
            "a turn action's slip does not read as its requester; the action runs without a context board"
        );
        return None;
    }
    Some(auth)
}
