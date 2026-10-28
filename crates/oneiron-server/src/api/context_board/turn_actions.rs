//! The context board a queued Continue or Retry reads (FIX 6920), as a live
//! chat turn reads its own ([`super::chat_board`]): hydrated once, for the
//! user turn the reply answers, under the authority its requester asked
//! with. That is the invocation slip the action keeps, verified again now
//! and projected as the request's own credential was; nothing else stands
//! in for it. Reading it never fails the action: a slip that no longer
//! verifies, a credential that is not the requester's or reads nothing, a
//! refused assembly, an empty frame or a hold leaves the action as it always
//! ran, logged without content. A native action, asked in-process with no
//! slip, reads none. A managed vault's attested owner's reads as the owner
//! the vault records as live now (FIX 11090).
use std::sync::Arc;

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::conversation::{TurnActionAttempt, TurnActionAuthority};
use oneiron::settings::ReadDestination;
use oneiron::{EntityId, ModelLocality};

use super::PromptBoard;
use crate::ai_host::AiHandle;
use crate::auth::{CoreAuth, CoreScope};
use crate::models::Seat;
use crate::server::{SyncServer, blocking};

/// The board `action`'s reply reads for `query`, the user turn it answers,
/// with `agent`, the answering agent's definition, shaping its recall, and
/// what its context records keep of it (FIX 7145). It is read on the device
/// only when the action's requester asked from the device and the chat
/// role's live route from `seat` stays on it (FIX 8997, as a live turn reads
/// its own); otherwise as an off-device read is. Its rows meet the hold of a
/// prompt that goes back to the requester and as far as the chat role's live
/// route from `seat`, on `ai`, may take the call (FIX 7257); the call that
/// carries it is judged again once admitted ([`PromptBoard::rides`]). `None`
/// when the action reads none.
pub(crate) async fn action_board(
    server: &Arc<SyncServer>,
    ai: &AiHandle,
    seat: &Seat,
    action: &TurnActionAttempt,
    agent: EntityId,
    query: &str,
) -> Option<PromptBoard> {
    let reads_at = if !action.off_device
        && PromptBoard::route_locality(ai, server.vault(), seat) == ModelLocality::OnDevice
    {
        CallerLocality::OnDevice
    } else {
        CallerLocality::OffDevice
    };
    let auth = blocking(|| requester_auth(server, action))?.at(reads_at);
    // The answer goes back to where its attempt recorded the requester
    // asking from, toward no machine anyone proved now; never where the
    // actor might be.
    let caller = ReadDestination::at(
        if action.off_device {
            CallerLocality::OffDevice
        } else {
            CallerLocality::OnDevice
        },
        PeerMachine::Unknown,
    );
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
    let board = PromptBoard::new(board, caller);
    board.rides_route(ai, server.vault(), seat).then_some(board)
}

/// The credential `action`'s request was admitted on, as it stands now: the
/// kept slip verified again in a snapshot of its own, then projected with
/// the fingerprint of the exact token the request presented, at no invitee
/// door. It must still name the requester at its class and grant a read.
/// An attested owner's is the owner the vault records as live now. `None`,
/// logged, for a native action or one whose credential no longer does.
fn requester_auth(server: &SyncServer, action: &TurnActionAttempt) -> Option<CoreAuth> {
    let binding = match &action.authority {
        TurnActionAuthority::Slip { binding } => binding,
        // The owner the vault records as live now, when he is the requester
        // as a human ([`CoreAuth::for_attested_owner`]).
        TurnActionAuthority::AttestedOwner { holder } => {
            let (actor, class) = action.requester().ok()?;
            let auth = (actor == *holder && class == oneiron::EdgeActorClass::Human)
                .then(|| CoreAuth::for_attested_owner(*holder, server).ok())
                .flatten();
            if auth.is_none() {
                tracing::info!(
                    "a turn action's owner does not stand for its context board; the action runs without it"
                );
            }
            return auth;
        }
        TurnActionAuthority::SlipErased => {
            tracing::info!(
                "a turn action's slip went with its requester's erase; the action runs without a context board"
            );
            return None;
        }
        TurnActionAuthority::Native => {
            tracing::debug!(
                "a native turn action reads no context board; it runs as it always did"
            );
            return None;
        }
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
