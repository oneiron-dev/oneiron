//! Run-tree cancel through the caller-bound cancel door (FIX 8219).
//!
//! A caller the route binds to a person cancels through
//! [`oneiron::memory::Memory::cancel_run_branch`]: the vault owner, the
//! TASK's owner, the run's own agent and its spawner stop the branch at
//! once; anyone else's cancel becomes a proposal and changes nothing. A
//! caller with no person behind it (a host-held slip, a host action that
//! cannot act as one, a credential that names no principal or an unknown
//! class) has no actor to own a proposal, and keeps today's immediate
//! cancel. The pause and resume host exception is not taken here.

use super::{
    CoreRunTreeInterventionEffect, CoreRunTreeInterventionKind, CoreRunTreeInterventionResponse,
    run_control_refusal,
};
use crate::api::hex_bytes;
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use oneiron::task_verb::run_cancel::RunCancelOutcome;
use oneiron::{EdgeActorClass, EntityId};

/// The person a cancel's caller acts as, as the pause and resume doors bind
/// it: the owner a host action acts as, else the credential's principal
/// under its class. `None` for a caller with no person behind it.
pub(super) fn bound_actor(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Option<(EntityId, EdgeActorClass)> {
    match crate::api::host_action::host_action_of(&server.vault, auth) {
        Some(Ok(action)) => {
            let actor = action.actor();
            Some((actor.entity_ref(), actor.actor_class()))
        }
        Some(Err(_)) => None,
        None if auth.is_host_holder() => None,
        None => {
            // A credential that declares no class is a person's, as the
            // pause and resume doors read it.
            let class = match auth.actor_class() {
                Some("human") | None => EdgeActorClass::Human,
                Some("agent") => EdgeActorClass::Agent,
                Some("system") => EdgeActorClass::System,
                Some(_) => return None,
            };
            auth.principal_entity().map(|actor| (actor, class))
        }
    }
}

/// Cancels `input`'s branch as `actor` through the engine's cancel door.
pub(super) fn core_run_cancel(
    server: &SyncServer,
    auth: &CoreAuth,
    (actor, class): (EntityId, EdgeActorClass),
    input: oneiron::InterveneAttempt,
) -> Result<RunCancelOutcome, EnvelopedApiError> {
    crate::api::credential_memory(&server.vault, Some(auth), actor, class)
        .at(auth.locality())
        .cancel_run_branch(input)
        .map_err(run_control_refusal)
}

/// The answer to a cancel that became a proposal: the branch it names, the
/// `proposed` effect and the claim, with no run id and no run-tree
/// snapshot.
pub(super) fn proposed(
    attempt_id: oneiron::attempt_queue::AttemptId,
    kind: CoreRunTreeInterventionKind,
    proposal_ref: EntityId,
) -> CoreRunTreeInterventionResponse {
    CoreRunTreeInterventionResponse {
        attempt_id: hex_bytes(attempt_id.as_bytes()),
        run_id: None,
        kind,
        effect: CoreRunTreeInterventionEffect::Proposed,
        proposal_ref: Some(proposal_ref.to_hex()),
        tree: None,
    }
}
