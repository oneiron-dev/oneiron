//! The positively bound Anonymous caller selects a session-owned claim first.

use super::*;
use oneiron::memory::SessionWitnessBinding;

pub(super) async fn claim(
    server: &SyncServer,
    auth: &CoreAuth,
    locality: oneiron::claim::CallerLocality,
    invocation: InvocationId,
    body: [u8; 32],
) -> Result<(DoorClaim, Option<SessionWitnessBinding>), Refused> {
    let Some(binding) = anonymous_binding(server, auth, locality)? else {
        return Ok((
            facade::claim_door_invocation(server, invocation, body, auth.principal_entity()).await,
            None,
        ));
    };
    let entry = binding
        .claim_invocation(server.vault(), invocation, body)
        .map_err(native_refusal)?;
    let claimed = DoorClaim::from_session(entry).await;
    binding.revalidate(server.vault()).map_err(native_refusal)?;
    Ok((claimed, Some(binding)))
}

fn anonymous_binding(
    server: &SyncServer,
    auth: &CoreAuth,
    locality: oneiron::claim::CallerLocality,
) -> Result<Option<SessionWitnessBinding>, Refused> {
    // This is the existing positive native selector. An ordinary unmatched
    // session header keeps the original durable path and route admission.
    if !crate::api::call_receipt::session_is_anonymous_for(
        server,
        auth.off_record_session(),
        crate::api::call_receipt::request_principal(auth),
    ) {
        return Ok(None);
    }
    let vault = server.vault();
    let (actor, class) = principal(auth, vault)?;
    let mut caller = credential_memory(vault, Some(auth), actor, class).at(locality);
    if let Some(holder) = crate::api::scoped_auth::attested_owner_holder(auth)
        && auth.principal_entity() == Some(holder)
        && actor == holder
        && class == EdgeActorClass::Human
        && auth.actor_class() == Some("human")
    {
        let owner = crate::api::owner_routes::managed_owner_proof(server, holder)
            .map_err(|error| Box::new(facade::FacadeApiError::from(error).into_response()))?
            .ok_or_else(|| {
                Box::new(
                    facade::FacadeApiError::from(crate::error::ApiError::managed_owner_not_live())
                        .into_response(),
                )
            })?;
        // Only the requester's Human caller handle receives this proof.
        // The independently selected assistant author is never changed.
        caller = caller.with_owner_authorship(&owner);
    }
    let context = caller
        .session_witness_context()
        .map_err(native_refusal)?
        .ok_or_else(|| {
            native_refusal(MemoryError::new(
                oneiron::memory::MEMORY_CODE_FORBIDDEN,
                "the caller has no live session binding",
                &[],
            ))
        })?;
    if !context.keeps_no_record() {
        // The user's own mode changed before capture. No private claim or
        // durable state has been opened; use the newly captured ordinary mode.
        return Ok(None);
    }
    context.into_binding().map(Some).map_err(native_refusal)
}

pub(super) fn replay(
    vault: &Vault,
    auth: &CoreAuth,
    binding: Option<&SessionWitnessBinding>,
    outcome: oneiron::runtime_hooks::verb::InvocationOutcome,
) -> Response {
    let response = facade::door_replay_for(vault, auth, "chat", outcome);
    if let Some(binding) = binding
        && let Err(error) = binding.revalidate(vault)
    {
        return *native_refusal(error);
    }
    response
}

fn native_refusal(error: MemoryError) -> Refused {
    Box::new(facade::FacadeApiError::from(error).into_response())
}
